import copy
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import maintenance
import production
import public
from guard import load_batch_state, save_batch_state
from safety import SafetyError
from tools.tests import test_production as fixtures


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
        self.f.qb.login = Mock()

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def test_verification_rotates_independently_when_slow_pack_fills_its_budget(self):
        f = self.f
        single = "b" * 40
        queue = f.s.routes["/api/v3/queue"]
        queue["records"].extend(dict(queue["records"][0], id=20 + i, episodeId=i) for i in range(4, 11))
        queue["records"].append(dict(queue["records"][0], id=40, episodeId=11, downloadId=single))
        queue["totalRecords"] = len(queue["records"])
        history = f.s.routes["/api/v3/history"]
        history["records"].extend(dict(f.grab, id=20 + i, episodeId=i) for i in range(4, 11))
        history["records"].append(dict(f.grab, id=40, episodeId=11, downloadId=single))
        history["totalRecords"] = len(history["records"])
        f.qb.routes["/api/v2/torrents/info"].append(dict(f.qb.routes["/api/v2/torrents/info"][0], hash=single))
        state_path = Path(f.folder.name) / "batch-state.json"
        attempts = []
        now = [100.0]
        recheck = public.recheck_candidate

        def verify(report, *args):
            attempts.append(report["hash"])
            if report["hash"] == f.hash:
                now[0] = f.qb.deadline
                raise production.GuardError("run_time_limit_reached")
            return recheck(report, *args)

        for cycle_number in range(3):
            now[0] = 100.0
            attempts.clear()
            f.qb.deadline = f.s.deadline = 280.0
            state = load_batch_state(state_path)
            with patch("public.time.monotonic", side_effect=lambda: now[0]), patch(
                    "public.require_connectivity", return_value={}), patch("public.recheck_candidate", side_effect=verify):
                report = public.cycle(f.config, f.qb, f.apis, state, reserve_dispatch=True)
            self.assertEqual([r["decision"] for r in report["assessment"]], ["would_fail", "would_fail"])
            self.assertEqual(attempts, [f.hash] if cycle_number == 0 else [single, f.hash])
            self.assertEqual(state["after"], ["HD", single])
            self.assertEqual(state["verification_after"], ["HD", f.hash])
            by_hash = {r["hash"]: r for r in report["assessment"]}
            self.assertEqual(by_hash[single]["safeguards"]["status"],
                             "held" if cycle_number == 0 else "fresh_attempt_verified")
            save_batch_state(state_path, state)

    def test_no_direct_downloader_work_when_sonarr_is_down(self):
        f = self.f
        with patch("public.require_connectivity", side_effect=SafetyError("sonarr_connectivity_unavailable")):
            with self.assertRaises(SafetyError):
                public.cycle(f.config, f.qb, f.apis)
            f.qb.login.assert_not_called()

    def test_cycle_is_dry_run_even_when_release_flag_is_set(self):
        f = self.f
        with patch("public.require_connectivity", return_value={}), patch(
                "production.ROUTINE_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            report = public.cycle(f.config, f.qb, f.apis)
            self.assertTrue(report["dry_run"])
            self.assertFalse(report["live_sender_enabled"])
            send.assert_not_called()

    def test_guard_preview_checks_safeguards(self):
        import contextlib
        import io
        import guard

        f = self.f
        directory = Path(f.folder.name)
        args = ["guard.py", "--config", str(directory / "connections.json"), "--check-safeguards"]
        with contextlib.redirect_stdout(io.StringIO()) as output, patch("sys.argv", args), patch(
                "guard.load_config", return_value=f.config), patch("guard.Api", side_effect=[f.qb, f.s]):
            self.assertEqual(guard.main(), 0)
        self.assertIn("preview verified", output.getvalue())

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def probe(self, response):
        f = self.f
        return maintenance.require_connectivity(f.config, f.s, "HD", probe=Mock(return_value=response))

    def test_payload_uses_saved_credentials_and_disables_category_creation_without_saving(self):
        client = self.f.s.routes["/api/v3/downloadclient"][0]
        original = copy.deepcopy(client)
        payload = maintenance.probe_payload(client)
        self.assertEqual(client, original)
        self.assertEqual(payload["id"], client["id"])
        categories = {f["name"]: f["value"] for f in payload["fields"] if "Category" in f["name"]}
        self.assertEqual(categories, {"tvCategory": "", "tvImportedCategory": ""})

    def test_positive_or_only_expected_warning_is_required(self):
        self.assertEqual(self.probe((200, {}))["status"], "verified")
        self.assertEqual(self.probe((400, [{"propertyName": "TvCategory", "isWarning": True,
                                          "severity": "error"}]))["status"], "verified")
        for response in ((500, {}), (200, []), (400, []), (400, [{"propertyName": "Host", "isWarning": False}]),
                         (400, [{"propertyName": "TvCategory", "isWarning": False}])):
            with self.subTest(response=response), self.assertRaises(SafetyError):
                self.probe(response)

    def test_connectivity_accepts_v4_versions_and_rejects_other_or_malformed_versions(self):
        status_route = "/api/v3/system/status"
        for version in ("4.0.1", "4.0.20.3014", "4.0.21.3090", "4.5.2", "4.10"):
            with self.subTest(version=version):
                self.f.s.routes[status_route] = {"version": version}
                self.assertEqual(self.probe((200, {}))["status"], "verified")
        for version in ("3.0.10.1567", "5.0.1", "5.1", "40.0.1", "4", "4.bad",
                        "4.0.1\n", "4.1.2.3.4", 4.1, None):
            with self.subTest(version=version), self.assertRaisesRegex(SafetyError, "unreviewed_sonarr_version"):
                self.f.s.routes[status_route] = {"version": version}
                self.probe((200, {}))

    def test_outage_and_version_change_fail_closed(self):
        self.f.s.routes["/api/v3/system/status"] = TimeoutError()
        with self.assertRaises(SafetyError):
            self.probe((200, {}))
        self.f.s.routes["/api/v3/system/status"] = {"version": "unreviewed"}
        with self.assertRaisesRegex(SafetyError, "unreviewed_sonarr_version"):
            self.probe((200, {}))

    def test_probe_redirects_are_refused(self):
        with self.assertRaises(SafetyError):
            maintenance.NoRedirect().redirect_request(None)

    def test_probe_transport_is_narrow_and_never_saves_settings(self):
        f = self.f
        response = Mock(code=200)
        response.read.return_value = b"{}"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        payload = maintenance.probe_payload(f.s.routes["/api/v3/downloadclient"][0])
        with patch("maintenance.urllib.request.build_opener", return_value=opener):
            self.assertEqual(maintenance.sonarr_probe(f.s, payload), (200, {}))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertTrue(request.full_url.endswith("/api/v3/downloadclient/test"))
        self.assertEqual(request.data.decode().count('"tvCategory"'), 1)
        opener.open.assert_called_once()

    def test_timer_template_has_ten_minute_interval_and_dry_run_only_target(self):
        from pathlib import Path
        folder = Path(__file__).resolve().parents[2] / "deploy"
        timer = (folder / "sonarr-torrent-guard.timer").read_text()
        service = (folder / "sonarr-torrent-guard.service").read_text()
        self.assertIn("OnUnitInactiveSec=10min", timer)
        self.assertIn("Persistent=false", timer)
        self.assertIn("/public.py --config", service)
        self.assertNotIn("--live", service)


if __name__ == "__main__":
    unittest.main()
