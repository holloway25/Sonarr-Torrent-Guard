import copy
import datetime
import time
import unittest
from contextlib import closing, nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

import maintenance
import production
import public
from guard import run, load_batch_state, save_batch_state
from safety import Journal, SafetyError, reconcile
import test_production as fixtures


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
        self.f.journal.allow_public_attempt = True
        self.f.qb.login = Mock()

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def execute(self):
        f = self.f
        return production.execute_public_attempt(f.config, f.qb, f.apis, f.journal, f.report, f.approval)

    def result(self):
        f = self.f
        last_block = max([r["id"] for r in f.s.routes["/api/v3/blocklist"]["records"]] or [0])
        f.results()
        stamp = datetime.datetime.fromtimestamp(time.time() + 1, datetime.timezone.utc).isoformat()
        for number, row in enumerate(f.s.routes["/api/v3/history/since"][1:], 1):
            row["date"] = stamp
            row["id"] = max(f.report["grab_ids"]) + number
        f.s.routes["/api/v3/blocklist"]["records"][0]["date"] = stamp
        f.s.routes["/api/v3/blocklist"]["records"][0]["id"] = last_block + 1

    def test_public_gate_is_separate_from_single_test_gate(self):
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                self.execute()
            send.assert_not_called()

    def test_cleanup_resolves_without_claiming_file_deletion_or_good_replacement(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: self.result()) as send:
            row = self.execute()
            self.assertEqual(row["stage"], "cleanup_resolved")
            self.assertIsNone(row["current_observation"]["data_deleted"])
            self.f.journal.close()
            self.f.journal = Journal(self.f.journal.path, allow_public_attempt=True)
            again = self.execute()
            self.assertEqual(again, row)
            send.assert_called_once()

    def test_different_attempt_cannot_reuse_original_approval(self):
        f = self.f
        f.qb.routes["/api/v2/torrents/info"][0]["added_on"] += 1
        f.report = run(f.config, f.qb, f.apis)[0]
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "approval_expired_or_target_mismatch"):
                self.execute()
            send.assert_not_called()

    def test_new_approval_cannot_repeat_a_resolved_download_attempt(self):
        f = self.f
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: self.result()) as send:
            self.execute()
            f.approval["nonce"] = "e" * 64
            with self.assertRaisesRegex(SafetyError, "new_attempt_not_confirmed"):
                self.execute()
            send.assert_called_once()

    def test_single_test_cannot_bypass_public_holds(self):
        f = self.f
        for stage in ("prepared", "dispatch_recorded", "uncertain", "replacement_pending", "manual_review"):
            with self.subTest(stage=stage), closing(Journal(Path(f.folder.name) / (stage + ".sqlite3"),
                    allow_single_test=True, allow_public_attempt=True)) as journal:
                row = journal.prepare(f.report, mode="public_attempt", context=f.context)
                if stage != "prepared":
                    row = journal.transition(row["key"], "prepared", "dispatch_recorded")
                if stage not in ("prepared", "dispatch_recorded"):
                    journal.transition(row["key"], "dispatch_recorded", stage)
                with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
                    with self.assertRaisesRegex(SafetyError, "previous_attempt_unresolved"):
                        production.execute_single_test(f.config, f.qb, f.apis, journal, f.report, f.approval)
                    send.assert_not_called()

    def test_single_test_cannot_repeat_resolved_public_attempt(self):
        f = self.f
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: self.result()):
            self.execute()
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "new_attempt_not_confirmed"):
                production.execute_single_test(f.config, f.qb, f.apis, f.journal, f.report, f.approval)
            send.assert_not_called()

    def pending_records(self, count):
        f = self.f
        keys = []
        for number in range(1, count + 1):
            h = format(number, "040x")
            fingerprint = production.digest(["HD", h, f.context["download_added_on"], f.context["grab_ids"]])
            report = dict(f.report, hash=h, attempt_fingerprint=fingerprint)
            context = dict(f.context, hash=h, attempt_fingerprint=fingerprint)
            row = f.journal.prepare(report, mode="public_attempt", context=context)
            f.journal.transition(row["key"], "prepared", "dispatch_recorded")
            keys.append(row["key"])
        return sorted(keys)

    def test_recovery_backlog_rotates_across_restarts_without_starving_assessment(self):
        f = self.f
        keys = self.pending_records(12)
        state_path = Path(f.folder.name) / "batch-state.json"
        visited = []
        events = []
        class Verifier:
            def __init__(self, config, qb, apis, context, not_before):
                self.context = context
            def observe(self):
                events.append("recovery")
                visited.append(self.context["hash"])
                raise TimeoutError()
        original_run = public.run
        def assess(*args, **kwargs):
            events.append("assessment")
            return original_run(*args, **kwargs)
        for _ in range(3):
            events.clear()
            state = load_batch_state(state_path)
            with patch("public.require_connectivity", return_value={}), patch("public.OutcomeVerifier", Verifier), patch(
                    "public.run", side_effect=assess):
                result = public.cycle(f.config, f.qb, f.apis, f.journal, state)
            self.assertEqual(events[0], "assessment")
            self.assertEqual(len(result["recovery"]), public.RECOVERY_LIMIT)
            self.assertEqual(state["after"], ["HD", f.hash])
            self.assertEqual(result["assessment"][0]["decision"], "would_fail")
            save_batch_state(state_path, state)
            f.journal.close()
            f.journal = Journal(f.journal.path, allow_public_attempt=True)
        self.assertEqual(len(set(visited)), 12)
        self.assertTrue(all(f.journal.get(k)["stage"] == "uncertain" for k in keys))

    def test_recovery_budget_caps_each_observation_and_restores_adapter_deadlines(self):
        f = self.f
        keys = self.pending_records(8)
        now = [100.0]
        seen = []
        f.qb.deadline, f.s.deadline = 280.0, 270.0
        class Verifier:
            def __init__(self, *args):
                pass
            def observe(self):
                seen.append((f.qb.deadline, f.s.deadline))
                now[0] += 5
                raise TimeoutError()
        state = {}
        with patch("public.time.monotonic", side_effect=lambda: now[0]), patch(
                "public.hard_deadline", side_effect=lambda d: nullcontext()), patch(
                "public.OutcomeVerifier", Verifier):
            result = public.recover_pending(f.config, f.qb, f.apis, f.journal, state, 112.0)
        self.assertEqual(len(result), 2)
        self.assertEqual(seen, [(105.0, 105.0), (110.0, 110.0)])
        self.assertEqual((f.qb.deadline, f.s.deadline), (280.0, 270.0))
        self.assertEqual(state["recovery_after"], keys[1])

    def test_recovery_only_cursor_survives_restart_and_invalid_cursor_is_refused(self):
        path = Path(self.f.folder.name) / "batch-state.json"
        state = {"recovery_after": "a" * 64}
        save_batch_state(path, state)
        self.assertEqual(load_batch_state(path), state)
        save_batch_state(path, {"recovery_after": "invalid"})
        from guard import GuardError
        with self.assertRaises(GuardError):
            load_batch_state(path)

    def test_recovery_slow_observation_is_interrupted_without_delaying_assessment(self):
        f = self.f
        keys = self.pending_records(2)
        class SlowVerifier:
            def __init__(self, *args):
                pass
            def observe(self):
                time.sleep(1)
                return {}
        state = {}
        started = time.monotonic()
        with patch("public.require_connectivity", return_value={}), patch(
                "public.OutcomeVerifier", SlowVerifier), patch("public.RECOVERY_ITEM_SECONDS", .02):
            result = public.cycle(f.config, f.qb, f.apis, f.journal, state)
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(state["after"], ["HD", f.hash])
        self.assertEqual(len(result["assessment"]), 1)
        self.assertEqual(len(result["recovery"]), 2)
        self.assertTrue(all(f.journal.get(k)["stage"] == "uncertain" for k in keys))

    def test_recovery_with_no_remaining_allowance_preserves_pending_hold(self):
        f = self.f
        keys = self.pending_records(1)
        state = {}
        with patch("public.OutcomeVerifier") as verifier:
            self.assertEqual(public.recover_pending(f.config, f.qb, f.apis, f.journal,
                                                    state, time.monotonic()), [])
            verifier.assert_not_called()
        self.assertEqual(state, {})
        self.assertEqual(f.journal.get(keys[0])["stage"], "dispatch_recorded")

    def test_attempt_context_rejects_forged_or_partial_identity(self):
        f = self.f
        for change in ({"attempt_fingerprint": "e" * 64}, {"download_added_on": True},
                       {"grab_ids": []}, {"grab_ids": [5, 5]}):
            with self.subTest(change=change), self.assertRaises(SafetyError):
                production.validate_context(dict(f.context, **change))
        legacy = {k: v for k, v in f.context.items() if k not in production.ATTEMPT_CONTEXT_FIELDS}
        self.assertEqual(production.validate_context(legacy), legacy)

    def test_lost_response_never_resends_even_after_restart(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=TimeoutError()) as send:
            row = self.execute()
            self.assertEqual(row["stage"], "uncertain")
            self.f.journal.close()
            self.f.journal = Journal(self.f.journal.path, allow_public_attempt=True)
            self.execute()
            send.assert_called_once()

    def test_maintenance_before_dispatch_sends_nothing(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=SafetyError("sonarr_connectivity_unavailable")), patch(
                "production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "sonarr_connectivity_unavailable"):
                self.execute()
            send.assert_not_called()

    def test_maintenance_after_commit_leaves_definitely_unsent_record(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=[{}, {}, SafetyError("sonarr_connectivity_unavailable")]), patch(
                "production._send_queue_delete") as send:
            row = self.execute()
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "sonarr_connectivity_unavailable")
            send.assert_not_called()

    def test_no_direct_downloader_work_when_sonarr_is_down(self):
        f = self.f
        with patch("public.require_connectivity", side_effect=SafetyError("sonarr_connectivity_unavailable")):
            with self.assertRaises(SafetyError):
                public.cycle(f.config, f.qb, f.apis, f.journal)
            f.qb.login.assert_not_called()

    def test_cycle_is_dry_run_even_when_release_flag_is_set(self):
        f = self.f
        with patch("public.require_connectivity", return_value={}), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            report = public.cycle(f.config, f.qb, f.apis, f.journal)
            self.assertTrue(report["dry_run"])
            self.assertFalse(report["live_sender_enabled"])
            send.assert_not_called()

    def test_old_unresolved_attempt_holds_only_that_hash(self):
        f = self.f
        old = f.journal.prepare(f.report, mode="single_test", context=f.context)
        f.journal.transition(old["key"], "prepared", "dispatch_recorded")
        f.journal.transition(old["key"], "dispatch_recorded", "manual_review")
        f.report["attempt_fingerprint"] = "e" * 64
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "previous_attempt_unresolved"):
                self.execute()
            send.assert_not_called()

    def test_cycle_keeps_checking_other_torrents_beside_manual_review(self):
        f = self.f
        old = f.journal.prepare(f.report, mode="single_test", context=f.context)
        f.journal.transition(old["key"], "prepared", "dispatch_recorded")
        f.journal.transition(old["key"], "dispatch_recorded", "manual_review")
        other = "b" * 40
        queue = f.s.routes["/api/v3/queue"]
        queue["records"].append(dict(queue["records"][0], id=8, downloadId=other))
        queue["totalRecords"] = 2
        f.s.routes["/api/v3/history"]["records"].append(dict(f.grab, id=20, downloadId=other))
        f.s.routes["/api/v3/history"]["totalRecords"] = 2
        f.qb.routes["/api/v2/torrents/info"].append(dict(f.qb.routes["/api/v2/torrents/info"][0], hash=other))
        with patch("public.require_connectivity", return_value={}):
            reports = public.cycle(f.config, f.qb, f.apis, f.journal)["assessment"]
        states = {r["hash"]: r["safeguards"]["status"] for r in reports}
        self.assertEqual(states, {f.hash: "held", other: "fresh_attempt_verified"})

    def test_definitely_unsent_maintenance_retry_requires_new_approval(self):
        f = self.f
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=[{}, {}, SafetyError("sonarr_connectivity_unavailable")]), patch(
                "production._send_queue_delete") as send:
            blocked = self.execute()
            self.assertEqual(self.execute(), blocked)
            send.assert_not_called()
        f.approval["nonce"] = "e" * 64
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: self.result()) as send:
            retried = self.execute()
            self.assertEqual(retried["stage"], "cleanup_resolved")
            self.assertNotEqual(blocked["key"], retried["key"])
            self.assertEqual(f.journal.get(blocked["key"]), blocked)
            send.assert_called_once()

    def test_new_confirmed_grab_of_same_hash_gets_a_separate_action(self):
        f = self.f
        base = time.time()
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: self.result()) as send:
            first = self.execute()
            self.assertEqual(first["stage"], "cleanup_resolved")
            # Advance to a new run after a distinct grab/addition, not a rename.
            added = int(base) + 10
            grab = dict(f.grab, id=20, date=datetime.datetime.fromtimestamp(
                added, datetime.timezone.utc).isoformat())
            f.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [f.grab, grab]}
            f.s.routes["/api/v3/history/since"] = [grab]
            f.qb.routes["/api/v2/torrents/info"] = [{"hash": f.hash, "category": "tv-hd",
                "state": "stoppedUP", "added_on": added}]
            with patch("time.time", return_value=base + 600):
                f.report = run(f.config, f.qb, f.apis)[0]
                f.approval = dict(f.approval, ownership_fingerprint=f.report["ownership_fingerprint"],
                                 expires_at=base + 720, nonce="e" * 64)
                second = self.execute()
            self.assertNotEqual(first["key"], second["key"])
            self.assertEqual(send.call_count, 2)
            self.assertEqual(f.journal.get(first["key"]), first)

    def test_original_absence_can_be_distinguished_from_correlated_same_hash_regrab(self):
        f = self.f
        self.result()
        added = int(time.time()) + 10
        grab = dict(f.grab, id=20, date=datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat())
        f.s.routes["/api/v3/history/since"].append(grab)
        f.qb.routes["/api/v2/torrents/info"] = [{"hash": f.hash, "added_on": added}]
        result = production.OutcomeVerifier(f.config, f.qb, f.apis, f.context, time.time()).observe()
        self.assertTrue(result["torrent_absent"])
        self.assertTrue(result["replacement_observed"])
        self.assertIsNone(result["data_deleted"])
        f.s.routes["/api/v3/history/since"].remove(grab)
        result = production.OutcomeVerifier(f.config, f.qb, f.apis, f.context, time.time()).observe()
        self.assertIsNone(result["torrent_absent"])

    def test_resolved_cleanup_requires_current_positive_cleanup_evidence(self):
        f = self.f
        row = f.journal.prepare(f.report, mode="public_attempt", context=f.context)
        f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        with self.assertRaisesRegex(SafetyError, "cleanup_not_verified"):
            f.journal.transition(row["key"], "dispatch_recorded", "cleanup_resolved", {"torrent_absent": True})
        for missing in ("torrent_absent", "failed", "blocklisted"):
            partial = {k: True for k in ("torrent_absent", "failed", "blocklisted") if k != missing}
            with self.subTest(missing=missing), self.assertRaisesRegex(SafetyError, "cleanup_not_verified"):
                f.journal.transition(row["key"], "dispatch_recorded", "cleanup_resolved", partial)
        row = reconcile(f.journal, row["key"], lambda: {"torrent_absent": True, "failed": None, "blocklisted": None})
        self.assertEqual(row["stage"], "uncertain")

    def test_replacement_progress_does_not_change_cleanup_resolution(self):
        f = self.f
        row = f.journal.prepare(f.report, mode="public_attempt", context=f.context)
        row = f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        row = f.journal.transition(row["key"], "dispatch_recorded", "uncertain", {"replacement_observed": True})
        row = reconcile(f.journal, row["key"], lambda: {"torrent_absent": True,
            "failed": True, "blocklisted": True, "replacement_observed": False, "data_deleted": None})
        self.assertEqual(row["stage"], "cleanup_resolved")
        self.assertTrue(row["confirmed"]["replacement_observed"])
        self.assertFalse(row["current_observation"]["replacement_observed"])

    def test_endpoint_change_during_post_commit_probe_blocks_send(self):
        f = self.f
        calls = []
        def probe(*args):
            calls.append(1)
            if len(calls) == 3:
                f.config["sonarr"]["HD"]["url"] = "https://changed.example.invalid"
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=probe), patch("production._send_queue_delete") as send:
            self.assertEqual(self.execute()["stage"], "dispatch_blocked")
            send.assert_not_called()


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
        folder = Path(__file__).parent / "deploy"
        timer = (folder / "sonarr-torrent-guard.timer").read_text()
        service = (folder / "sonarr-torrent-guard.service").read_text()
        self.assertIn("OnUnitInactiveSec=10min", timer)
        self.assertIn("Persistent=false", timer)
        self.assertIn("/public.py --config", service)
        self.assertNotIn("--live", service)


if __name__ == "__main__":
    unittest.main()
