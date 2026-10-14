import unittest
from unittest.mock import patch

from guard import run, recheck_candidate
import production
from safety import SafetyError, check_fresh
import test_guard as guard_fixtures
import test_production as production_fixtures


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.f = guard_fixtures.WorkflowTests()
        self.f.setUp()
        self.t = self.f.qb.routes["/api/v2/torrents/info"][0]
        self.t.update(state="metaDL", total_size=-1, progress=0, time_active=1800)
        self.f.qb.routes["/api/v2/torrents/files"] = []

    def assess(self, now=1900):
        return run(self.f.config, self.f.qb, {"HD": self.f.s}, now=now)[0]

    def test_public_metadata_timeout_is_separate_from_empty_or_unselected_files(self):
        report = self.assess()
        self.assertEqual(report["decision"], "would_fail")
        self.assertEqual(report["reasons"], ["metadata_timeout"])
        self.assertEqual(report["file_count"], 0)
        self.assertNotIn("contains_exe", report["reasons"])
        self.t["state"] = "forcedMetaDL"
        self.assertEqual(self.assess()["decision"], "would_fail")

    def test_requires_elapsed_age_but_does_not_depend_on_stalled_active_counter(self):
        self.assertEqual(self.assess(1899)["reason"], "metadata_timeout_not_reached")
        for active in (None, True, -1, 1799, 1800.0):
            self.t["time_active"] = active
            self.assertEqual(self.assess()["decision"], "would_fail")

    def test_private_unknown_manual_and_wrong_client_are_still_protected(self):
        for source in ("Private Source", "Unknown Source"):
            self.f.s.routes["/api/v3/history"]["records"][0]["data"]["indexer"] = source
            self.assertEqual(self.assess()["decision"], "skip")
        self.f.s.routes["/api/v3/history"]["records"][0]["data"]["indexer"] = "Public Source"
        self.f.s.routes["/api/v3/queue"]["records"][0]["downloadClient"] = "Other"
        self.assertEqual(self.assess()["decision"], "skip")
        self.f.s.routes["/api/v3/queue"]["records"][0]["downloadClient"] = "Downloader"
        self.f.s.routes["/api/v3/history"] = {"totalRecords": 0, "records": []}
        self.assertEqual(self.assess()["reason"], "no_sonarr_grab_history")

    def test_inconsistent_state_or_file_response_does_not_prove_metadata_timeout(self):
        for files in (None, {}, [{"name": "payload.exe"}], guard_fixtures.manifest(("video.mkv", 1))):
            self.f.qb.routes["/api/v2/torrents/files"] = files
            self.assertEqual(self.assess()["reason"], "metadata_state_inconsistent")
        self.f.qb.routes["/api/v2/torrents/files"] = []
        for changes in ({"progress": True}, {"progress": .1}, {"total_size": 123}, {"total_size": None}):
            original = dict(self.t)
            self.t.update(changes)
            self.assertEqual(self.assess()["reason"], "metadata_state_inconsistent")
            self.t.update(original)

    def test_paused_stopped_or_empty_known_download_is_not_failed_by_timeout(self):
        for state in ("pausedDL", "stoppedDL", "checkingDL", "error"):
            self.t["state"] = state
            self.assertEqual(self.assess()["decision"], "skip")


class MetadataSenderTests(unittest.TestCase):
    def setUp(self):
        self.f = production_fixtures.ProductionTests()
        self.f.setUp()
        self.f.journal.allow_public_attempt = True
        self.t = self.f.qb.routes["/api/v2/torrents/info"][0]
        # Fixture's torrent is ten minutes old; use a matching older grab.
        self.t["added_on"] -= 1800
        from datetime import datetime, timezone
        self.f.grab["date"] = datetime.fromtimestamp(self.t["added_on"], timezone.utc).isoformat()
        self.t.update(state="metaDL", progress=0, total_size=-1, time_active=1800)
        self.f.qb.routes["/api/v2/torrents/files"] = []
        self.f.report = run(self.f.config, self.f.qb, self.f.apis)[0]
        self.f.approval.update(ownership_fingerprint=self.f.report["ownership_fingerprint"],
                               manifest_fingerprint=self.f.report["manifest_fingerprint"])

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def test_metadata_arriving_before_dispatch_cancels_even_if_new_file_is_bad(self):
        f = self.f
        def wait(*args):
            self.t["state"] = "stalledUP"
            f.qb.routes["/api/v2/torrents/files"] = guard_fixtures.manifest(("payload.exe", 0))
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", side_effect=wait), patch("production._send_queue_delete") as send:
            row = production.execute_public_attempt(f.config, f.qb, f.apis, f.journal, f.report, f.approval)
        self.assertEqual(row["stage"], "dispatch_blocked")
        self.assertEqual(row["stop_reason"], "identity_or_manifest_changed")
        send.assert_not_called()

    def test_metadata_failure_uses_same_sonarr_sender_and_independent_confirmation(self):
        f = self.f
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: f.results()) as send:
            row = production.execute_public_attempt(f.config, f.qb, f.apis, f.journal, f.report, f.approval)
        self.assertEqual(row["stage"], "cleanup_resolved")
        self.assertIsNone(row["current_observation"]["data_deleted"])
        send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
