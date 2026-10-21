"""Timing regressions use fake senders; no production transport is called."""

import datetime
import time
import unittest
from unittest.mock import patch

import production
from production import wait_for_event_boundary as actual_wait, event_boundary_reached as actual_reached
from safety import Journal, SafetyError
from tools.tests import test_production as fixtures


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
        self.f.journal.allow_public_attempt = True

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def execute(self):
        f = self.f
        return production.execute_public_attempt(f.config, f.qb, f.apis, f.journal, f.report, f.approval)

    def test_whole_second_sonarr_results_resolve_after_real_boundary_wait(self):
        f = self.f
        seen = []
        def send(*args):
            f.results()
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            for row in f.s.routes["/api/v3/history/since"][1:]:
                row["date"] = stamp
            f.s.routes["/api/v3/blocklist"]["records"][0]["date"] = stamp
            seen.append(stamp)
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", actual_wait), patch(
                "production.event_boundary_reached", actual_reached), patch(
                "production._send_queue_delete", side_effect=send) as sender:
            row = self.execute()
        sender.assert_called_once()
        self.assertEqual(row["stage"], "cleanup_resolved")
        self.assertGreater(production.event_time({"date": seen[0]}), row["dispatched_at"])
        self.assertIsNone(row["current_observation"]["data_deleted"])

    def test_boundary_wait_is_bounded_when_wall_clock_stalls(self):
        elapsed = [0.0]
        def sleep(amount):
            elapsed[0] += amount
        with patch("production.event_boundary_reached", actual_reached), patch(
                "production.time.time", return_value=100.5), patch(
                "production.time.monotonic", side_effect=lambda: elapsed[0]), patch(
                "production.time.sleep", side_effect=sleep):
            with self.assertRaisesRegex(SafetyError, "dispatch_clock_unavailable"):
                actual_wait(100.5)
        self.assertLessEqual(elapsed[0], 1.11)

    def test_coordinator_separates_fractional_intent_from_whole_second_events(self):
        from guard import run
        f = self.f
        now = [1000.8]
        f.qb.routes["/api/v2/torrents/info"][0]["added_on"] = 100
        f.grab["date"] = "1970-01-01T00:01:40Z"
        def sleep(amount):
            now[0] += amount
        def send(*args):
            f.results()
            stamp = datetime.datetime.fromtimestamp(now[0], datetime.timezone.utc).isoformat(timespec="seconds")
            for row in f.s.routes["/api/v3/history/since"][1:]:
                row["date"] = stamp
            f.s.routes["/api/v3/blocklist"]["records"][0]["date"] = stamp
        with patch("production.time.time", side_effect=lambda: now[0]), patch(
                "production.time.sleep", side_effect=sleep), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", actual_wait), patch(
                "production.event_boundary_reached", actual_reached), patch(
                "production._send_queue_delete", side_effect=send):
            f.report = run(f.config, f.qb, f.apis)[0]
            f.approval.update(ownership_fingerprint=f.report["ownership_fingerprint"], expires_at=1120)
            row = self.execute()
        self.assertEqual(row["dispatched_at"], 1000.8)
        self.assertGreaterEqual(now[0], 1001)
        self.assertEqual(row["stage"], "cleanup_resolved")

    def test_boundary_wait_advances_to_next_second_without_rounding_intent_down(self):
        elapsed = [0.0]
        def sleep(amount):
            elapsed[0] += amount
        with patch("production.event_boundary_reached", actual_reached), patch(
                "production.time.time", side_effect=lambda: 100.8 + elapsed[0]), patch(
                "production.time.monotonic", side_effect=lambda: elapsed[0]), patch(
                "production.time.sleep", side_effect=sleep):
            self.assertEqual(actual_wait(100.8), 101)
        self.assertGreaterEqual(elapsed[0], .2)
        self.assertLess(elapsed[0], .4)

    def test_invalid_dispatch_clock_is_refused(self):
        for stamp in (None, True, 0, float("nan"), float("inf")):
            with self.subTest(stamp=stamp), self.assertRaises(SafetyError):
                actual_wait(stamp)

    def test_expired_approval_during_wait_blocks_without_send(self):
        f = self.f
        def wait(*args):
            f.approval["expires_at"] = time.time() - 1
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", side_effect=wait), patch("production._send_queue_delete") as sender:
            row = self.execute()
        self.assertEqual(row["stage"], "dispatch_blocked")
        self.assertEqual(row["stop_reason"], "approval_expired_or_target_mismatch")
        sender.assert_not_called()

    def test_file_change_during_wait_blocks_before_send(self):
        f = self.f
        def wait(*args):
            f.qb.routes["/api/v2/torrents/files"][0]["name"] = "changed.exe"
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", side_effect=wait), patch("production._send_queue_delete") as sender:
            row = self.execute()
        self.assertEqual(row["stage"], "dispatch_blocked")
        self.assertEqual(row["stop_reason"], "identity_or_manifest_changed")
        sender.assert_not_called()

    def test_clock_falls_back_across_boundary_after_final_checks_blocks_send(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.event_boundary_reached", return_value=False), patch("production._send_queue_delete") as sender:
            row = self.execute()
        self.assertEqual(row["stage"], "dispatch_blocked")
        self.assertEqual(row["stop_reason"], "dispatch_clock_unavailable")
        sender.assert_not_called()

    def test_pre_send_events_observed_during_wait_are_in_new_baseline_not_results(self):
        f = self.f
        def wait(*args):
            f.results()
            # Keep the original download present for the post-wait fresh check.
            f.qb.routes["/api/v2/torrents/info"] = [{"hash": f.hash, "category": "tv-hd",
                "state": "stoppedUP", "added_on": f.context["download_added_on"]}]
        def send(*args):
            f.qb.routes["/api/v2/torrents/info"] = []
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production.wait_for_event_boundary", side_effect=wait), patch(
                "production._send_queue_delete", side_effect=send):
            row = self.execute()
        self.assertEqual(row["stage"], "manual_review")
        self.assertFalse(row["current_observation"]["failed"])
        self.assertFalse(row["current_observation"]["blocklisted"])
        self.assertIn(6, row["context"]["baseline_history_ids"])
        self.assertIn(9, row["context"]["baseline_blocklist_ids"])

    def test_baseline_refresh_preserves_original_evidence_and_survives_restart(self):
        f = self.f
        row = f.journal.prepare(f.report, mode="public_attempt", context=f.context)
        row = f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        changed = dict(f.context, baseline_history_ids=[99], baseline_blocklist_ids=[98],
                       window_start=f.context["window_start"]+1)
        updated = f.journal.refresh_baselines(row["key"], changed)
        self.assertEqual(updated["context"]["baseline_history_ids"], [5, 99])
        self.assertEqual(updated["context"]["window_start"], f.context["window_start"])
        self.assertEqual(updated["dispatched_at"], row["dispatched_at"])
        self.assertEqual(updated["evidence"], row["evidence"])
        f.journal.close()
        f.journal = Journal(f.journal.path, allow_public_attempt=True)
        self.assertEqual(f.journal.get(row["key"]), updated)

    def test_baseline_refresh_cannot_change_identity_or_modify_recovery_records(self):
        f = self.f
        row = f.journal.prepare(f.report, mode="public_attempt", context=f.context)
        row = f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        with self.assertRaisesRegex(SafetyError, "identity_or_manifest_changed"):
            f.journal.refresh_baselines(row["key"], dict(f.context, queue_id=99))
        f.journal.transition(row["key"], "dispatch_recorded", "uncertain")
        with self.assertRaisesRegex(SafetyError, "baseline_refresh_forbidden"):
            f.journal.refresh_baselines(row["key"], f.context)


if __name__ == "__main__":
    unittest.main()
