import datetime
import json
import time
import unittest
from unittest.mock import Mock, patch

from guard import run, recheck_candidate
import production
from safety import Journal, SafetyError, check_fresh, reconcile
from workflow import preview_failure
from reports import human_report, json_events
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

    def test_metadata_human_and_json_proposals_do_not_promise_blocklisting(self):
        report = self.assess()
        self.assertNotIn("blocklist_release_in_owning_sonarr", report["proposed_actions"])
        self.assertIn("remove_torrent_and_data_through_sonarr_without_blocklisting", report["proposed_actions"])
        self.assertIn("request_owning_sonarr_episode_search_after_confirmed_removal_and_final_checks", report["proposed_actions"])
        output = human_report([report], {}, "test time")
        self.assertIn("WITHOUT blocklisting", output)
        self.assertIn("affected-episode search", output)
        self.assertNotIn("blocklists and handles retry", output)
        event = list(json_events([report], {}, "test time"))[0]
        self.assertEqual(event["proposed_actions"], report["proposed_actions"])

    def test_file_failure_human_and_json_proposals_still_blocklist(self):
        self.t["state"] = "stalledUP"
        self.f.qb.routes["/api/v2/torrents/files"] = guard_fixtures.manifest(("payload.exe", 0))
        report = self.assess()
        self.assertIn("blocklist_release_in_owning_sonarr", report["proposed_actions"])
        self.assertIn("blocklists and handles retry", human_report([report], {}, "test time"))
        event = list(json_events([report], {}, "test time"))[0]
        self.assertIn("blocklist_release_in_owning_sonarr", event["proposed_actions"])


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
        gate = patch("production.METADATA_RETRY_RELEASE_ENABLED", True)
        gate.start()
        self.addCleanup(gate.stop)

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

    def removed(self, *args, **kwargs):
        self.f.qb.routes["/api/v2/torrents/info"] = []
        self.f.s.routes["/api/v3/queue"] = {"totalRecords": 0, "records": []}

    def execute(self):
        f = self.f
        return production.execute_public_attempt(f.config, f.qb, f.apis, f.journal, f.report, f.approval)

    def test_metadata_removal_does_not_require_failure_or_blocklist_and_searches_once(self):
        f = self.f
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed) as send, patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
            self.assertEqual(self.execute(), row)
        self.assertEqual(row["stage"], "retry_requested")
        self.assertEqual(row["search_command_id"], 41)
        self.assertEqual(row["context"]["metadata_retry"], {"blocklist": False, "search": "EpisodeSearch"})
        self.assertTrue(row["confirmed"]["torrent_absent"])
        self.assertFalse(row["current_observation"]["failed"])
        self.assertFalse(row["current_observation"]["blocklisted"])
        self.assertIsNone(row["current_observation"]["data_deleted"])
        send.assert_called_once_with(f.s, 7, blocklist=False)
        search.assert_called_once_with(f.s, [3])
        reopened = Journal(f.journal.path)
        try:
            self.assertEqual(reopened.get(row["key"]), row)
            observe = Mock()
            self.assertEqual(reconcile(reopened, row["key"], observe), row)
            observe.assert_not_called()
        finally:
            reopened.close()

    def test_metadata_retry_requires_separate_release_gate(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", False), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "metadata_retry_not_released"):
                self.execute()
        send.assert_not_called()

    def test_unconfirmed_removal_never_searches(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=TimeoutError()), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "uncertain")
        search.assert_not_called()

    def test_lost_search_response_is_durable_and_never_retried(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed) as remove, patch(
                "production._send_episode_search", side_effect=TimeoutError()) as search:
            row = self.execute()
            self.assertEqual(self.execute(), row)
        self.assertEqual(row["stage"], "retry_search_uncertain")
        self.assertIsNone(row["search_command_id"])
        remove.assert_called_once()
        search.assert_called_once()
        reopened = Journal(self.f.journal.path)
        try:
            with patch("production._send_episode_search") as search:
                self.assertEqual(reconcile(reopened, row["key"], Mock()), row)
            search.assert_not_called()
        finally:
            reopened.close()

    def test_expired_approval_after_search_intent_blocks_search(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                f.approval["expires_at"] = time.time() - 1
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "approval_expired_or_target_mismatch")
        search.assert_not_called()

    def test_reviewed_version_drift_before_search_blocks_search(self):
        def removed(*args, **kwargs):
            self.removed()
        original = self.f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                self.f.s.routes["/api/v3/system/status"] = {"version": "unreviewed"}
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=removed), patch.object(
                self.f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "unreviewed_sonarr_version")
        search.assert_not_called()

    def test_reappearing_hash_or_new_queued_replacement_blocks_extra_search(self):
        original = self.f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                self.f.qb.routes["/api/v2/torrents/info"] = [self.t]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                self.f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stop_reason"], "target_reappeared")
        self.assertEqual(row["stage"], "retry_search_blocked")
        search.assert_not_called()

    def test_new_queued_replacement_blocks_extra_search(self):
        def removed(*args, **kwargs):
            self.removed()
            self.f.s.routes["/api/v3/queue"] = {"totalRecords": 1,
                "records": [{"id": 19, "seriesId": 2, "episodeId": 3}]}
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=removed), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_already_queued")
        search.assert_not_called()

    def test_timeout_never_escalates_to_blocklist_and_new_attempts_need_new_grabs(self):
        f = self.f
        now = int(time.time())
        rows = []
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed) as remove, patch(
                "production._send_episode_search", return_value=41) as search:
            for attempt in range(4):
                stamp = now + attempt * 2000
                if attempt:
                    self.t["added_on"] = stamp - 1900
                    f.grab.update(id=5 + attempt, date=datetime.datetime.fromtimestamp(
                        self.t["added_on"], datetime.timezone.utc).isoformat())
                    f.qb.routes["/api/v2/torrents/info"] = [self.t]
                    f.s.routes["/api/v3/queue"] = {"totalRecords": 1, "records": [{"id": 7,
                        "downloadId": f.hash.upper(), "seriesId": 2, "episodeId": 3, "downloadClientId": 1}]}
                with patch("time.time", return_value=stamp):
                    f.report = run(f.config, f.qb, f.apis)[0]
                    f.approval.update(ownership_fingerprint=f.report["ownership_fingerprint"],
                        manifest_fingerprint=f.report["manifest_fingerprint"], nonce=str(attempt + 1) * 64,
                        expires_at=stamp + 120)
                    row = self.execute()
                rows.append(row)
                self.assertEqual(row["stage"], "retry_requested")
                self.assertIs(row["context"]["metadata_retry"]["blocklist"], False)
                with self.assertRaises(SafetyError):
                    production.check_prior_attempts(f.journal, f.report, config=f.config)
        self.assertEqual(len({r["key"] for r in rows}), 4)
        self.assertEqual(remove.call_count, 4)
        self.assertEqual(search.call_count, 4)
        self.assertTrue(all(call.kwargs == {"blocklist": False} for call in remove.call_args_list))

    def test_preview_describes_remove_then_search_not_failure_and_blocklist(self):
        plan = preview_failure(self.f.report, {"status": "verified", "automatic_retry": True, "interactive_retry": True})
        self.assertIs(plan["request_preview"]["params"]["blocklist"], False)
        self.assertIs(plan["request_preview"]["params"]["skipRedownload"], True)
        self.assertEqual(plan["search_preview"]["body"], {"name": "EpisodeSearch", "episodeIds": [3]})
        self.assertIn("metadata_retry_release_disabled", plan["blockers"])

    def test_crash_after_removal_does_not_cause_recovery_search(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch(
                "production.finish_metadata_retry", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                self.execute()
        row = self.f.journal.related("HD", self.f.hash)[0]
        self.assertEqual(row["stage"], "retry_removed")
        reopened = Journal(self.f.journal.path)
        try:
            with patch("production._send_episode_search") as search:
                self.assertEqual(reconcile(reopened, row["key"], Mock()), row)
            search.assert_not_called()
        finally:
            reopened.close()

    def test_crash_after_search_intent_never_replays_search(self):
        original = self.f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                raise RuntimeError("simulated crash")
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                self.f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            with self.assertRaises(RuntimeError):
                self.execute()
        row = self.f.journal.related("HD", self.f.hash)[0]
        self.assertEqual(row["stage"], "retry_search_recorded")
        self.assertEqual(reconcile(self.f.journal, row["key"], Mock()), row)
        search.assert_not_called()

    def test_preexisting_new_grab_suppresses_redundant_search(self):
        def removed(*args, **kwargs):
            self.removed()
            replacement = dict(self.f.grab, id=8, downloadId="b" * 40,
                date=datetime.datetime.now(datetime.timezone.utc).isoformat())
            self.f.s.routes["/api/v3/history/since"] = [self.f.grab, replacement]
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=removed), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_superseded")
        search.assert_not_called()

    def assert_coordinator_restart_does_not_replay(self, crash_stage):
        f = self.f
        original_finish = production.finish_metadata_retry
        original_transition = f.journal.transition
        def finish(*args, **kwargs):
            if crash_stage == "retry_removed":
                raise RuntimeError("simulated crash")
            return original_finish(*args, **kwargs)
        def transition(*args, **kwargs):
            row = original_transition(*args, **kwargs)
            if args[2] == crash_stage:
                raise RuntimeError("simulated crash")
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch(
                "production.finish_metadata_retry", side_effect=finish), patch.object(
                f.journal, "transition", side_effect=transition):
            with self.assertRaises(RuntimeError):
                self.execute()
        previous = f.journal.related("HD", f.hash)[0]
        self.assertEqual(previous["stage"], crash_stage)
        f.journal.close()
        f.journal = Journal(f.journal.path, allow_public_attempt=True)
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete") as remove, patch("production._send_episode_search") as search:
            recovered = self.execute()  # Actual coordinator entry, not just reconcile().
        self.assertEqual(recovered, previous)
        remove.assert_not_called()
        search.assert_not_called()

    def test_coordinator_restart_after_removal_never_sends_deferred_search(self):
        self.assert_coordinator_restart_does_not_replay("retry_removed")

    def test_coordinator_restart_after_search_intent_never_replays_either_request(self):
        self.assert_coordinator_restart_does_not_replay("retry_search_recorded")

    def test_final_history_refresh_suppresses_new_grab_even_when_queue_is_empty(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                replacement = dict(f.grab, id=18, downloadId="b" * 40,
                    date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                f.s.routes["/api/v3/history/since"] = [f.grab, replacement]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "replacement_already_grabbed")
        search.assert_not_called()

    def test_final_history_same_hash_new_grab_also_suppresses_search(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                replacement = dict(f.grab, id=18, date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                f.s.routes["/api/v3/history/since"] = [f.grab, replacement]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stop_reason"], "replacement_already_grabbed")
        search.assert_not_called()

    def test_final_history_outage_blocks_search_without_disclosing_response(self):
        f = self.f
        original = f.s.call
        state = {"intent": False}
        original_transition = f.journal.transition
        def transition(*args, **kwargs):
            row = original_transition(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                state["intent"] = True
            return row
        def call(path, *args, **kwargs):
            if path == "/api/v3/history/since" and state["intent"]:
                raise RuntimeError("private-response")
            return original(path, *args, **kwargs)
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch.object(
                f.s, "call", side_effect=call), patch("production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "dispatch_validation_failed")
        self.assertNotIn("private-response", json.dumps(row))
        search.assert_not_called()

    def test_final_history_old_or_other_client_grabs_do_not_suppress_search(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                old = dict(f.grab, id=18, downloadId="b" * 40)
                other = dict(f.grab, id=19, downloadId="c" * 40,
                    data={"downloadClientName": "Other"},
                    date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                f.s.routes["/api/v3/history/since"] = [f.grab, old, other]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        search.assert_called_once()

    def test_final_history_missing_or_invalid_client_identity_blocks_search(self):
        f = self.f
        cases = [{}, {"data": None}, {"data": []}, {"data": {}},
                 *({"data": {"downloadClientName": value}} for value in
                   (None, True, 0, [], {}, "", "   "))]
        queue_rows = f.s.routes["/api/v3/queue"]
        for number, changes in enumerate(cases):
            with self.subTest(case=number):
                f.journal.close()
                f.journal = Journal(f.journal.path.parent / ("case-" + str(number) + ".sqlite3"), allow_public_attempt=True)
                f.qb.routes["/api/v2/torrents/info"] = [self.t]
                f.s.routes["/api/v3/queue"] = queue_rows
                f.s.routes["/api/v3/history/since"] = [f.grab]
                original = f.journal.transition
                def transition(*args, **kwargs):
                    row = original(*args, **kwargs)
                    if args[2] == "retry_search_recorded":
                        replacement = dict(f.grab, id=18, downloadId="b" * 40,
                            date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                        replacement.pop("data")
                        replacement.update(changes)
                        f.s.routes["/api/v3/history/since"] = [f.grab, replacement]
                    return row
                with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                        "production._send_queue_delete", side_effect=self.removed), patch.object(
                        f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
                    row = self.execute()
                self.assertEqual(row["stage"], "retry_search_blocked")
                self.assertEqual(row["stop_reason"], "replacement_client_unknown")
                search.assert_not_called()
                reopened = Journal(f.journal.path)
                try:
                    self.assertEqual(reopened.get(row["key"])["stop_reason"], "replacement_client_unknown")
                finally:
                    reopened.close()

    def test_pre_intent_history_with_unknown_client_does_not_block_search(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                old = dict(f.grab, id=18, data=None)
                f.s.routes["/api/v3/history/since"] = [f.grab, old]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        search.assert_called_once()

    def test_final_history_missing_or_invalid_content_identity_blocks_search(self):
        f = self.f
        cases = [(field, missing, value) for field in ("seriesId", "episodeId")
                 for missing, value in [(True, None), *[(False, value) for value in
                     (None, True, False, "2", "3", 2.0, 3.0, 0, -1, [], {}, "")]]]
        queue_rows = f.s.routes["/api/v3/queue"]
        for number, (field, missing, value) in enumerate(cases):
            with self.subTest(field=field, missing=missing, value=value):
                f.journal.close()
                f.journal = Journal(f.journal.path.parent / ("identity-" + str(number) + ".sqlite3"),
                                    allow_public_attempt=True)
                f.qb.routes["/api/v2/torrents/info"] = [self.t]
                f.s.routes["/api/v3/queue"] = queue_rows
                f.s.routes["/api/v3/history/since"] = [f.grab]
                original = f.journal.transition
                def transition(*args, **kwargs):
                    row = original(*args, **kwargs)
                    if args[2] == "retry_search_recorded":
                        replacement = dict(f.grab, id=18, downloadId="b" * 40,
                            date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                        if missing:
                            replacement.pop(field)
                        else:
                            replacement[field] = value
                        f.s.routes["/api/v3/history/since"] = [f.grab, replacement]
                    return row
                with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                        "production._send_queue_delete", side_effect=self.removed), patch.object(
                        f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
                    row = self.execute()
                self.assertEqual(row["stage"], "retry_search_blocked")
                self.assertEqual(row["stop_reason"], "replacement_history_identity_invalid")
                search.assert_not_called()
                reopened = Journal(f.journal.path)
                try:
                    self.assertEqual(reopened.get(row["key"])["stop_reason"], "replacement_history_identity_invalid")
                finally:
                    reopened.close()

    def test_final_history_valid_unrelated_content_can_be_ignored(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                date = datetime.datetime.now(datetime.timezone.utc).isoformat()
                other_series = dict(f.grab, id=18, seriesId=99, date=date)
                other_episode = dict(f.grab, id=19, episodeId=99, date=date)
                f.s.routes["/api/v3/history/since"] = [f.grab, other_series, other_episode]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        search.assert_called_once()

    def assert_invalid_final_records_block(self, cases, route, reason):
        f = self.f
        original_queue = f.s.routes["/api/v3/queue"]
        for number, record in enumerate(cases):
            with self.subTest(case=number):
                f.journal.close()
                f.journal = Journal(f.journal.path.parent / ("schema-" + str(number) + ".sqlite3"),
                                    allow_public_attempt=True)
                f.qb.routes["/api/v2/torrents/info"] = [self.t]
                f.s.routes["/api/v3/queue"] = original_queue
                f.s.routes["/api/v3/history/since"] = [f.grab]
                original = f.journal.transition
                def transition(*args, **kwargs):
                    row = original(*args, **kwargs)
                    if args[2] == "retry_search_recorded":
                        entry = dict(record, date=datetime.datetime.now(datetime.timezone.utc).isoformat())
                        if route == "/api/v3/queue":
                            f.s.routes[route] = {"totalRecords": 1, "records": [entry]}
                        else:
                            f.s.routes[route] = [entry]
                    return row
                with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                        "production._send_queue_delete", side_effect=self.removed), patch.object(
                        f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
                    row = self.execute()
                self.assertEqual(row["stage"], "retry_search_blocked")
                self.assertEqual(row["stop_reason"], reason)
                search.assert_not_called()
                reopened = Journal(f.journal.path)
                try:
                    self.assertEqual(reopened.get(row["key"])["stop_reason"], reason)
                finally:
                    reopened.close()

    def test_final_history_missing_malformed_unknown_event_type_blocks_search(self):
        base = dict(self.f.grab, id=18, downloadId="b" * 40)
        base.pop("eventType")
        cases = [base, *[dict(base, eventType=value) for value in
            (None, True, False, 1.0, "1", 0, "unknown", "Unknown", "futureType", 8, -1, [], {}, "")]]
        self.assert_invalid_final_records_block(cases, "/api/v3/history/since", "replacement_history_event_invalid")

    def test_known_non_grab_history_types_can_be_ignored(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                types = [2, 3, 4, 5, 6, 7, "seriesFolderImported", "downloadFolderImported",
                         "downloadFailed", "episodeFileDeleted", "episodeFileRenamed", "downloadIgnored"]
                f.s.routes["/api/v3/history/since"] = [dict(id=18 + n, eventType=value) for n, value in enumerate(types)]
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        search.assert_called_once()

    def test_final_history_baseline_does_not_waive_event_type_validation(self):
        malformed = dict(self.f.grab)
        malformed.pop("eventType")
        self.assert_invalid_final_records_block([malformed], "/api/v3/history/since", "replacement_history_event_invalid")

    def test_final_queue_missing_or_invalid_identity_blocks_search(self):
        base = {"id": 18, "seriesId": 2, "episodeId": 3}
        cases = []
        for field in ("seriesId", "episodeId"):
            missing = dict(base)
            missing.pop(field)
            cases.append(missing)
            for value in (None, True, False, "2", "3", 2.0, 3.0, 0, -1, [], {}, ""):
                cases.append(dict(base, **{field: value}))
        cases.append(dict(base, id=7, episodeId=None))  # Stale original row must also be validated.
        self.assert_invalid_final_records_block(cases, "/api/v3/queue", "replacement_queue_identity_invalid")

    def test_final_queue_valid_unrelated_content_can_be_ignored(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                f.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [
                    {"id": 18, "seriesId": 99, "episodeId": 3}, {"id": 19, "seriesId": 2, "episodeId": 99}]}
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        search.assert_called_once()

    def test_final_queue_unrelated_series_with_unmapped_episode_does_not_block_search(self):
        f = self.f
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                f.s.routes["/api/v3/queue"] = {"totalRecords": 2, "records": [
                    {"id": 18, "seriesId": 99, "episodeId": None}, {"id": 19, "seriesId": 98}]}
            return row
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch(
                "production._send_episode_search", return_value=41) as search:
            row = self.execute()
        self.assertEqual(row["stage"], "retry_requested")
        self.assertEqual(row["search_command_id"], 41)
        search.assert_called_once_with(f.s, [3])

    def test_unexpected_blocklisting_requires_review_not_another_search(self):
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a, **kw: self.f.results()), patch(
                "production._send_episode_search") as search:
            row = self.execute()
        self.assertEqual(row["stage"], "manual_review")
        search.assert_not_called()

    def test_withdrawn_routine_permission_after_search_commit_blocks_search(self):
        from authorization import RoutineAuthorization, RULE, code_digest, scope_digest
        f = self.f
        now = time.time()
        authority = RoutineAuthorization({"enabled": True, "rule": RULE, "grant_id": "c" * 64,
            "issued_at": now - 1, "expires_at": now + 3600, "scope_digest": scope_digest(f.config),
            "code_digest": code_digest()}, f.config)
        original = f.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[2] == "retry_search_recorded":
                authority.value["enabled"] = False
            return row
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=self.removed), patch.object(
                f.journal, "transition", side_effect=transition), patch("production._send_episode_search") as search:
            row = production.execute_routine_attempt(f.config, f.qb, f.apis, f.journal, f.report, authority)
        self.assertEqual(row["stage"], "retry_search_blocked")
        self.assertEqual(row["stop_reason"], "routine_authorization_expired_or_scope_changed")
        search.assert_not_called()

    def test_legacy_context_cannot_enable_soft_retry_without_attempt_identity(self):
        context = dict(self.f.context, metadata_retry={"blocklist": False, "search": "EpisodeSearch"})
        for field in production.ATTEMPT_CONTEXT_FIELDS:
            context.pop(field)
        with self.assertRaisesRegex(SafetyError, "invalid_operation_context"):
            production.validate_context(context)


class MetadataTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock(config={"url": "https://sonarr.example.invalid", "api_key": "REPLACE_ME"}, deadline=None)
        self.response = Mock(status=201)
        self.response.__enter__ = Mock(return_value=self.response)
        self.response.__exit__ = Mock(return_value=False)
        self.response.read.return_value = b'{"id":41,"name":"EpisodeSearch","body":{"episodeIds":[3]}}'
        self.opener = Mock()
        self.opener.open.return_value = self.response

    def test_soft_removal_params_and_exact_episode_search_command(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                "urllib.request.build_opener", return_value=self.opener):
            production._send_queue_delete(self.api, 7, blocklist=False)
            request = self.opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "DELETE")
            for param in ("removeFromClient=true", "blocklist=false", "skipRedownload=true", "changeCategory=false"):
                self.assertIn(param, request.full_url)
            self.assertEqual(production._send_episode_search(self.api, [3]), 41)
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://sonarr.example.invalid/api/v3/command")
        self.assertEqual(json.loads(request.data), {"name": "EpisodeSearch", "episodeIds": [3]})

    def test_search_and_soft_removal_refuse_disabled_release_gate(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", False), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("urllib.request.build_opener") as opener:
            with self.assertRaises(SafetyError):
                production._send_episode_search(self.api, [3])
            with self.assertRaises(SafetyError):
                production._send_queue_delete(self.api, 7, blocklist=False)
        opener.assert_not_called()

    def test_malformed_or_lost_search_receipt_is_uncertain_not_retried_or_disclosed(self):
        for payload in (b'{"id":true,"name":"EpisodeSearch"}', b'{"id":0,"name":"EpisodeSearch"}',
                        b'{"id":41,"name":"SeriesSearch"}', b'{"id":41,"name":"EpisodeSearch"}',
                        b'{"id":41,"name":"EpisodeSearch","body":{"episodeIds":[4]}}',
                        b'private-response', b'x' * 65537):
            self.response.read.return_value = payload
            self.opener.reset_mock()
            with self.subTest(payload_size=len(payload)), patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                    "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch(
                    "urllib.request.build_opener", return_value=self.opener):
                with self.assertRaisesRegex(SafetyError, "^episode_search_outcome_uncertain$"):
                    production._send_episode_search(self.api, [3])
            self.opener.open.assert_called_once()

    def test_episode_search_rejects_invalid_targets_before_transport(self):
        with patch("production.METADATA_RETRY_RELEASE_ENABLED", True), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("urllib.request.build_opener") as opener:
            for ids in ([], [True], [-1], [3, 3], None):
                with self.subTest(ids=ids), self.assertRaises(SafetyError):
                    production._send_episode_search(self.api, ids)
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
