import tempfile
import datetime
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import production
from guard import run
from safety import Journal, SafetyError
from test_guard import FakeApi, manifest


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.hash = "a" * 40
        self.config = {"dry_run": False, "qbittorrent": {"url": "https://downloader.example.invalid"},
                       "sonarr": {"HD": {"url": "https://sonarr.example.invalid", "api_key": "REPLACE_ME",
                           "category": "tv-hd", "download_client_binding": {
                               "id": 1, "endpoint": "https://downloader.example.invalid"},
                           "indexers": {"public": ["Public Source"], "private": ["Private Source"]}}}}
        client = {"id": 1, "name": "Downloader", "implementation": "QBittorrent", "enable": True,
                  "fields": [{"name": k, "value": v} for k, v in {
                      "host": "downloader.example.invalid", "port": 443, "useSsl": True,
                      "urlBase": "", "tvCategory": "tv-hd"}.items()]}
        self.grab = {"id": 5, "eventType": "grabbed", "downloadId": self.hash.upper(),
                     "seriesId": 2, "episodeId": 3, "sourceTitle": "Example Show S01E01",
                     "data": {"indexer": "Public Source", "downloadClientName": "Downloader"}}
        added = int(time.time()) - 600
        self.grab["date"] = datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat()
        self.s = FakeApi({
            "/api/v3/queue": {"totalRecords": 1, "records": [{"id": 7, "downloadId": self.hash.upper(),
                                "seriesId": 2, "episodeId": 3, "downloadClientId": 1}]},
            "/api/v3/history": {"totalRecords": 1, "records": [self.grab]},
            "/api/v3/history/since": [self.grab], "/api/v3/blocklist": {"totalRecords": 0, "records": []},
            "/api/v3/downloadclient": [client], "/api/v3/system/status": {"version": "4.0.20.3014"},
            "/api/v3/config/downloadclient": {"autoRedownloadFailed": True, "autoRedownloadFailedFromInteractiveSearch": True}})
        self.s.config, self.s.deadline = self.config["sonarr"]["HD"], None
        self.qb = FakeApi({"/api/v2/torrents/info": [{"hash": self.hash, "category": "tv-hd",
                                                   "state": "stoppedUP", "added_on": added}],
                           "/api/v2/torrents/files": manifest(("episode.exe", 0))})
        self.apis = {"HD": self.s}
        self.report = run(self.config, self.qb, self.apis)[0]
        self.folder = tempfile.TemporaryDirectory()
        self.journal = Journal(Path(self.folder.name)/"actions.sqlite3", allow_single_test=True)
        self.approval = dict({k: self.report[k] for k in (
            "instance", "hash", "ownership_fingerprint", "manifest_fingerprint")},
            operation="sonarr_fail_remove_retry", expires_at=time.time() + 120, nonce="d" * 64)
        self.context = production.capture_context(self.config, self.s, self.report, production.digest(self.approval["nonce"]))

    def tearDown(self):
        self.journal.close()
        self.folder.cleanup()

    def results(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.qb.routes["/api/v2/torrents/info"] = []
        failed = dict(self.grab, id=6, eventType="downloadFailed", date=stamp)
        replacement = dict(self.grab, id=8, downloadId="b" * 40, date=stamp)
        self.s.routes["/api/v3/history/since"] = [self.grab, failed, replacement]
        block = {"id": 9, "seriesId": 2, "episodeIds": [3], "indexer": "Public Source",
                 "sourceTitle": self.grab["sourceTitle"], "date": stamp}
        self.s.routes["/api/v3/blocklist"] = {"totalRecords": 1, "records": [block]}

    def observe(self):
        return production.OutcomeVerifier(self.config, self.qb, self.apis, self.context).observe()

    def test_api_results_are_independent_and_data_deletion_remains_unknown(self):
        self.results()
        result = self.observe()
        for field in ("torrent_absent", "failed", "blocklisted", "replacement_observed"):
            self.assertIs(result[field], True)
        self.assertIsNone(result["data_deleted"])

    def test_queue_disappearance_alone_does_not_prove_failure_or_replacement(self):
        self.qb.routes["/api/v2/torrents/info"] = []
        result = self.observe()
        self.assertTrue(result["torrent_absent"])
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertFalse(result[field])

    def test_preexisting_records_are_not_mistaken_for_new_results(self):
        self.results()
        self.context["baseline_history_ids"] = [5, 6, 8]
        self.context["baseline_blocklist_ids"] = [9]
        result = self.observe()
        self.assertFalse(result["failed"])
        self.assertFalse(result["blocklisted"])
        self.assertFalse(result["replacement_observed"])

    def test_new_records_before_dispatch_are_not_outcome_evidence(self):
        self.results()
        result = production.OutcomeVerifier(self.config, self.qb, self.apis, self.context,
                                            not_before=time.time()+10).observe()
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertFalse(result[field])

    def test_same_second_results_are_uncertain_not_missing_or_confirmed(self):
        self.results()
        stamp = "2026-01-01T00:00:10Z"
        for row in self.s.routes["/api/v3/history/since"][1:]:
            row["date"] = stamp
        self.s.routes["/api/v3/blocklist"]["records"][0]["date"] = stamp
        boundary = production.event_time({"date": stamp}) + .25
        result = production.OutcomeVerifier(self.config, self.qb, self.apis, self.context, boundary).observe()
        for field in ("failed", "blocklisted", "replacement_observed"):
            self.assertIsNone(result[field])

    def test_timestamp_precision_timezone_and_predispatch_boundaries(self):
        boundary = production.event_time({"date": "2026-01-01T00:00:10.25Z"})
        for stamp, expected in (("2026-01-01T00:00:09Z", False),
                                ("2026-01-01T00:00:10Z", None),
                                ("2026-01-01T00:00:10.1Z", False),
                                ("2026-01-01T00:00:10.2Z", None),
                                ("2026-01-01T00:00:10.249Z", False),
                                ("2026-01-01T00:00:10.25Z", True),
                                ("2026-01-01T00:00:11Z", True),
                                ("2026-01-01T11:00:10+11:00", None)):
            with self.subTest(stamp=stamp):
                self.assertIs(production.event_after({"date": stamp}, boundary), expected)

    def test_same_second_baseline_records_still_cannot_confirm_outcomes(self):
        self.results()
        self.context["baseline_history_ids"] = [5, 6, 8]
        self.context["baseline_blocklist_ids"] = [9]
        result = self.observe()
        self.assertFalse(result["failed"])
        self.assertFalse(result["blocklisted"])

    def test_single_test_regrab_cannot_reuse_consumed_approval(self):
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=TimeoutError()) as sender:
            production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.report["attempt_fingerprint"] = "e" * 64
            production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            sender.assert_called_once()

    def test_missing_event_timestamps_are_unknown_not_confirmations(self):
        self.results()
        del self.s.routes["/api/v3/history/since"][1]["date"]
        del self.s.routes["/api/v3/blocklist"]["records"][0]["date"]
        result = self.observe()
        self.assertIsNone(result["failed"])
        self.assertIsNone(result["blocklisted"])

    def test_other_episode_hash_title_client_and_indexer_do_not_match(self):
        for mutation in ("episode", "hash", "title", "client", "indexer"):
            self.results()
            if mutation == "episode":
                self.s.routes["/api/v3/history/since"][1]["episodeId"] = 99
            elif mutation == "hash":
                self.s.routes["/api/v3/history/since"][1]["downloadId"] = "c" * 40
            elif mutation == "title":
                self.s.routes["/api/v3/history/since"][1]["sourceTitle"] = "Different release"
            elif mutation == "client":
                self.s.routes["/api/v3/history/since"][1]["data"] = {"downloadClientName": "Other"}
            else:
                self.s.routes["/api/v3/blocklist"]["records"][0]["indexer"] = "Other Source"
            with self.subTest(mutation=mutation):
                self.assertFalse(self.observe()["blocklisted" if mutation == "indexer" else "failed"])

    def test_partial_outage_does_not_erase_other_verified_results(self):
        self.results()
        self.s.routes["/api/v3/history/since"] = TimeoutError()
        result = self.observe()
        self.assertTrue(result["torrent_absent"])
        self.assertTrue(result["blocklisted"])
        self.assertIsNone(result["failed"])
        self.assertIsNone(result["replacement_observed"])

    def test_malformed_torrent_response_never_proves_absence(self):
        self.qb.routes["/api/v2/torrents/info"] = [{}]
        self.assertIsNone(self.observe()["torrent_absent"])

    def test_context_has_no_raw_release_title_endpoint_or_credentials(self):
        text = str(self.context)
        for value in (self.grab["sourceTitle"], "example.invalid", "REPLACE_ME"):
            self.assertNotIn(value, text)
        with self.assertRaises(SafetyError):
            production.validate_context(dict(self.context, password="not allowed"))

    def test_context_title_comes_from_current_grab_not_older_same_hash(self):
        old = dict(self.grab, id=4, sourceTitle="An older display title")
        self.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [old, self.grab]}
        context = production.capture_context(self.config, self.s, self.report, production.digest("approval"))
        self.assertEqual(context["release_title_digest"], production.digest(self.grab["sourceTitle"]))

    def test_endpoint_drift_and_unreviewed_version_stop_observation(self):
        self.s.routes["/api/v3/system/status"]["version"] = "unreviewed"
        with self.assertRaises(SafetyError):
            self.observe()
        self.s.routes["/api/v3/system/status"]["version"] = "4.0.20.3014"
        self.config["qbittorrent"]["url"] = "https://other.example.invalid"
        with self.assertRaises(SafetyError):
            self.observe()

    def test_release_gate_and_dry_run_and_journal_gate_all_block_sender(self):
        with patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            with patch("production.SINGLE_TEST_RELEASE_ENABLED", True):
                self.config["dry_run"] = True
                with self.assertRaises(SafetyError):
                    production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
                self.config["dry_run"] = False
                self.journal.allow_single_test = False
                with self.assertRaises(SafetyError):
                    production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            send.assert_not_called()

    def test_approval_expiry_and_exact_target_are_required(self):
        for change in ({"expires_at": time.time()-1}, {"expires_at": time.time()+1000},
                       {"hash": "b"*40}, {"manifest_fingerprint": "b"*64}, {"instance": "UHD"}):
            with self.subTest(change=change), self.assertRaises(SafetyError):
                production.validate_approval(dict(self.approval, **change), self.report)
        production.validate_approval(self.approval, self.report)

    def test_changed_sonarr_endpoint_invalidates_original_approval_before_send(self):
        self.config["sonarr"]["HD"]["url"] = "https://other-sonarr.example.invalid"
        refreshed = run(self.config, self.qb, self.apis)[0]
        with self.assertRaisesRegex(SafetyError, "approval_expired_or_target_mismatch"):
            production.validate_approval(self.approval, refreshed)
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete") as sender:
            with self.assertRaisesRegex(SafetyError, "identity_or_manifest_changed"):
                production.execute_single_test(self.config, self.qb, self.apis,
                                               self.journal, self.report, self.approval)
            sender.assert_not_called()

    def test_sonarr_endpoint_drift_during_final_recheck_cancels_dispatch(self):
        original = production.recheck_candidate
        checks = []
        def recheck(*args):
            checks.append(1)
            if len(checks) == 2:
                self.config["sonarr"]["HD"]["url"] = "https://other-sonarr.example.invalid"
            return original(*args)
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production.recheck_candidate", side_effect=recheck), patch(
                "production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis,
                                                 self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "cancelled")
            sender.assert_not_called()

    def test_controlled_sender_records_intent_then_sends_exactly_once(self):
        stages = []
        def send(api, queue_id):
            self.assertIs(api, self.s)
            self.assertEqual(queue_id, 7)
            key = production.digest(["single_test", "HD", self.hash])
            stages.append(self.journal.get(key)["stage"])
            self.results()
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete", side_effect=send) as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(stages, ["dispatch_recorded"])
            self.assertEqual(row["stage"], "replacement_pending")
            self.assertIsNone(row["observation"].get("data_deleted"))
            self.journal.close()
            self.journal = Journal(Path(self.folder.name)/"actions.sqlite3", allow_single_test=True)
            production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            sender.assert_called_once()

    def test_lost_response_is_never_retried(self):
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete", side_effect=TimeoutError()) as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "uncertain")
            production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            sender.assert_called_once()

    def test_final_recheck_change_cancels_before_send(self):
        original_recheck = production.recheck_candidate
        checks = []
        def recheck(*args):
            fresh = original_recheck(*args)
            checks.append(1)
            if len(checks) == 2:
                fresh["assessment"]["manifest_fingerprint"] = "e"*64
            return fresh
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production.recheck_candidate", side_effect=recheck), patch("production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "cancelled")
            sender.assert_not_called()

    def test_approval_expiring_during_preparation_cancels_before_send(self):
        def capture(*args):
            self.approval["expires_at"] = time.time() - 1
            return self.context
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production.capture_context", side_effect=capture), patch("production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "cancelled")
            sender.assert_not_called()

    def test_worker_overlap_blocks_sender(self):
        import fcntl
        with open(Path(self.folder.name)/"guard.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete") as sender:
                with self.assertRaisesRegex(SafetyError, "another_run_is_active"):
                    production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
                sender.assert_not_called()

    def after_dispatch_commit(self, effect):
        original = self.journal.transition
        def transition(*args, **kwargs):
            row = original(*args, **kwargs)
            if args[1:3] == ("prepared", "dispatch_recorded"):
                effect()
            return row
        return transition

    def test_approval_expiring_during_commit_preserves_unsent_record_after_restart(self):
        def expire():
            self.approval["expires_at"] = time.time() - 1
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch.object(
                self.journal, "transition", side_effect=self.after_dispatch_commit(expire)), patch(
                "production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "approval_expired_or_target_mismatch")
            self.assertIsNotNone(row["dispatched_at"])
            self.assertEqual(row["evidence"]["hash"], self.hash)
            self.assertEqual(row["context"]["queue_id"], 7)
            sender.assert_not_called()
        self.journal.close()
        self.journal = Journal(Path(self.folder.name)/"actions.sqlite3", allow_single_test=True)
        self.assertEqual(self.journal.get(row["key"]), row)
        observe = Mock()
        self.assertEqual(production.reconcile(self.journal, row["key"], observe), row)
        observe.assert_not_called()

    def test_snapshot_expiring_during_commit_blocks_send(self):
        snapshots = []
        original = production.recheck_candidate
        def recheck(*args):
            fresh = original(*args)
            snapshots.append(fresh)
            return fresh
        def expire():
            snapshots[-1]["assessment"]["checked_at"] = time.time()-11
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production.recheck_candidate", side_effect=recheck), patch.object(
                self.journal, "transition", side_effect=self.after_dispatch_commit(expire)), patch(
                "production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "fresh_assessment_expired")
            sender.assert_not_called()

    def test_version_change_after_context_capture_blocks_final_send(self):
        original = production.capture_context
        def capture(*args):
            result = original(*args)
            self.s.routes["/api/v3/system/status"] = {"version": "unreviewed"}
            return result
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production.capture_context", side_effect=capture), patch("production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "unreviewed_sonarr_version")
            sender.assert_not_called()

    def test_version_change_during_commit_blocks_send(self):
        def change():
            self.s.routes["/api/v3/system/status"] = {"version": "unreviewed"}
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch.object(
                self.journal, "transition", side_effect=self.after_dispatch_commit(change)), patch(
                "production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stop_reason"], "unreviewed_sonarr_version")
            sender.assert_not_called()

    def test_post_commit_version_outage_blocks_send(self):
        def outage():
            self.s.routes["/api/v3/system/status"] = TimeoutError()
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch.object(
                self.journal, "transition", side_effect=self.after_dispatch_commit(outage)), patch(
                "production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "dispatch_validation_failed")
            sender.assert_not_called()

    def test_approval_expiring_during_final_version_request_blocks_send(self):
        original = self.s.call
        def call(route, params=None):
            key = production.digest(["single_test", "HD", self.hash])
            row = self.journal.get(key)
            if route == "/api/v3/system/status" and row is not None and row["stage"] == "dispatch_recorded":
                self.approval["expires_at"] = time.time()-1
            return original(route, params)
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch.object(
                self.s, "call", side_effect=call), patch("production._send_queue_delete") as sender:
            row = production.execute_single_test(self.config, self.qb, self.apis, self.journal, self.report, self.approval)
            self.assertEqual(row["stage"], "dispatch_blocked")
            self.assertEqual(row["stop_reason"], "approval_expired_or_target_mismatch")
            sender.assert_not_called()

    def test_sender_refuses_production_transport_when_release_gate_is_off(self):
        with patch("urllib.request.build_opener") as opener:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                production._send_queue_delete(self.s, 7)
            opener.assert_not_called()

    def test_delete_transport_has_fixed_scope_and_never_follows_redirects(self):
        response = Mock(status=200)
        response.read.return_value = b""
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("urllib.request.build_opener", return_value=opener):
            production._send_queue_delete(self.s, 7)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "DELETE")
        self.assertIn("/api/v3/queue/7?", request.full_url)
        for param in ("removeFromClient=true", "blocklist=true", "skipRedownload=false", "changeCategory=false"):
            self.assertIn(param, request.full_url)
        with self.assertRaises(SafetyError):
            production.RejectDeleteRedirect().redirect_request(None)


if __name__ == "__main__":
    unittest.main()
