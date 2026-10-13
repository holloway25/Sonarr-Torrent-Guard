import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from safety import (Journal, SafetyError, check_fresh, record_preview, reconcile, simulate_action)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name)/"action-journal.sqlite3"
        self.journal = Journal(self.path)
        self.original = {"instance": "HD", "hash": "a" * 40, "decision": "would_fail",
                         "public_source_confirmed": True, "ownership_fingerprint": "b" * 64,
                         "manifest_fingerprint": "c" * 64, "checked_at": 1000}
        self.ready = {"status": "verified", "automatic_retry": True, "interactive_retry": True}
        self.fresh = {"assessment": copy.deepcopy(self.original), "readiness": self.ready}
        self.confirmed = {k: True for k in (
            "torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")}

    def tearDown(self):
        self.journal.close()
        self.folder.cleanup()

    def simulate(self, sender, observation=None, fresh=None):
        return simulate_action(self.journal, self.original, lambda: fresh or self.fresh,
                               sender, lambda: self.confirmed if observation is None else observation, now=1000)

    def test_preview_rechecks_and_cannot_dispatch(self):
        prepared = self.journal.prepare(self.original)
        with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
            self.journal.transition(prepared["key"], "prepared", "dispatch_recorded")
        recheck = Mock(return_value=self.fresh)
        row = record_preview(self.journal, self.original, recheck, now=1000)
        recheck.assert_called_once()
        self.assertEqual(row["stage"], "preview_verified")
        with self.assertRaises(SafetyError):
            self.journal.transition(row["key"], "preview_verified", "dispatch_recorded")
        with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
            self.journal.prepare(self.original, mode="live")

    def test_rechecks_reject_identity_manifest_source_decision_and_staleness(self):
        changes = [("ownership_fingerprint", "d" * 64), ("manifest_fingerprint", "d" * 64),
                   ("hash", "d" * 40), ("instance", "UHD"), ("decision", "keep"),
                   ("public_source_confirmed", False), ("checked_at", 980),
                   ("checked_at", 1001), ("checked_at", float("nan"))]
        for field, value in changes:
            fresh = copy.deepcopy(self.fresh)
            fresh["assessment"][field] = value
            with self.subTest(field=field), self.assertRaises(SafetyError):
                check_fresh(self.original, fresh, now=1000)

    def test_disabled_unknown_retry_and_failed_recheck_never_send(self):
        for readiness in ({}, dict(self.ready, automatic_retry=False),
                          dict(self.ready, interactive_retry=False)):
            with self.subTest(readiness=readiness), self.assertRaises(SafetyError):
                check_fresh(self.original, dict(self.fresh, readiness=readiness), now=1000)
        sender = Mock()
        row = simulate_action(self.journal, self.original,
                              Mock(side_effect=TimeoutError()), sender, Mock(), now=1000)
        self.assertEqual(row["stage"], "cancelled")
        sender.assert_not_called()

    def test_fresh_file_change_cancels_simulated_action(self):
        fresh = copy.deepcopy(self.fresh)
        fresh["assessment"]["manifest_fingerprint"] = "d" * 64
        sender = Mock()
        row = self.simulate(sender, fresh=fresh)
        self.assertEqual(row["stage"], "cancelled")
        sender.assert_not_called()

    def test_durable_dispatch_record_exists_before_simulated_send(self):
        observed_stages = []
        def sender():
            other = Journal(self.path)
            try:
                key = self.journal.prepare(self.original, mode="simulation")["key"]
                observed_stages.append(other.get(key)["stage"])
            finally:
                other.close()
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        self.assertEqual(observed_stages, ["dispatch_recorded"])

    def test_success_code_alone_does_not_prove_completion(self):
        sender = Mock(return_value=204)
        row = self.simulate(sender, observation={})
        self.assertEqual(row["stage"], "uncertain")
        sender.assert_called_once()

    def test_completion_transition_requires_all_positive_observations(self):
        row = self.journal.prepare(self.original, mode="simulation")
        self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        with self.assertRaisesRegex(SafetyError, "completion_not_verified"):
            self.journal.transition(row["key"], "dispatch_recorded", "complete", {})
        self.assertEqual(self.journal.get(row["key"])["stage"], "dispatch_recorded")

    def test_lost_response_then_restart_does_not_repeat_send(self):
        sender = Mock(side_effect=TimeoutError())
        row = self.simulate(sender, observation={})
        self.assertEqual(row["stage"], "uncertain")
        self.journal.close()
        self.journal = Journal(self.path)
        row = self.simulate(sender)
        self.assertEqual(row["stage"], "complete")
        sender.assert_called_once()

    def test_process_interruption_after_dispatch_is_reconciled_only(self):
        sender = Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.simulate(sender)
        self.journal.close()
        self.journal = Journal(self.path)
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        sender.assert_called_once()

    def test_interruption_before_dispatch_allows_fresh_simulated_attempt(self):
        row = self.journal.prepare(self.original, mode="simulation")
        self.assertEqual(row["stage"], "prepared")
        sender = Mock()
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        sender.assert_called_once()

    def test_partial_removal_requires_manual_review_without_retry(self):
        sender = Mock()
        row = self.simulate(sender, observation={"torrent_absent": True})
        self.assertEqual(row["stage"], "manual_review")
        self.assertEqual(self.simulate(sender)["stage"], "manual_review")
        sender.assert_called_once()

    def test_no_replacement_or_unverified_data_deletion_stays_pending(self):
        for field in ("data_deleted", "replacement_observed"):
            observation = dict(self.confirmed, **{field: None})
            sender = Mock()
            # Use an independent hash to test both durable operation records.
            self.original["hash"] = ("a" if field == "data_deleted" else "d") * 40
            self.fresh["assessment"] = copy.deepcopy(self.original)
            row = self.simulate(sender, observation=observation)
            self.assertEqual(row["stage"], "replacement_pending")
            self.assertEqual(self.simulate(sender)["stage"], "complete")
            sender.assert_called_once()

    def test_observation_outage_is_uncertain_not_success(self):
        row = self.journal.prepare(self.original, mode="simulation")
        self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        row = reconcile(self.journal, row["key"], Mock(side_effect=TimeoutError()))
        self.assertEqual(row["stage"], "uncertain")

    def test_confirmed_evidence_survives_observation_outage_and_restart(self):
        sender = Mock()
        positives = {k: True for k in self.confirmed if k != "replacement_observed"}
        row = self.simulate(sender, observation=positives)
        self.assertEqual(row["stage"], "replacement_pending")
        row = reconcile(self.journal, row["key"], Mock(side_effect=TimeoutError()))
        self.assertEqual(row["stage"], "uncertain")
        self.assertEqual(row["observation"], positives)
        self.assertEqual(row["confirmed"], positives)
        self.assertFalse(row["observation_available"])
        self.assertEqual(row["current_observation"], {})
        self.journal.close()
        self.journal = Journal(self.path)
        self.assertEqual(self.journal.get(row["key"]), row)
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        sender.assert_called_once()

    def test_later_partial_observations_preserve_history_without_stale_completion(self):
        sender = Mock()
        positives = {k: True for k in self.confirmed if k != "replacement_observed"}
        row = self.simulate(sender, observation=positives)
        row = reconcile(self.journal, row["key"], lambda: {"replacement_observed": True})
        self.assertEqual(row["confirmed"], self.confirmed)
        self.assertEqual(row["observation"], self.confirmed)
        self.assertEqual(row["current_observation"], {"replacement_observed": True})
        self.assertTrue(row["observation_available"])
        self.assertEqual(row["stage"], "replacement_pending")
        # A historical union of positives is not a coherent current snapshot.
        with self.assertRaisesRegex(SafetyError, "completion_not_verified"):
            self.journal.transition(row["key"], "replacement_pending", "complete", {})
        self.journal.close()
        self.journal = Journal(self.path)
        self.assertEqual(self.journal.get(row["key"]), row)
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        sender.assert_called_once()

    def test_unknown_and_invalid_updates_do_not_erase_confirmations(self):
        positives = {k: True for k in self.confirmed if k != "replacement_observed"}
        row = self.simulate(Mock(), observation=positives)
        row = reconcile(self.journal, row["key"], lambda: {"failed": None})
        self.assertEqual(row["confirmed"], positives)
        self.assertEqual(row["observation"], positives)
        self.assertEqual(row["current_observation"], {"failed": None})
        row = reconcile(self.journal, row["key"], lambda: {"failed": "true"})
        self.assertEqual(row["stage"], "uncertain")
        self.assertFalse(row["observation_available"])
        self.assertEqual(row["confirmed"], positives)
        self.assertEqual(row["observation"], positives)

    def test_contradictions_require_review_without_erasing_historical_positives(self):
        positives = {k: True for k in self.confirmed if k != "replacement_observed"}
        row = self.simulate(Mock(), observation=positives)
        row = reconcile(self.journal, row["key"], lambda: {"torrent_absent": False})
        self.assertEqual(row["stage"], "manual_review")
        self.assertEqual(row["confirmed"], positives)
        self.assertFalse(row["observation"]["torrent_absent"])
        self.assertEqual(row["current_observation"], {"torrent_absent": False})
        self.journal.close()
        self.journal = Journal(self.path)
        self.assertEqual(self.journal.get(row["key"]), row)

    def test_existing_journal_schema_migrates_without_losing_evidence(self):
        import sqlite3
        from safety import evidence
        legacy = Path(self.folder.name)/"legacy.sqlite3"
        positives = {k: True for k in self.confirmed if k != "replacement_observed"}
        with sqlite3.connect(legacy) as db:
            db.execute("CREATE TABLE actions (key TEXT PRIMARY KEY, mode TEXT NOT NULL, stage TEXT NOT NULL, "
                       "evidence TEXT NOT NULL, observation TEXT NOT NULL, updated REAL NOT NULL)")
            db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?)", (
                "legacy-key", "simulation", "replacement_pending", json.dumps(evidence(self.original)),
                json.dumps(positives), 1000))
        db.close()
        for _ in range(2):
            journal = Journal(legacy)
            try:
                row = journal.get("legacy-key")
                self.assertEqual(row["stage"], "replacement_pending")
                self.assertEqual(row["observation"], positives)
                self.assertEqual(row["confirmed"], positives)
                self.assertFalse(row["observation_available"])
            finally:
                journal.close()

    def test_duplicates_and_concurrent_stage_changes_cannot_send_twice(self):
        row = self.journal.prepare(self.original, mode="simulation")
        self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        with self.assertRaisesRegex(SafetyError, "journal_stage_changed"):
            self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        sender = Mock()
        self.assertEqual(self.simulate(sender)["stage"], "complete")
        sender.assert_not_called()

    def test_journal_privacy_capacity_and_evidence_whitelist(self):
        report = dict(self.original, title="must not be stored", password="must not be stored")
        row = self.journal.prepare(report)
        self.assertNotIn("must not be stored", json.dumps(row))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.journal.limit = 1
        with self.assertRaisesRegex(SafetyError, "journal_capacity_reached"):
            self.journal.prepare(dict(self.original, hash="d" * 40))

    def test_corrupt_journal_is_not_replaced(self):
        self.journal.close()
        original = b"invalid database; preserve evidence"
        self.path.write_bytes(original)
        with self.assertRaises(Exception):
            Journal(self.path)
        self.assertEqual(self.path.read_bytes(), original)
        # Reopen a separate valid database so tearDown can close it normally.
        self.journal = Journal(Path(self.folder.name)/"other.sqlite3")


if __name__ == "__main__":
    unittest.main()
