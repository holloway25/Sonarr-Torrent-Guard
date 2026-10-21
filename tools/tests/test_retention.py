import contextlib
import copy
import io
import json
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

import production
import retention
import safety
from safety import Journal, SafetyError
from tools.tests import test_production as fixtures


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
        self.journal = self.f.journal
        self.journal.allow_public_attempt = True
        self.journal.allow_archive = True
        self.later = time.time() + 31 * 86400

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def make_row(self, number=1, stage="cleanup_resolved", mode="public_attempt"):
        report = copy.deepcopy(self.f.report)
        context = copy.deepcopy(self.f.context)
        h = format(number, "040x")
        fp = production.digest(["HD", h, context["download_added_on"], context["grab_ids"]])
        report.update(hash=h, attempt_fingerprint=fp)
        context.update(hash=h, attempt_fingerprint=fp, approval_digest=format(number, "064x"))
        row = self.journal.prepare(report, mode=mode, context=context)
        if stage == "prepared":
            return report, context, row
        row = self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        if stage != "dispatch_recorded":
            fields = safety.OBSERVATION_FIELDS if stage == "complete" else ("torrent_absent", "failed", "blocklisted")
            row = self.journal.transition(row["key"], "dispatch_recorded", stage,
                {field: True for field in fields} if stage in ("cleanup_resolved", "complete") else None)
        return report, context, row

    def test_default_preview_moves_nothing_and_apply_requires_separate_permission(self):
        _, _, row = self.make_row()
        self.journal.allow_archive = False
        result = self.journal.archive_resolved(now=self.later)
        self.assertEqual(result["eligible"], 1)
        self.assertEqual(result["archived"], 0)
        self.assertEqual(self.journal.get(row["key"]), row)
        with self.assertRaisesRegex(SafetyError, "journal_archive_not_authorized"):
            self.journal.archive_resolved(now=self.later, preview=False)

    def test_archive_preserves_every_column_restart_lookup_and_private_permissions(self):
        report, context, row = self.make_row()
        self.journal.db.execute("ALTER TABLE actions ADD COLUMN future_field TEXT")
        self.journal.db.execute("UPDATE actions SET future_field='retained extension'")
        self.journal.db.commit()
        columns = [r[1] for r in self.journal.db.execute("PRAGMA table_info(actions)")]
        raw = dict(zip(columns, self.journal.db.execute("SELECT * FROM actions").fetchone()))
        result = self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(result["archived"], 1)
        self.assertEqual(result["active_rows"], 0)
        self.assertEqual(json.loads(self.journal.db.execute("SELECT payload FROM actions_archive").fetchone()[0]), raw)
        self.assertEqual(self.journal.get(row["key"]), row)
        self.assertEqual(self.journal.related("HD", report["hash"]), [row])
        reopened = Journal(self.journal.path, read_only=True)
        try:
            self.assertEqual(reopened.get(row["key"]), row)
            self.assertEqual(reopened.related("HD", report["hash"]), [row])
        finally:
            reopened.close()
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)

    def test_archived_attempt_still_blocks_duplicate_via_actual_coordinator(self):
        f = self.f
        row = self.journal.prepare(f.report, mode="public_attempt", context=f.context)
        self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        self.journal.transition(row["key"], "dispatch_recorded", "cleanup_resolved",
                               {k: True for k in ("torrent_absent", "failed", "blocklisted")})
        self.journal.archive_resolved(now=self.later, preview=False)
        with patch("production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            # Exact old approval/context key takes read-only reconciliation.
            recovered = production.execute_public_attempt(f.config, f.qb, f.apis, self.journal, f.report, f.approval)
        self.assertEqual(recovered["stage"], "cleanup_resolved")
        send.assert_not_called()
        with self.assertRaisesRegex(SafetyError, "new_attempt_not_confirmed"):
            production.check_prior_attempts(self.journal, f.report, config=f.config)
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "new_attempt_not_confirmed"):
                production.execute_single_test(f.config, f.qb, f.apis, self.journal, f.report, f.approval)
        send.assert_not_called()

    def test_same_key_prepare_never_recreates_archived_operation(self):
        report, context, row = self.make_row()
        self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.prepare(report, mode="public_attempt", context=context), row)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 0)

    def test_archived_single_test_still_blocks_other_mode(self):
        report, context, row = self.make_row(mode="single_test", stage="complete")
        self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.related("HD", report["hash"]), [row])
        with self.assertRaisesRegex(SafetyError, "new_attempt_not_confirmed"):
            production.check_prior_attempts(self.journal, report, config=self.f.config)

    def test_archived_history_still_allows_a_genuinely_new_attempt(self):
        report, context, row = self.make_row()
        self.journal.archive_resolved(now=self.later, preview=False)
        added = int(row["dispatched_at"]) + 3
        grabs = [max(context["grab_ids"]) + 1]
        newer = dict(report, download_added_on=added, grab_ids=grabs,
                     attempt_fingerprint=production.digest(["HD", report["hash"], added, grabs]))
        production.check_prior_attempts(self.journal, newer, config=self.f.config)

    def test_unresolved_records_are_never_moved(self):
        records = [self.make_row(n, stage=stage)[2] for n, stage in enumerate(
            ("prepared", "dispatch_recorded", "uncertain", "replacement_pending", "manual_review"), 1)]
        result = self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(result["archived"], 0)
        for row in records:
            self.assertEqual(self.journal.get(row["key"]), row)
        self.assertEqual(result["active_rows"], 5)

    def test_metadata_receipts_and_nonproduction_records_remain_active(self):
        report, context, row = self.make_row(stage="prepared")
        context["metadata_retry"] = {"blocklist": False, "search": "EpisodeSearch"}
        # Simulate persisted metadata workflow states, never an actual sender.
        self.journal.db.execute("UPDATE actions SET stage='retry_requested',context=? WHERE key=?",
                                (json.dumps(context), row["key"]))
        self.journal.db.commit()
        self.journal.prepare(dict(report, hash="f" * 40), mode="preview")
        result = self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(result["archived"], 0)
        self.assertEqual(result["active_rows"], 2)

    def test_manual_review_with_positive_evidence_is_not_treated_as_resolved(self):
        _, _, row = self.make_row(stage="dispatch_recorded")
        row = self.journal.transition(row["key"], "dispatch_recorded", "manual_review",
                                     {k: True for k in ("torrent_absent", "failed", "blocklisted")})
        self.assertEqual(self.journal.archive_resolved(now=self.later, preview=False)["archived"], 0)
        self.assertEqual(self.journal.get(row["key"]), row)

    def test_recent_or_unavailable_or_incomplete_evidence_is_not_archived(self):
        _, _, row = self.make_row()
        self.assertEqual(self.journal.archive_resolved()["eligible"], 0)
        self.journal.db.execute("UPDATE actions SET observation_available=0")
        self.journal.db.commit()
        self.assertEqual(self.journal.archive_resolved(now=self.later)["eligible"], 0)
        self.journal.db.execute("UPDATE actions SET observation_available=1,current_observation='{}'")
        self.journal.db.commit()
        self.assertEqual(self.journal.archive_resolved(now=self.later)["eligible"], 0)

    def test_copy_delete_failure_rolls_back_all_evidence(self):
        _, _, row = self.make_row()
        self.journal.db.execute("CREATE TRIGGER fail_archive_delete BEFORE DELETE ON actions "
                                "BEGIN SELECT RAISE(ABORT,'simulated failure'); END")
        self.journal.db.commit()
        with self.assertRaises(sqlite3.DatabaseError):
            self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM actions_archive").fetchone()[0], 0)
        self.assertEqual(self.journal.get(row["key"]), row)

    def test_second_row_delete_failure_rolls_back_entire_batch(self):
        first = self.make_row(1)[2]
        second = self.make_row(2)[2]
        # Make transaction order deterministic: a first-row commit must be
        # exposed by failure on the second row, not a failure before any work.
        self.journal.db.execute("UPDATE actions SET updated=? WHERE key=?", (time.time() + 1, first["key"]))
        self.journal.db.execute("UPDATE actions SET updated=? WHERE key=?", (time.time() + 2, second["key"]))
        self.journal.db.execute("CREATE TRIGGER fail_second_delete BEFORE DELETE ON actions "
                                "WHEN OLD.key='" + second["key"] + "' "
                                "BEGIN SELECT RAISE(ABORT,'simulated second-row failure'); END")
        self.journal.db.commit()
        before = self.journal.db.execute("SELECT * FROM actions ORDER BY key").fetchall()
        with self.assertRaises(sqlite3.DatabaseError):
            self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM actions_archive").fetchone()[0], 0)
        self.assertEqual(self.journal.db.execute("SELECT * FROM actions ORDER BY key").fetchall(), before)
        self.assertEqual(self.journal.get(first["key"]), first)
        self.assertEqual(self.journal.get(second["key"]), second)
        reopened = Journal(self.journal.path, read_only=True)
        try:
            self.assertEqual(reopened.db.execute("SELECT * FROM actions ORDER BY key").fetchall(), before)
            self.assertEqual(reopened.db.execute("SELECT COUNT(*) FROM actions_archive").fetchone()[0], 0)
        finally:
            reopened.close()

    def test_archive_capacity_is_fail_closed_and_batch_is_bounded(self):
        self.make_row(1)
        self.make_row(2)
        with patch("safety.ARCHIVE_ROW_LIMIT", 1):
            with self.assertRaisesRegex(SafetyError, "journal_archive_capacity_reached"):
                self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 2)
        result = self.journal.archive_resolved(now=self.later, batch_limit=1, preview=False)
        self.assertEqual((result["active_rows"], result["archive_rows"]), (1, 1))
        with patch("safety.ARCHIVE_ROW_LIMIT", 1), self.assertRaises(SafetyError):
            self.journal.archive_resolved(now=self.later, preview=False)

    def test_archiving_frees_active_capacity_without_losing_archive(self):
        _, _, row = self.make_row()
        self.journal.limit = 1
        with self.assertRaisesRegex(SafetyError, "journal_capacity_reached"):
            self.make_row(2)
        self.journal.archive_resolved(now=self.later, preview=False)
        self.make_row(2)
        self.assertEqual(self.journal.get(row["key"]), row)

    def test_readonly_preview_does_not_migrate_legacy_database(self):
        self.make_row()
        self.journal.db.execute("DROP TABLE actions_archive")
        self.journal.db.commit()
        before = self.journal.path.read_bytes()
        ro = Journal(self.journal.path, read_only=True)
        try:
            self.assertEqual(ro.archive_resolved(now=self.later)["eligible"], 1)
            with self.assertRaises(SafetyError):
                ro.archive_resolved(now=self.later, preview=False)
        finally:
            ro.close()
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_related_lookup_limit_fails_closed_instead_of_truncating(self):
        report, context, _ = self.make_row()
        other = dict(context, approval_digest="f" * 64)
        row = self.journal.prepare(report, mode="public_attempt", context=other)
        self.journal.transition(row["key"], "prepared", "dispatch_recorded")
        self.journal.transition(row["key"], "dispatch_recorded", "cleanup_resolved",
                               {k: True for k in ("torrent_absent", "failed", "blocklisted")})
        self.journal.archive_resolved(now=self.later, preview=False)
        with patch("safety.RELATED_RECORD_LIMIT", 1), self.assertRaisesRegex(SafetyError, "journal_history_limit_reached"):
            self.journal.related("HD", report["hash"])

    def test_cli_apply_is_disabled_and_does_not_touch_database(self):
        self.make_row()
        before = self.journal.path.read_bytes()
        output = io.StringIO()
        with patch("sys.argv", ["retention.py", "--journal", str(self.journal.path), "--apply"]), contextlib.redirect_stdout(output):
            self.assertEqual(retention.main(), 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "journal_archive_not_authorized")
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_cli_preview_is_readonly(self):
        self.make_row()
        before = self.journal.path.read_bytes()
        output = io.StringIO()
        with patch("sys.argv", ["retention.py", "--journal", str(self.journal.path)]), contextlib.redirect_stdout(output):
            self.assertEqual(retention.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "preview")
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_actual_cli_preview_preserves_legacy_database_bytes_and_schema(self):
        self.make_row()
        self.journal.db.execute("DROP TABLE actions_archive")
        self.journal.db.commit()
        before_bytes = self.journal.path.read_bytes()
        before_schema = self.journal.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
        output = io.StringIO()
        # Exercise the actual CLI entry point, not Journal(..., read_only=True)
        # directly; this must catch a writable connection chosen by the CLI.
        with patch("sys.argv", ["retention.py", "--journal", str(self.journal.path)]), contextlib.redirect_stdout(output):
            self.assertEqual(retention.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "preview")
        self.assertEqual(self.journal.path.read_bytes(), before_bytes)
        self.assertEqual(self.journal.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), before_schema)
        # Also exercise argument parsing and __main__ in a real process.
        process = subprocess.run([sys.executable, retention.__file__, "--journal", str(self.journal.path)],
                                 capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(process.stdout)["mode"], "preview")
        self.assertEqual(self.journal.path.read_bytes(), before_bytes)
        self.assertEqual(self.journal.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), before_schema)

    def test_cli_apply_respects_worker_lock(self):
        import fcntl
        self.make_row()
        before = self.journal.path.read_bytes()
        output = io.StringIO()
        with open(self.journal.path.parent / "guard.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("retention.ARCHIVE_RELEASE_ENABLED", True), patch("sys.argv", [
                    "retention.py", "--journal", str(self.journal.path), "--apply"]), contextlib.redirect_stdout(output):
                self.assertEqual(retention.main(), 1)
        self.assertEqual(json.loads(output.getvalue())["reason"], "another_run_is_active")
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_archive_key_conflict_does_not_overwrite_or_delete_active_record(self):
        _, _, row = self.make_row()
        # An inconsistent duplicate archive key must hold, never replace evidence.
        self.journal.db.execute("INSERT INTO actions_archive VALUES(?,?,?,?,?,?)",
            (row["key"], "HD", "a" * 40, "public_attempt", "{}", self.later))
        self.journal.db.commit()
        with self.assertRaisesRegex(SafetyError, "journal_duplicate_archive_key"):
            self.journal.archive_resolved(now=self.later, preview=False)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 1)
        self.assertEqual(self.journal.db.execute("SELECT payload FROM actions_archive").fetchone()[0], "{}")

    def test_invalid_archive_parameters_fail_closed(self):
        for changes in ({"now": True}, {"now": float("nan")}, {"now": -1},
                        {"batch_limit": 0}, {"batch_limit": 101}, {"batch_limit": True}, {"preview": 1}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                self.journal.archive_resolved(**changes)


if __name__ == "__main__":
    unittest.main()
