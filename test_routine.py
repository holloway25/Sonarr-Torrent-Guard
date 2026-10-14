import copy
import datetime
import json
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

from authorization import RoutineAuthorization, code_digest, scope_digest, RULE
from guard import run
import production
import routine
from safety import SafetyError
import test_production as fixtures


class RoutineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
        self.f.journal.allow_public_attempt = True
        self.f.qb.login = Mock()
        now = time.time()
        self.grant = {"enabled": True, "rule": RULE, "grant_id": "c" * 64,
            "issued_at": now - 1, "expires_at": now + 3600,
            "scope_digest": scope_digest(self.f.config), "code_digest": code_digest()}
        self.authority = RoutineAuthorization(self.grant, self.f.config)

    def tearDown(self):
        self.f.tearDown()
        self.f.doCleanups()

    def execute(self):
        f = self.f
        return production.execute_routine_attempt(f.config, f.qb, f.apis, f.journal, f.report, self.authority)

    def test_routine_gate_is_not_enabled_by_test_permission(self):
        with patch("production.SINGLE_TEST_RELEASE_ENABLED", True), patch(
                "production.PUBLIC_ATTEMPT_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                self.execute()
            send.assert_not_called()

    def test_valid_routine_permission_uses_normal_checks_and_records_its_grant(self):
        f = self.f
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: f.results()) as send:
            row = self.execute()
        self.assertEqual(row["stage"], "cleanup_resolved")
        self.assertEqual(row["context"]["routine_grant_digest"], self.authority.identifier)
        send.assert_called_once()

    def test_disabled_expired_future_or_overlong_permission_is_refused(self):
        now = time.time()
        for changes in ({"enabled": False}, {"expires_at": now - 1}, {"issued_at": now + 20},
                        {"expires_at": now + 172801}, {"rule": "other-workflow"}, {"grant_id": "bad"}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                RoutineAuthorization(dict(self.grant, **changes), self.f.config)

    def test_source_scope_and_immutable_permission_changes_are_refused(self):
        with self.assertRaisesRegex(SafetyError, "routine_code_not_authorized"):
            RoutineAuthorization(dict(self.grant, code_digest="d" * 64), self.f.config)
        self.f.config["sonarr"]["HD"]["url"] = "https://changed.example.invalid"
        with self.assertRaises(SafetyError):
            self.authority.validate(self.f.config)
        self.f.config["sonarr"]["HD"]["url"] = "https://sonarr.example.invalid"
        self.authority.value["expires_at"] += 1
        with self.assertRaises(SafetyError):
            self.authority.validate(self.f.config)

    def test_private_unknown_and_nonfailure_reports_cannot_be_authorized(self):
        for changes in ({"indexer": "Private Source"}, {"indexer": "Unknown Source"},
                        {"decision": "keep"}, {"public_source_confirmed": False}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                self.authority.validate(self.f.config, dict(self.f.report, **changes))

    def test_permission_withdrawn_during_final_checks_blocks_sender(self):
        calls = []
        def connection(*args):
            calls.append(1)
            if len(calls) == 3:
                self.authority.value["enabled"] = False
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=connection), patch("production._send_queue_delete") as send:
            row = self.execute()
        self.assertEqual(row["stage"], "dispatch_blocked")
        self.assertEqual(row["stop_reason"], "routine_authorization_expired_or_scope_changed")
        send.assert_not_called()

    def test_auth_file_requires_private_permissions_and_valid_content(self):
        path = Path(self.f.folder.name) / "routine-authorization.json"
        # Test-only fixture file, not an installed permission grant.
        with patch.object(Path, "read_text", return_value=json.dumps(self.grant)), patch.object(
                Path, "stat") as stat:
            stat.return_value.st_mode = 0o600
            stat.return_value.st_size = 500
            with patch.object(Path, "is_symlink", return_value=False):
                self.assertEqual(RoutineAuthorization.load(path, self.f.config).identifier, self.authority.identifier)
                stat.return_value.st_mode = 0o644
                with self.assertRaises(SafetyError):
                    RoutineAuthorization.load(path, self.f.config)

    def newer_attempt(self, legacy=False):
        f = self.f
        context = copy.deepcopy(f.context)
        if legacy:
            for name in production.ATTEMPT_CONTEXT_FIELDS:
                context.pop(name)
        row = f.journal.prepare(f.report, mode="single_test", context=context)
        row = f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        row = f.journal.transition(row["key"], "dispatch_recorded", "manual_review", {"torrent_absent": True})
        added = int(row["dispatched_at"]) + 3
        grab = dict(f.grab, id=50, date=datetime.datetime.fromtimestamp(added, datetime.timezone.utc).isoformat())
        f.s.routes["/api/v3/history"] = {"totalRecords": 2, "records": [f.grab, grab]}
        f.qb.routes["/api/v2/torrents/info"][0]["added_on"] = added
        report = run(f.config, f.qb, f.apis, now=added+200)[0]
        return row, report, added+200

    def test_confirmed_new_attempt_can_supersede_old_timestamp_hold_without_erasing_it(self):
        f = self.f
        old, f.report, now = self.newer_attempt()
        with patch("time.time", return_value=now), patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete") as send:
            row = self.execute()
        send.assert_called_once()
        self.assertNotEqual(row["key"], old["key"])
        self.assertEqual(f.journal.get(old["key"]), old)

    def test_legacy_hold_needs_new_addition_new_grab_and_same_binding(self):
        old, report, now = self.newer_attempt(legacy=True)
        production.check_prior_attempts(self.f.journal, report, config=self.f.config)
        for changes in ({"download_added_on": int(old["dispatched_at"])},
                        {"grab_ids": old["context"]["baseline_history_ids"]}, {"attempt_fingerprint": None},
                        {"grab_time_floor": old["dispatched_at"]}, {"grab_time_floor": None}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                production.check_prior_attempts(self.f.journal, dict(report, **changes), config=self.f.config)
        self.f.config["sonarr"]["HD"]["url"] = "https://changed.example.invalid"
        with self.assertRaises(SafetyError):
            production.check_prior_attempts(self.f.journal, report, config=self.f.config)

    def test_legacy_empty_baseline_still_requires_positive_new_grab_time(self):
        f = self.f
        f.context["baseline_history_ids"] = []
        old, report, now = self.newer_attempt(legacy=True)
        production.check_prior_attempts(f.journal, report, config=f.config)
        with self.assertRaisesRegex(SafetyError, "previous_attempt_unresolved"):
            production.check_prior_attempts(f.journal, dict(report, grab_time_floor=old["dispatched_at"]), config=f.config)

    def test_trial_cannot_authorize_lower_than_agreed_two_minute_age(self):
        self.f.config["minimum_age_seconds"] = 1
        grant = dict(self.grant, scope_digest=scope_digest(self.f.config))
        with self.assertRaises(SafetyError):
            RoutineAuthorization(grant, self.f.config)

    def test_same_attempt_uncertainty_still_blocks_unattended_sender(self):
        f = self.f
        row = f.journal.prepare(f.report, mode="public_attempt", context=f.context)
        row = f.journal.transition(row["key"], "prepared", "dispatch_recorded")
        f.journal.transition(row["key"], "dispatch_recorded", "uncertain")
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "previous_attempt_unresolved"):
                self.execute()
            send.assert_not_called()

    def test_worker_handles_only_assessed_unheld_attempts_and_never_chases_replacements(self):
        f = self.f
        report = dict(f.report, safeguards={"status": "fresh_attempt_verified"})
        held = dict(report, hash="b" * 40, safeguards={"status": "held"})
        proposal = {"assessment": [report, held], "recovery": []}
        events = []
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a: f.results()) as send:
            result = routine.cycle(f.config, f.qb, f.apis, f.journal, self.authority, {}, proposal, events.append)
        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(result["actions"][0]["stage"], "cleanup_resolved")
        self.assertEqual(events, result["actions"])
        send.assert_called_once()

    def test_trial_timer_has_explicit_live_worker_and_ten_minute_interval(self):
        folder = Path(__file__).parent / "deploy"
        self.assertIn("OnUnitInactiveSec=10min", (folder / "sonarr-torrent-guard-live.timer").read_text())
        self.assertIn("routine.py --live", (folder / "sonarr-torrent-guard-live.service").read_text())

    def test_full_journal_hold_records_reason_and_grant_without_sending(self):
        f = self.f
        f.journal.limit = 0
        proposal = {"assessment": [dict(f.report, safeguards={"status": "fresh_attempt_verified"})],
                    "recovery": []}
        events = []
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch("production._send_queue_delete") as send:
            result = routine.cycle(f.config, f.qb, f.apis, f.journal, self.authority, {}, proposal, events.append)
        action = result["actions"][0]
        self.assertEqual(action["stage"], "held")
        self.assertEqual(action["stop_reason"], "journal_capacity_reached")
        self.assertEqual(action["routine_grant_digest"], self.authority.identifier)
        self.assertEqual(events, result["actions"])
        send.assert_not_called()

    def test_held_errors_only_log_exact_allowlisted_reasons(self):
        f = self.f
        proposal = {"assessment": [dict(f.report, safeguards={"status": "fresh_attempt_verified"})],
                    "recovery": []}
        for error in (SafetyError("previous_attempt_unresolved"),
                      SafetyError("journal_capacity_reached secret-payload"),
                      routine.GuardError("private-response secret-payload")):
            with self.subTest(error=type(error).__name__), patch(
                    "production.execute_routine_attempt", side_effect=error):
                result = routine.cycle(f.config, f.qb, f.apis, f.journal, self.authority, {}, proposal)
            action = result["actions"][0]
            expected = ("previous_attempt_unresolved" if str(error) == "previous_attempt_unresolved"
                        else "maintenance_or_safety_check_unavailable")
            self.assertEqual(action["stop_reason"], expected)
            self.assertEqual(action["routine_grant_digest"], self.authority.identifier)
            self.assertNotIn("secret-payload", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
