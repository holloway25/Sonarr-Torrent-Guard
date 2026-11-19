import copy
import datetime
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

from authorization import (CONTAINER_SCOPE_FILE, ContainerAuthorization, RoutineAuthorization,
                           code_digest, container_scope_record, scope_digest, RULE, MAX_TRIAL_SECONDS)
from guard import load_batch_state, run
import production
import routine
from safety import SafetyError
from tools.tests import test_production as fixtures


class RoutineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProductionTests()
        self.f.setUp()
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
        return production.execute_native_file_removal(f.config, f.qb, f.apis, f.report, self.authority, f.lock_path)

    def write_container_scope(self):
        directory = Path(self.f.folder.name)
        path = directory / CONTAINER_SCOPE_FILE
        path.write_text(json.dumps(container_scope_record(self.f.config)))
        path.chmod(0o600)
        return self.write_connections()

    def write_connections(self):
        config = copy.deepcopy(self.f.config)
        config["dry_run"] = True
        config["qbittorrent"].update(username="REPLACE_ME", password="REPLACE_ME")
        config_path = Path(self.f.folder.name) / "connections.json"
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        return config_path

    def test_container_live_switch_authorizes_the_existing_dispatch_path(self):
        config_path = self.write_container_scope()
        with patch.dict(os.environ, {"STGUARD_MODE": "live"}):
            self.authority = ContainerAuthorization(self.f.config, config_path)
            with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                    "production._send_queue_delete", side_effect=lambda *args, **kwargs: self.f.results()) as send:
                row = self.execute()
        send.assert_called_once()
        self.assertIsNone(row)

    def test_container_permission_requires_live_mode_and_valid_scope(self):
        config_path = self.write_container_scope()
        for env in ({}, {"STGUARD_MODE": "dry-run"}):
            with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(
                    SafetyError, "live_execution_disabled"):
                ContainerAuthorization(self.f.config, config_path)
        with patch.dict(os.environ, {"STGUARD_MODE": "live"}):
            authority = ContainerAuthorization(self.f.config, config_path)
            with self.assertRaisesRegex(SafetyError, "routine_candidate_not_authorized"):
                authority.validate(self.f.config, dict(self.f.report, indexer="Private Source"))
            with self.assertRaisesRegex(SafetyError, "container_live_scope_confirmation_required"):
                authority.validate(dict(self.f.config, minimum_age_seconds=180))
            changed = copy.deepcopy(self.f.config)
            changed["sonarr"]["HD"]["indexers"]["private"].clear()
            with self.assertRaisesRegex(SafetyError, "container_live_scope_confirmation_required"):
                ContainerAuthorization(changed, config_path)

    def test_routine_cli_does_not_append_waiting_message_to_config_or_grant(self):
        import contextlib
        import io

        config = self.write_connections()
        grant = config.parent / "custom-grant.json"
        grant.write_text(json.dumps(self.grant))
        before = {path: path.read_bytes() for path in (config, grant)}
        for log_path in (config, grant, config.parent / "batch-state.json"):
            args = ["routine.py", "--live", "--config", str(config),
                    "--authorization", str(grant), "--log-file", str(log_path)]
            with self.subTest(path=log_path.name), contextlib.redirect_stdout(io.StringIO()) as output, patch(
                    "sys.argv", args), patch("routine.RoutineAuthorization.load") as authorize, patch("routine.Api") as api:
                self.assertEqual(routine.main(), 0)
                self.assertEqual(json.loads(output.getvalue())["reason"], "log_destination_reserved")
                authorize.assert_not_called()
                api.assert_not_called()
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            if log_path not in before:
                self.assertFalse(log_path.exists())

    def test_live_dispatch_rotates_across_cli_restarts_after_a_timeout(self):
        import contextlib
        import io

        f = self.f
        directory = Path(f.folder.name)
        state_path = directory / "batch-state.json"
        args = ["routine.py", "--live", "--config", str(directory / "connections.json"),
                "--authorization", str(directory / "routine-authorization.json"),
                "--log-file", str(directory / "routine.log")]
        verified = dict(f.report, safeguards={"status": "fresh_attempt_verified"})
        other = dict(verified, hash="b" * 40)
        tried = []

        def attempt(config, qb, apis, report, authority, lock_path):
            tried.append(report["hash"])
            self.assertEqual(load_batch_state(state_path)["dispatch_after"], ["HD", report["hash"]])
            if report["hash"] == f.hash:
                raise production.GuardError("run_time_limit_reached")

        def assess(config, qb, apis, state, **kwargs):
            state["after"] = ["HD", other["hash"]]
            return {"assessment": [verified, other]}

        for number in range(3):
            tried.clear()
            with contextlib.redirect_stdout(io.StringIO()) as output, patch("sys.argv", args), patch(
                    "routine.load_config", return_value=f.config), patch(
                    "routine.RoutineAuthorization.load", return_value=self.authority), patch(
                    "routine.Api", side_effect=[f.qb, f.s]), patch(
                    "routine.public.cycle", side_effect=assess), patch(
                    "production.execute_native_file_removal", side_effect=attempt):
                self.assertEqual(routine.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "interrupted")
            self.assertEqual(tried, [f.hash] if number == 0 else [other["hash"], f.hash])
            self.assertEqual([row["hash"] for row in result["actions"]], [] if number == 0 else [other["hash"]])
            self.assertEqual(load_batch_state(state_path), {
                "after": ["HD", other["hash"]], "dispatch_after": ["HD", f.hash]})

    def test_assessment_cursor_is_accessed_only_under_the_lock(self):
        import contextlib
        import io

        directory = Path(self.f.folder.name)
        args = ["routine.py", "--live", "--config", str(directory / "connections.json"),
                "--authorization", str(directory / "routine-authorization.json"),
                "--log-file", str(directory / "routine.log")]
        state = {}
        for busy in (True, False):
            with self.subTest(busy=busy), contextlib.ExitStack() as stack:
                stack.enter_context(patch("sys.argv", args))
                stack.enter_context(patch("routine.load_config", return_value=self.f.config))
                stack.enter_context(patch("routine.RoutineAuthorization.load", return_value=self.authority))
                stack.enter_context(patch("routine.Api"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                calls = Mock()
                calls.load.return_value = state
                calls.assess.side_effect = RuntimeError("assessment interrupted")
                stack.enter_context(patch("routine.fcntl.flock", calls.lock))
                stack.enter_context(patch("routine.load_batch_state", calls.load))
                stack.enter_context(patch("routine.public.cycle", calls.assess))
                stack.enter_context(patch("routine.save_batch_state", calls.save))
                if busy:
                    calls.lock.side_effect = BlockingIOError()
                routine.main()
                self.assertEqual([call[0] for call in calls.mock_calls],
                                 ["lock"] if busy else ["lock", "load", "assess", "save"])
                if not busy:
                    calls.save.assert_called_once_with(directory / "batch-state.json", state)

    def test_busy_assessment_reserves_time_for_the_real_coordinator(self):
        f = self.f
        second = "b" * 40
        qb_info = f.qb.routes["/api/v2/torrents/info"]
        qb_info.append(dict(qb_info[0], hash=second))
        queue = f.s.routes["/api/v3/queue"]
        queue["records"].append(dict(queue["records"][0], id=8, downloadId=second))
        queue["totalRecords"] = 2
        history = f.s.routes["/api/v3/history"]
        history["records"].append(dict(f.grab, id=6, downloadId=second))
        history["totalRecords"] = 2
        now = [100.0]
        state = {}
        f.qb.deadline = f.s.deadline = 280.0
        call = f.qb.call
        deadlines = []

        def busy_downloader(route, params=None):
            if route.endswith("/files"):
                deadlines.append(f.qb.deadline)
                if params["hash"] == second:
                    now[0] = f.qb.deadline
                    raise production.GuardError("run_time_limit_reached")
            if now[0] >= f.qb.deadline:
                raise production.GuardError("run_time_limit_reached")
            return call(route, params)

        def send_removal(*args, **kwargs):
            self.assertEqual(f.s.deadline, 280.0)
            f.results()

        with patch("public.time.monotonic", side_effect=lambda: now[0]), patch(
                "public.require_connectivity", return_value={}), patch.object(
                f.qb, "call", side_effect=busy_downloader), patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=send_removal) as send:
            result = routine.cycle(f.config, f.qb, f.apis, self.authority, state, lock_path=f.lock_path)
        send.assert_called_once_with(f.s, 7, blocklist=True)
        self.assertEqual(deadlines[:3], [190.0, 190.0, 235.0])
        self.assertEqual(deadlines[3:], [280.0, 280.0])
        self.assertEqual(state["after"], ["HD", f.hash])
        self.assertEqual(result["assessment"][-1]["reason"], "run_time_limit_reached")
        self.assertEqual(result["actions"][0]["stage"], "sonarr_remove_blocklist_accepted")

    def test_interrupted_cli_summary_retains_completed_live_actions(self):
        import contextlib
        import io

        f = self.f
        directory = Path(f.folder.name)
        log_path = directory / "routine.log"
        args = ["routine.py", "--live", "--config", str(directory / "connections.json"),
                "--authorization", str(directory / "routine-authorization.json"), "--log-file", str(log_path)]
        first = dict(f.report, safeguards={"status": "fresh_attempt_verified"})
        second = dict(first, hash="b" * 40)
        proposal = {"assessment": [first, second]}
        execute = production.execute_native_file_removal

        def interrupt_after_first(config, qb, apis, report, authority, lock_path):
            if report["hash"] == second["hash"]:
                raise production.GuardError("run_time_limit_reached")
            return execute(config, qb, apis, report, authority, lock_path)

        with contextlib.ExitStack() as stack:
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch("sys.argv", args))
            stack.enter_context(patch("routine.load_config", return_value=f.config))
            stack.enter_context(patch("routine.RoutineAuthorization.load", return_value=self.authority))
            stack.enter_context(patch("routine.Api", side_effect=[f.qb, f.s]))
            stack.enter_context(patch("routine.public.cycle", return_value=proposal))
            stack.enter_context(patch("production.execute_native_file_removal", side_effect=interrupt_after_first))
            send = stack.enter_context(patch("production._send_queue_delete", side_effect=lambda *args, **kw: f.results()))
            self.assertEqual(routine.main(), 0)

        send.assert_called_once_with(f.s, 7, blocklist=True)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["status"], "interrupted")
        self.assertIs(summary["live_authorized"], True)
        self.assertEqual(summary["reason"], "run_time_limit_reached")
        self.assertEqual([(action["hash"], action["stage"]) for action in summary["actions"]],
                         [(f.hash, "sonarr_remove_blocklist_accepted")])
        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        self.assertEqual(lines[0].pop("event"), "routine_action")
        self.assertIn("time", lines[0])
        self.assertEqual({key: value for key, value in lines[0].items() if key != "time"}, summary["actions"][0])
        self.assertEqual(lines[1]["status"], "interrupted")
        self.assertEqual(len(lines), 2)

    def test_routine_requires_explicit_live_gate(self):
        with patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "live_execution_disabled"):
                self.execute()
            send.assert_not_called()

    def test_valid_routine_permission_uses_normal_checks(self):
        f = self.f
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a, **kw: f.results()) as send:
            row = self.execute()
        self.assertIsNone(row)
        send.assert_called_once()

    def test_disabled_expired_future_or_overlong_permission_is_refused(self):
        now = time.time()
        for changes in ({"enabled": False}, {"expires_at": now - 1}, {"issued_at": now + 20},
                        {"expires_at": self.grant["issued_at"] + MAX_TRIAL_SECONDS + 1},
                        {"rule": "other-workflow"}, {"grant_id": "bad"}):
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

    def test_seven_day_trial_accepts_boundary_and_refuses_expiry_or_longer_grant(self):
        self.assertEqual(MAX_TRIAL_SECONDS, 7 * 24 * 60 * 60)
        grant = dict(self.grant, expires_at=self.grant["issued_at"] + MAX_TRIAL_SECONDS)
        authority = RoutineAuthorization(grant, self.f.config)
        with patch("time.time", return_value=grant["expires_at"] - 0.001):
            authority.validate(self.f.config)
        with patch("time.time", return_value=grant["expires_at"]), self.assertRaisesRegex(
                SafetyError, "routine_authorization_expired_or_scope_changed"):
            authority.validate(self.f.config)
        with self.assertRaises(SafetyError):
            RoutineAuthorization(dict(grant, expires_at=grant["expires_at"] + 1), self.f.config)

    def test_private_unknown_and_nonfailure_reports_cannot_be_authorized(self):
        for changes in ({"indexer": "Private Source"}, {"indexer": "Unknown Source"},
                        {"decision": "keep"}, {"public_source_confirmed": False}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                self.authority.validate(self.f.config, dict(self.f.report, **changes))

    def ongoing_grant(self):
        return dict(self.grant, authorization_mode="ongoing", expires_at=None)

    def test_ongoing_authority_is_explicit_and_does_not_extend_legacy_trial(self):
        authority = RoutineAuthorization(self.ongoing_grant(), self.f.config)
        with patch("time.time", return_value=self.grant["issued_at"] + MAX_TRIAL_SECONDS * 10):
            authority.validate(self.f.config, self.f.report)
        for changes in ({"authorization_mode": "trial"}, {"authorization_mode": True},
                        {"authorization_mode": None}, {"expires_at": time.time() + 3600}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                RoutineAuthorization(dict(self.ongoing_grant(), **changes), self.f.config)
        with self.assertRaises(SafetyError):
            RoutineAuthorization(dict(self.grant, expires_at=None), self.f.config)

    def test_ongoing_grant_still_checks_time_scope_and_enabled(self):
        for changes in ({"issued_at": time.time() + 60}, {"issued_at": True}, {"issued_at": float("nan")},
                        {"enabled": False}, {"scope_digest": "e" * 64}, {"code_digest": "malformed"}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                RoutineAuthorization(dict(self.ongoing_grant(), **changes), self.f.config)

    def test_standalone_code_updates_require_explicit_ongoing_opt_in(self):
        old_code = "f" * 64
        ongoing = dict(self.ongoing_grant(), code_digest=old_code)
        path = self.write_grant(ongoing)
        with self.assertRaisesRegex(SafetyError, "routine_code_not_authorized"):
            self.load_grant(path)
        path = self.write_grant(dict(ongoing, allow_code_updates=True))
        self.load_grant(path).validate(self.f.config, self.f.report)
        for grant in (dict(ongoing, allow_code_updates=1),
                      dict(ongoing, allow_code_updates=False),
                      dict(self.grant, allow_code_updates=True)):
            with self.subTest(grant=grant), self.assertRaisesRegex(SafetyError, "routine_authorization_invalid"):
                RoutineAuthorization(grant, self.f.config)

    def write_grant(self, value):
        path = Path(self.f.folder.name) / "routine-authorization.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def load_grant(self, path):
        return RoutineAuthorization.load(path, self.f.config, config_path=self.write_connections())

    def test_grant_file_rejects_duplicate_enable_and_expiry(self):
        grant = self.ongoing_grant()
        path = self.write_grant(grant)
        original = path.read_text()
        self.load_grant(path)
        for before, after in (('"enabled": true', '"enabled": false, "enabled": true'),
                              ('"expires_at": null', '"expires_at": 1, "expires_at": null')):
            with self.subTest(field=before):
                path.write_text(original.replace(before, after))
                with self.assertRaisesRegex(SafetyError, "routine_authorization_unavailable"):
                    self.load_grant(path)

    def test_loaded_grant_rejects_removal_and_replacement(self):
        for removed in (True, False):
            with self.subTest(removed=removed):
                path = self.write_grant(self.ongoing_grant())
                authority = self.load_grant(path)
                if removed:
                    path.unlink()
                else:
                    self.write_grant(dict(self.ongoing_grant(), grant_id="d" * 64))
                with self.assertRaisesRegex(SafetyError, "routine_authorization_revoked_or_changed"):
                    authority.validate(self.f.config, self.f.report)

    def test_final_dispatch_blocks_grant_disabled_after_history_check(self):
        grant = self.ongoing_grant()
        path = self.write_grant(grant)
        self.authority = self.load_grant(path)
        refresh = production.check_visible_native_grabs

        def revoke_after_refresh(*args, **kwargs):
            row = refresh(*args, **kwargs)
            self.write_grant(dict(grant, enabled=False))
            return row

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.check_visible_native_grabs", side_effect=revoke_after_refresh), patch(
                "production._send_queue_delete") as sender:
            with self.assertRaisesRegex(SafetyError, "^routine_authorization_revoked_or_changed$"):
                self.execute()
            sender.assert_not_called()

    def test_standalone_grant_rechecks_disk_scope_at_final_dispatch(self):
        path = self.write_grant(self.ongoing_grant())
        config_path = self.write_connections()
        self.authority = RoutineAuthorization.load(path, self.f.config, config_path=config_path)
        refresh = production.check_visible_native_grabs

        def protect_after_refresh(*args, **kwargs):
            row = refresh(*args, **kwargs)
            changed = json.loads(config_path.read_text())
            changed["sonarr"]["HD"]["indexers"] = {
                "mode": "private_exclusions", "private": ["Public Source"]}
            config_path.write_text(json.dumps(changed))
            return row

        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.check_visible_native_grabs", side_effect=protect_after_refresh), patch(
                "production._send_queue_delete") as sender:
            with self.assertRaisesRegex(SafetyError, "^routine_authorization_expired_or_scope_changed$"):
                self.execute()
            sender.assert_not_called()

    def test_ongoing_authority_cannot_be_changed_in_memory(self):
        authority = RoutineAuthorization(self.ongoing_grant(), self.f.config)
        # Still structurally valid and enabled: only the integrity check rejects it.
        authority.value["grant_id"] = "a" * 64
        with self.assertRaises(SafetyError):
            authority.validate(self.f.config)

    def test_ongoing_authority_can_complete_same_existing_safety_workflow(self):
        self.authority = RoutineAuthorization(self.ongoing_grant(), self.f.config)
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production._send_queue_delete", side_effect=lambda *a, **kw: self.f.results()) as send:
            row = self.execute()
        self.assertIsNone(row)
        send.assert_called_once()

    def test_permission_withdrawn_during_final_checks_blocks_sender(self):
        calls = []
        def connection(*args):
            calls.append(1)
            self.authority.value["enabled"] = False
        with patch("production.ROUTINE_RELEASE_ENABLED", True), patch(
                "production.require_connectivity", side_effect=connection), patch("production._send_queue_delete") as send:
            with self.assertRaisesRegex(SafetyError, "^routine_authorization_expired_or_scope_changed$"):
                self.execute()
        send.assert_not_called()

    def test_auth_file_requires_private_permissions_and_valid_content(self):
        path = self.write_grant(self.grant)
        self.assertEqual(self.load_grant(path).identifier, self.authority.identifier)
        path.chmod(0o644)
        with self.assertRaises(SafetyError):
            self.load_grant(path)

    def test_trial_cannot_authorize_lower_than_agreed_two_minute_age(self):
        self.f.config["minimum_age_seconds"] = 1
        grant = dict(self.grant, scope_digest=scope_digest(self.f.config))
        with self.assertRaises(SafetyError):
            RoutineAuthorization(grant, self.f.config)

    def test_trial_timer_has_explicit_live_worker_and_ten_minute_interval(self):
        folder = Path(__file__).resolve().parents[2] / "deploy"
        self.assertIn("OnUnitInactiveSec=10min", (folder / "sonarr-torrent-guard-live.timer").read_text())
        self.assertIn("routine.py --live", (folder / "sonarr-torrent-guard-live.service").read_text())

    def test_held_errors_only_log_exact_allowlisted_reasons(self):
        f = self.f
        proposal = {"assessment": [dict(f.report, safeguards={"status": "fresh_attempt_verified"})]}
        for error in (SafetyError("target_reappeared"),
                      SafetyError("target_reappeared secret-payload"),
                      routine.GuardError("private-response secret-payload")):
            with self.subTest(error=type(error).__name__), patch(
                    "production.execute_native_file_removal", side_effect=error):
                result = routine.cycle(f.config, f.qb, f.apis, self.authority, {}, proposal, lock_path=f.lock_path)
            action = result["actions"][0]
            expected = ("target_reappeared" if str(error) == "target_reappeared"
                        else "maintenance_or_safety_check_unavailable")
            self.assertEqual(action["stop_reason"], expected)
            self.assertEqual(action["routine_grant_digest"], self.authority.identifier)
            self.assertNotIn("secret-payload", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
