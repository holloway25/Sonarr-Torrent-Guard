"""An unattended public worker with explicit live authorization."""

import argparse
import copy
import datetime
import fcntl
import json
import logging
from pathlib import Path
import time

from authorization import ContainerAuthorization, RoutineAuthorization
from guard import (Api, GuardError, PrivateRotatingFileHandler, hard_deadline, load_config,
                   load_batch_state, save_batch_state)
import production
import public
from safety import DISPATCH_STOP_REASONS, SafetyError, open_lock_file
from workflow import file_policy_removal


HELD_REASONS = DISPATCH_STOP_REASONS | {
    "another_run_is_active",
    "routine_authorization_invalid", "routine_code_not_authorized",
    "routine_authorization_revoked_or_changed",
    "not_a_public_failure_candidate", "candidate_no_longer_eligible", "retry_settings_not_ready",
    "metadata_retry_not_released",
    "delete_request_outcome_uncertain",
}


def loggable_hold_reason(reason):
    if isinstance(reason, str) and reason in HELD_REASONS:
        return reason
    return "maintenance_or_safety_check_unavailable"


def save_dispatch_cursor(state_path, cursor):
    """Merge into current state under the same lock as assessment."""
    with open_lock_file(state_path.parent / "guard.lock") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafetyError("another_run_is_active") from None
        state = load_batch_state(state_path)
        state["dispatch_after"] = cursor
        save_batch_state(state_path, state)


def cycle(config, qb, apis, authority, batch_state, proposal=None, on_action=None, *,
          lock_path, summary=None, on_attempt=None):
    authority.validate(config)
    if proposal is None:
        proposal = public.cycle(config, qb, apis, batch_state, reserve_dispatch=True)
    runtime = copy.deepcopy(config)
    runtime["dry_run"] = False
    if summary is None:
        summary = {}
    actions = []
    summary.update(mode="routine", live_authorized=True, status="interrupted", retry_after_seconds=600,
                   grant_expires_at=authority.expires_at, grant_authorization_mode=authority.mode,
                   assessment=proposal["assessment"], actions=actions)
    if on_action is not None:
        for report in proposal["assessment"]:
            safeguards = report.get("safeguards", {})
            if safeguards.get("status") == "held":
                on_action({"instance": report["instance"], "hash": report["hash"],
                           "reasons": report.get("reasons", []), "routine_grant_digest": authority.identifier,
                           "stage": "held", "phase": "verification",
                           "stop_reason": loggable_hold_reason(safeguards.get("reason"))})
    # Rotate the verified snapshot independently of the earlier phases.
    # Record the attempted key before starting work that can consume the cycle.
    candidates = sorted(((r["instance"], r["hash"]), r) for r in proposal["assessment"]
                        if r.get("safeguards", {}).get("status") == "fresh_attempt_verified")
    after = tuple(batch_state.get("dispatch_after", ()))
    deadlines = [getattr(api, "deadline", None) for api in (qb, *apis.values())]
    deadline = min((value for value in deadlines if value is not None), default=float("inf"))
    ordered = [entry for entry in candidates if entry[0] > after] + [
        entry for entry in candidates if entry[0] <= after]
    for key, report in ordered:
        if time.monotonic() >= deadline:
            raise GuardError("run_time_limit_reached")
        cursor = list(key)
        if on_attempt is not None:
            on_attempt(cursor)
        batch_state["dispatch_after"] = cursor
        action = {"instance": report["instance"], "hash": report["hash"],
                  "reasons": report.get("reasons", []), "routine_grant_digest": authority.identifier}
        try:
            if file_policy_removal(report):
                outcome = production.execute_native_file_removal(runtime, qb, apis, report, authority, lock_path)
                if outcome is None:
                    action.update(stage="sonarr_remove_blocklist_accepted", stop_reason=None)
                else:
                    action.update(outcome)
            else:
                action.update(production.execute_live_metadata_retry(runtime, qb, apis, report, authority, lock_path))
        except (GuardError, SafetyError) as error:
            if str(error) == "run_time_limit_reached":
                raise
            # Only exact known codes may reach logs; exception text can contain secrets.
            reason = loggable_hold_reason(str(error))
            stage = "uncertain" if reason == "delete_request_outcome_uncertain" else "held"
            action.update(stage=stage, stop_reason=reason)
        actions.append(action)
        if on_action is not None:
            on_action(actions[-1])
        if actions[-1]["stop_reason"] == "run_time_limit_reached":
            raise GuardError("run_time_limit_reached")
    summary["status"] = "completed"
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    permission = parser.add_mutually_exclusive_group(required=True)
    permission.add_argument("--authorization", type=Path)
    permission.add_argument("--container-mode", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Enable live routine actions")
    args = parser.parse_args()
    result = {"mode": "routine", "live_authorized": False, "status": "waiting", "actions": [], "retry_after_seconds": 600}
    handler = None
    try:
        if not args.live:
            raise SafetyError("explicit_live_mode_required")
        config = load_config(args.config)  # Ordinary CLI deliberately remains dry-run.
        if args.log_file.parent.resolve() != args.config.parent.resolve():
            raise SafetyError("routine_log_requires_private_config_directory")
        handler = PrivateRotatingFileHandler(args.log_file, config_path=args.config,
                                            authorization_path=args.authorization)
        authority = (ContainerAuthorization(config, args.config) if args.container_mode
                     else RoutineAuthorization.load(args.authorization, config, config_path=args.config))
        deadline = time.monotonic() + 180
        qb = Api(config["qbittorrent"], deadline=deadline)
        apis = {label: Api(item, deadline=deadline) for label, item in config["sonarr"].items()}
        state_path = args.config.parent / "batch-state.json"
        lock_path = args.config.parent / "guard.lock"
        with open_lock_file(lock_path) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = load_batch_state(state_path)
            try:
                with hard_deadline(deadline):
                    proposal = public.cycle(config, qb, apis, state, reserve_dispatch=True)
            finally:
                save_batch_state(state_path, state)
        production.ROUTINE_RELEASE_ENABLED = True

        def log_action(action):
            stamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            text = json.dumps({"event": "routine_action", "time": stamp, **action})
            handler.emit(logging.LogRecord("routine", logging.INFO, "", 0, text, (), None))

        with hard_deadline(deadline):
            cycle(config, qb, apis, authority, state, proposal, log_action, summary=result,
                  on_attempt=lambda cursor: save_dispatch_cursor(state_path, cursor), lock_path=lock_path)
    except BlockingIOError:
        result["reason"] = "another_run_is_active"
    except (SafetyError, GuardError) as error:
        allowed = {"routine_authorization_invalid", "routine_authorization_unavailable",
            "routine_code_not_authorized", "routine_authorization_expired_or_scope_changed",
            "routine_authorization_revoked_or_changed",
            "explicit_live_mode_required", "live_execution_disabled",
            "container_live_scope_confirmation_required",
            "routine_log_requires_private_config_directory", "run_time_limit_reached",
            "log_destination_reserved", "log_destination_not_private_file", "log_symlink_refused",
            "another_run_is_active", "invalid_worker_lock", "invalid_batch_state"}
        result["reason"] = str(error) if str(error) in allowed else "maintenance_or_safety_check_unavailable"
    except Exception:
        # Operational exceptions can contain secrets. Never include raw text.
        result["reason"] = "authorization_maintenance_or_safety_check_unavailable"
    finally:
        production.ROUTINE_RELEASE_ENABLED = False
    line = json.dumps(result)
    if handler is not None:
        if result["status"] != "completed":
            stamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            entry = {"event": "routine_status", "time": stamp, "status": result["status"],
                     "reason": result.get("reason")}
            handler.emit(logging.LogRecord("routine", logging.INFO, "", 0, json.dumps(entry), (), None))
        handler.close()
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
