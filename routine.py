"""An unattended public worker with explicit live authorization."""

import argparse
import copy
import fcntl
import json
import logging
from pathlib import Path
import time

from authorization import ContainerAuthorization, RoutineAuthorization, read_container_journal_id
from guard import (Api, GuardError, PrivateRotatingFileHandler, hard_deadline, load_config,
                   load_batch_state, save_batch_state)
import production
import public
from safety import ACTION_JOURNAL_FILE, DISPATCH_STOP_REASONS, Journal, SafetyError, open_lock_file


HELD_REASONS = DISPATCH_STOP_REASONS | {
    "journal_capacity_reached", "previous_attempt_unresolved", "another_run_is_active",
    "approval_already_consumed", "new_attempt_not_confirmed", "attempt_identity_required",
    "routine_authorization_invalid", "routine_code_not_authorized",
    "routine_authorization_revoked_or_changed",
    "not_a_public_failure_candidate", "candidate_no_longer_eligible", "retry_settings_not_ready",
    "metadata_retry_not_released",
    "journal_history_limit_reached", "journal_archive_capacity_reached", "invalid_archive_evidence",
}


def save_dispatch_cursor(state_path, cursor):
    """Merge into current state under the same lock as assessment and recovery."""
    with open_lock_file(state_path.parent / "guard.lock") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafetyError("another_run_is_active") from None
        state = load_batch_state(state_path)
        state["dispatch_after"] = cursor
        save_batch_state(state_path, state)


def cycle(config, qb, apis, journal, authority, batch_state, proposal=None, on_action=None, *,
          summary=None, on_attempt=None):
    authority.validate(config)
    if proposal is None:
        proposal = public.cycle(config, qb, apis, journal, batch_state, reserve_dispatch=True)
    runtime = copy.deepcopy(config)
    runtime["dry_run"] = False
    if summary is None:
        summary = {}
    actions = []
    summary.update(mode="routine", live_authorized=True, status="interrupted", retry_after_seconds=600,
                   grant_expires_at=authority.expires_at, grant_authorization_mode=authority.mode,
                   assessment=proposal["assessment"], recovery=proposal["recovery"], actions=actions)
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
        try:
            row = production.execute_routine_attempt(runtime, qb, apis, journal, report, authority)
            actions.append({"instance": report["instance"], "hash": report["hash"],
                "key": row["key"], "stage": row["stage"], "confirmed": row["confirmed"],
                "current_observation": row["current_observation"], "stop_reason": row["stop_reason"],
                "routine_grant_digest": authority.identifier,
                "metadata_retry": row["context"].get("metadata_retry"),
                **({"file_cleanup": True} if row["context"].get("file_cleanup") is True else {}),
                "search_command_id": row["search_command_id"]})
        except (GuardError, SafetyError) as error:
            if str(error) == "run_time_limit_reached":
                raise
            # Only exact known codes may reach logs; exception text can contain secrets.
            reason = str(error) if str(error) in HELD_REASONS else "maintenance_or_safety_check_unavailable"
            actions.append({"instance": report["instance"], "hash": report["hash"], "stage": "held",
                "stop_reason": reason, "routine_grant_digest": authority.identifier})
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
    parser.add_argument("--container-journal", action="store_true", help=argparse.SUPPRESS)
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
        journal_id = (authority.journal_id if args.container_mode else
                      read_container_journal_id(args.config.parent, required=args.container_journal))
        journal = Journal(args.config.parent / ACTION_JOURNAL_FILE, allow_public_attempt=True,
                          expected_installation_id=journal_id)
        try:
            # Assessment/recovery and each sender use the same lock. Release it
            # before coordinator calls; they independently lock and recheck. A
            # second process can at most cause a hold, never duplicate sending.
            with open_lock_file(args.config.parent / "guard.lock") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                state = load_batch_state(state_path)
                try:
                    with hard_deadline(deadline):
                        proposal = public.cycle(config, qb, apis, journal, state, reserve_dispatch=True)
                finally:
                    save_batch_state(state_path, state)
            production.ROUTINE_RELEASE_ENABLED = True
            # Reuse exactly the assessed snapshot, not another full pass.
            def log_action(action):
                text = json.dumps({"event": "routine_action", **action})
                handler.emit(logging.LogRecord("routine", logging.INFO, "", 0, text, (), None))
            with hard_deadline(deadline):
                cycle(config, qb, apis, journal, authority, state, proposal, log_action, summary=result,
                      on_attempt=lambda cursor: save_dispatch_cursor(state_path, cursor))
        finally:
            journal.close()
    except (SafetyError, GuardError) as error:
        allowed = {"routine_authorization_invalid", "routine_authorization_unavailable",
            "routine_code_not_authorized", "routine_authorization_expired_or_scope_changed",
            "routine_authorization_revoked_or_changed",
            "explicit_live_mode_required", "live_execution_disabled",
            "container_live_scope_confirmation_required",
            "routine_log_requires_private_config_directory", "run_time_limit_reached",
            "log_destination_reserved", "log_destination_not_private_file", "log_symlink_refused",
            "another_run_is_active", "invalid_worker_lock", "container_journal_missing",
            "container_journal_identity_mismatch", "container_journal_marker_missing"}
        result["reason"] = str(error) if str(error) in allowed else "maintenance_or_safety_check_unavailable"
    except Exception:
        # Operational exceptions can contain secrets. Never include raw text.
        result["reason"] = "authorization_maintenance_or_safety_check_unavailable"
    finally:
        production.ROUTINE_RELEASE_ENABLED = False
    line = json.dumps(result)
    if handler is not None:
        handler.emit(logging.LogRecord("routine", logging.INFO, "", 0, line, (), None))
        handler.close()
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
