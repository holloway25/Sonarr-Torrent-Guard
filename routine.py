"""A time-limited unattended public worker; explicit routine permission required."""

import argparse
import copy
import fcntl
import json
import logging
from pathlib import Path
import time

from authorization import RoutineAuthorization
from guard import (Api, GuardError, PrivateRotatingFileHandler, hard_deadline, load_config,
                   load_batch_state, save_batch_state)
import production
import public
from safety import DISPATCH_STOP_REASONS, Journal, SafetyError


HELD_REASONS = DISPATCH_STOP_REASONS | {
    "journal_capacity_reached", "previous_attempt_unresolved", "another_run_is_active",
    "approval_already_consumed", "new_attempt_not_confirmed", "attempt_identity_required",
    "routine_authorization_invalid", "routine_code_not_authorized",
    "not_a_public_failure_candidate", "candidate_no_longer_eligible", "retry_settings_not_ready",
}


def cycle(config, qb, apis, journal, authority, batch_state, proposal=None, on_action=None):
    authority.validate(config)
    if proposal is None:
        proposal = public.cycle(config, qb, apis, journal, batch_state)
    runtime = copy.deepcopy(config)
    runtime["dry_run"] = False
    actions = []
    # Snapshot this pass only. Never loop over replacements created by it.
    for report in proposal["assessment"]:
        if report.get("safeguards", {}).get("status") != "fresh_attempt_verified":
            continue
        try:
            row = production.execute_routine_attempt(runtime, qb, apis, journal, report, authority)
            actions.append({"instance": report["instance"], "hash": report["hash"],
                "key": row["key"], "stage": row["stage"], "confirmed": row["confirmed"],
                "current_observation": row["current_observation"], "stop_reason": row["stop_reason"],
                "routine_grant_digest": authority.identifier})
        except (GuardError, SafetyError) as error:
            # Only exact known codes may reach logs; exception text can contain secrets.
            reason = str(error) if str(error) in HELD_REASONS else "maintenance_or_safety_check_unavailable"
            actions.append({"instance": report["instance"], "hash": report["hash"], "stage": "held",
                "stop_reason": reason, "routine_grant_digest": authority.identifier})
        if on_action is not None:
            on_action(actions[-1])
    return {"mode": "routine", "live_authorized": True, "status": "completed", "retry_after_seconds": 600,
            "grant_expires_at": authority.value["expires_at"], "assessment": proposal["assessment"],
            "recovery": proposal["recovery"], "actions": actions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Use the explicit expiring routine grant")
    args = parser.parse_args()
    result = {"mode": "routine", "live_authorized": False, "status": "waiting", "actions": [], "retry_after_seconds": 600}
    handler = None
    try:
        if not args.live:
            raise SafetyError("explicit_live_mode_required")
        config = load_config(args.config)  # Ordinary CLI deliberately remains dry-run.
        if args.log_file.parent.resolve() != args.config.parent.resolve():
            raise SafetyError("routine_log_requires_private_config_directory")
        handler = PrivateRotatingFileHandler(args.log_file)
        authority = RoutineAuthorization.load(args.authorization, config)
        deadline = time.monotonic() + 180
        qb = Api(config["qbittorrent"], deadline=deadline)
        apis = {label: Api(item, deadline=deadline) for label, item in config["sonarr"].items()}
        state_path = args.config.parent / "batch-state.json"
        state = load_batch_state(state_path)
        journal = Journal(args.config.parent / "action-journal.sqlite3", allow_public_attempt=True)
        try:
            # Assessment/recovery and each sender use the same lock. Release it
            # before coordinator calls; they independently lock and recheck. A
            # second process can at most cause a hold, never duplicate sending.
            with open(args.config.parent / "guard.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with hard_deadline(deadline):
                    proposal = public.cycle(config, qb, apis, journal, state)
                save_batch_state(state_path, state)
            production.ROUTINE_RELEASE_ENABLED = True
            # Reuse exactly the assessed snapshot, not another full pass.
            def log_action(action):
                text = json.dumps({"event": "routine_action", **action})
                handler.emit(logging.LogRecord("routine", logging.INFO, "", 0, text, (), None))
            with hard_deadline(deadline):
                result = cycle(config, qb, apis, journal, authority, state, proposal, log_action)
        finally:
            journal.close()
            save_batch_state(state_path, state)
    except (SafetyError, GuardError) as error:
        allowed = {"routine_authorization_invalid", "routine_authorization_unavailable",
            "routine_code_not_authorized", "routine_authorization_expired_or_scope_changed",
            "explicit_live_mode_required", "routine_log_requires_private_config_directory"}
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
