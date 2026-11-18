"""One bounded public dry-run cycle. Scheduling never grants live approval."""

import argparse
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import time

from guard import (Api, GuardError, hard_deadline, load_config, run, recheck_candidate,
                   load_batch_state, save_batch_state)
from maintenance import RETRY_AFTER_SECONDS, require_connectivity
from production import OutcomeVerifier, check_prior_attempts
from safety import Journal, SafetyError, check_fresh, reconcile

RECOVERY_LIMIT = 5
RECOVERY_SECONDS = 30
RECOVERY_ITEM_SECONDS = 5


@contextmanager
def limit_adapter_deadlines(adapters, deadline):
    previous = [(api, hasattr(api, "deadline"), getattr(api, "deadline", None)) for api in adapters]
    try:
        for api, _, old in previous:
            api.deadline = deadline if old is None else min(old, deadline)
        yield
    finally:
        for api, existed, old in previous:
            if existed:
                api.deadline = old
            else:
                del api.deadline


def recover_pending(config, qb, apis, journal, batch_state, deadline):
    """Recover a bounded, rotating slice while the caller holds guard.lock."""
    keys = sorted(r[0] for r in journal.db.execute(
        "SELECT key FROM actions WHERE mode IN ('single_test','public_attempt') "
        "AND (stage IN ('dispatch_recorded','uncertain','replacement_pending') "
        "OR (stage = 'prepared' AND dispatched_at IS NULL))").fetchall())
    after = batch_state.get("recovery_after", "")
    keys = [k for k in keys if k > after] + [k for k in keys if k <= after]
    end = min(deadline - 2, time.monotonic() + RECOVERY_SECONDS)
    recovered = []
    adapters = [qb, *apis.values()]
    for key in keys[:RECOVERY_LIMIT]:
        if time.monotonic() >= end:
            break
        item_end = min(end, time.monotonic() + RECOVERY_ITEM_SECONDS)
        try:
            row = journal.get(key)
            if row["stage"] == "prepared":
                row = journal.transition(key, "prepared", "cancelled", stop_reason="abandoned_before_dispatch")
            else:
                # An observation branch can catch an alarm. Each subsequent
                # request still has to respect the same recovery deadline.
                try:
                    with limit_adapter_deadlines(adapters, item_end), hard_deadline(item_end):
                        verifier = OutcomeVerifier(config, qb, apis, row["context"], row["dispatched_at"])
                        observation = verifier.observe()
                except Exception:
                    observation = None

                def observe():
                    if observation is None:
                        raise SafetyError("recovery_observation_unavailable")
                    return observation

                row = reconcile(journal, key, observe)
            result = {"key": key, "stage": row["stage"], "confirmed": row["confirmed"]}
            if row["stop_reason"] is not None:
                result["stop_reason"] = row["stop_reason"]
            recovered.append(result)
        finally:
            batch_state["recovery_after"] = key
    return recovered


def cycle(config, qb, apis, journal, batch_state=None, *, reserve_dispatch=False):
    if batch_state is None:
        batch_state = {}
    adapters = [qb, *apis.values()]
    started = time.monotonic()
    deadlines = [getattr(api, "deadline", None) for api in adapters]
    deadline = min([d for d in deadlines if d is not None] + [started + 180])
    budget = deadline - started
    assessment_end = started + budget / 2
    verification_end = started + budget * 2 / 3 if reserve_dispatch else deadline
    recovery_end = started + budget * 3 / 4 if reserve_dispatch else deadline
    # Validate both owners before contacting the downloader. The shorter scan
    # deadline reserves time even when a large queue exhausts assessment.
    with limit_adapter_deadlines(adapters, assessment_end):
        for label, api in apis.items():
            require_connectivity(config, api, label)
        qb.login()
        reports = run(config, qb, apis, batch_state=batch_state)
    # Rotation is independent of assessment. Even an attempted verification
    # that exhausts this phase gives the next candidate first turn next cycle.
    candidates = sorted(((r["instance"], r["hash"]), r) for r in reports if r["decision"] == "would_fail")
    after = tuple(batch_state.get("verification_after", ()))
    candidates = [entry for entry in candidates if entry[0] > after] + [
        entry for entry in candidates if entry[0] <= after]
    with limit_adapter_deadlines(adapters, verification_end):
        for key, report in candidates:
            try:
                if time.monotonic() >= verification_end:
                    raise GuardError("run_time_limit_reached")
                batch_state["verification_after"] = list(key)
                fresh = recheck_candidate(report, config, qb, apis)
                check_fresh(report, fresh)
                check_prior_attempts(journal, report, config=config)
                report["safeguards"] = {"status": "fresh_attempt_verified", "live_enabled": False}
            except (SafetyError, GuardError) as error:
                report["safeguards"] = {"status": "held", "reason": str(error), "live_enabled": False}
    recovered = recover_pending(config, qb, apis, journal, batch_state, recovery_end)
    return {"dry_run": True, "status": "assessed", "retry_after_seconds": RETRY_AFTER_SECONDS,
            "live_sender_enabled": False, "recovery": recovered, "assessment": reports}


def main():
    parser = argparse.ArgumentParser(description="One public dry-run cycle; never removes torrents")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        with open(args.config.parent / "guard.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafetyError("another_run_is_active") from None
            deadline = time.monotonic() + 180
            qb = Api(config["qbittorrent"], deadline=deadline)
            apis = {label: Api(c, deadline=deadline) for label, c in config["sonarr"].items()}
            batch_path = args.config.parent / "batch-state.json"
            batch_state = load_batch_state(batch_path)
            journal = Journal(args.config.parent / "action-journal.sqlite3")
            try:
                with hard_deadline(deadline):
                    result = cycle(config, qb, apis, journal, batch_state)
            finally:
                journal.close()
                save_batch_state(batch_path, batch_state)
    except (SafetyError, GuardError):
        result = {"dry_run": True, "status": "waiting", "reason": "maintenance_or_safety_check_unavailable",
                  "live_sender_enabled": False, "retry_after_seconds": RETRY_AFTER_SECONDS}
    except Exception:
        result = {"dry_run": True, "status": "waiting", "reason": "cycle_unavailable",
                  "live_sender_enabled": False, "retry_after_seconds": RETRY_AFTER_SECONDS}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
