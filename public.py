"""One bounded public dry-run cycle. Scheduling never grants live approval."""

import argparse
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


def recover_pending(config, qb, apis, journal, batch_state, deadline):
    """Small rotating slice, after assessment; never spend its reserved time."""
    keys = sorted(r[0] for r in journal.db.execute(
        "SELECT key FROM actions WHERE mode IN ('single_test','public_attempt') "
        "AND stage IN ('dispatch_recorded','uncertain','replacement_pending')").fetchall())
    after = batch_state.get("recovery_after", "")
    keys = [k for k in keys if k > after] + [k for k in keys if k <= after]
    end = min(deadline - 2, time.monotonic() + RECOVERY_SECONDS)
    recovered = []
    adapters = [qb, *apis.values()]
    for key in keys[:RECOVERY_LIMIT]:
        if time.monotonic() >= end:
            break
        item_end = min(end, time.monotonic() + RECOVERY_ITEM_SECONDS)
        old_deadlines = [(api, hasattr(api, "deadline"), getattr(api, "deadline", None)) for api in adapters]
        try:
            # Some observation branches deliberately catch failures. Propagate
            # the sub-deadline into every adapter too, so a caught alarm cannot
            # let the next branch start another long request.
            for api, _, old in old_deadlines:
                api.deadline = min(old, item_end) if old is not None else item_end
            row = journal.get(key)
            try:
                with hard_deadline(item_end):
                    verifier = OutcomeVerifier(config, qb, apis, row["context"], row["dispatched_at"])
                    observation = verifier.observe()
            except Exception:
                observation = None
            # Commit uncertainty outside the observation alarm's scope.
            def observe():
                if observation is None:
                    raise SafetyError("recovery_observation_unavailable")
                return observation
            row = reconcile(journal, key, observe)
            recovered.append({"key": key, "stage": row["stage"], "confirmed": row["confirmed"]})
        finally:
            batch_state["recovery_after"] = key
            for api, existed, old in old_deadlines:
                if existed:
                    api.deadline = old
                else:
                    del api.deadline
    return recovered


def cycle(config, qb, apis, journal, batch_state=None):
    if batch_state is None:
        batch_state = {}
    deadlines = [getattr(api, "deadline", None) for api in [qb, *apis.values()]]
    deadline = min([d for d in deadlines if d is not None] + [time.monotonic() + 180])
    # Fail closed across both owners. Do not fall back to downloader-only work
    # when either ownership queue or Sonarr-side connectivity is unavailable.
    for label, api in apis.items():
        require_connectivity(config, api, label)
    qb.login()
    # Reserve assessment's opportunity by doing it first. Recovery backlog is
    # never allowed to consume the cycle before the candidate cursor advances.
    reports = run(config, qb, apis, batch_state=batch_state)
    for report in reports:
        if report["decision"] != "would_fail":
            continue
        try:
            fresh = recheck_candidate(report, config, qb, apis)
            check_fresh(report, fresh)
            check_prior_attempts(journal, report, config=config)
            report["safeguards"] = {"status": "fresh_attempt_verified", "live_enabled": False}
        except (SafetyError, GuardError) as error:
            report["safeguards"] = {"status": "held", "reason": str(error), "live_enabled": False}
    recovered = recover_pending(config, qb, apis, journal, batch_state, deadline)
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
