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


def cycle(config, qb, apis, journal, batch_state=None):
    # Fail closed across both owners. Do not fall back to downloader-only work
    # when either ownership queue or Sonarr-side connectivity is unavailable.
    for label, api in apis.items():
        require_connectivity(config, api, label)
    qb.login()
    recovered = []
    keys = [r[0] for r in journal.db.execute(
        "SELECT key FROM actions WHERE mode IN ('single_test','public_attempt') "
        "AND stage IN ('dispatch_recorded','uncertain','replacement_pending')").fetchall()]
    for key in keys:
        row = journal.get(key)
        verifier = OutcomeVerifier(config, qb, apis, row["context"], row["dispatched_at"])
        row = reconcile(journal, key, verifier.observe)
        recovered.append({"key": key, "stage": row["stage"], "confirmed": row["confirmed"]})
    reports = run(config, qb, apis, batch_state=batch_state)
    for report in reports:
        if report["decision"] != "would_fail":
            continue
        try:
            fresh = recheck_candidate(report, config, qb, apis)
            check_fresh(report, fresh)
            check_prior_attempts(journal, report)
            report["safeguards"] = {"status": "fresh_attempt_verified", "live_enabled": False}
        except (SafetyError, GuardError) as error:
            report["safeguards"] = {"status": "held", "reason": str(error), "live_enabled": False}
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
