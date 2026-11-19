"""One bounded public dry-run cycle. Scheduling never grants live approval."""

import argparse
from contextlib import contextmanager
import datetime
import fcntl
import json
import logging
from pathlib import Path
import time

from guard import (Api, GuardError, PrivateRotatingFileHandler, hard_deadline, load_config, run, recheck_candidate,
                   load_batch_state, save_batch_state)
from maintenance import RETRY_AFTER_SECONDS, require_connectivity
from production import check_visible_native_grabs, require_sonarr_v4
from safety import SafetyError, check_fresh, open_lock_file
from workflow import file_policy_removal, manual_handling_reason

PERSIST_SECONDS = 2


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


def cycle(config, qb, apis, batch_state=None, *, reserve_dispatch=False):
    if batch_state is None:
        batch_state = {}
    adapters = [qb, *apis.values()]
    started = time.monotonic()
    deadlines = [getattr(api, "deadline", None) for api in adapters]
    deadline = min([d for d in deadlines if d is not None] + [started + 180])
    budget = deadline - started
    assessment_end = started + budget / 2
    verification_end = started + budget * 3 / 4 if reserve_dispatch else deadline - PERSIST_SECONDS
    # Validate both owners before contacting the downloader. The shorter scan
    # deadline reserves time even when a large queue exhausts assessment.
    with limit_adapter_deadlines(adapters, assessment_end):
        for label, api in apis.items():
            require_connectivity(config, api, label)
        qb.login()
        reports = run(config, qb, apis, batch_state=batch_state)
    # Rotation is independent of assessment. Even an attempted verification
    # that exhausts this phase gives the next candidate first turn next cycle.
    candidates = []
    for report in reports:
        if report["decision"] != "would_fail":
            continue
        reason = manual_handling_reason(report)
        if reason is None:
            candidates.append(((report["instance"], report["hash"]), report))
        else:
            report["safeguards"] = {"status": "manual_review", "reason": reason, "live_enabled": False}
    candidates.sort(key=lambda item: item[0])
    after = tuple(batch_state.get("verification_after", ()))
    candidates = [entry for entry in candidates if entry[0] > after] + [
        entry for entry in candidates if entry[0] <= after]
    with limit_adapter_deadlines(adapters, verification_end):
        for key, report in candidates:
            try:
                if time.monotonic() >= verification_end:
                    raise GuardError("run_time_limit_reached")
                batch_state["verification_after"] = list(key)
                with hard_deadline(verification_end):
                    fresh = recheck_candidate(report, config, qb, apis)
                    check_fresh(report, fresh)
                    if not reserve_dispatch and file_policy_removal(report):
                        label = report["instance"]
                        require_sonarr_v4(apis[label])
                        check_visible_native_grabs(apis[label], config["sonarr"][label], fresh["assessment"],
                                                   config.get("max_pages", 20))
                report["safeguards"] = {"status": "fresh_attempt_verified", "live_enabled": False}
            except (SafetyError, GuardError) as error:
                report["safeguards"] = {"status": "held", "reason": str(error), "live_enabled": False}
    return {"dry_run": True, "status": "assessed", "retry_after_seconds": RETRY_AFTER_SECONDS,
            "live_sender_enabled": False, "assessment": reports}


def main():
    parser = argparse.ArgumentParser(description="One public dry-run cycle; never removes torrents")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--log-file", type=Path, help="Write would-remove proposals to a private rotating log")
    args = parser.parse_args()
    handler = None
    try:
        config = load_config(args.config)
        if args.log_file is not None:
            handler = PrivateRotatingFileHandler(args.log_file, config_path=args.config)
        with open_lock_file(args.config.parent / "guard.lock") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafetyError("another_run_is_active") from None
            deadline = time.monotonic() + 180
            qb = Api(config["qbittorrent"], deadline=deadline)
            apis = {label: Api(c, deadline=deadline) for label, c in config["sonarr"].items()}
            batch_path = args.config.parent / "batch-state.json"
            batch_state = load_batch_state(batch_path)
            try:
                with hard_deadline(deadline):
                    result = cycle(config, qb, apis, batch_state)
            finally:
                save_batch_state(batch_path, batch_state)
    except (SafetyError, GuardError) as error:
        allowed = {"invalid_worker_lock", "another_run_is_active", "log_destination_reserved",
                   "log_destination_not_private_file", "log_symlink_refused"}
        reason = str(error) if str(error) in allowed else "maintenance_or_safety_check_unavailable"
        result = {"dry_run": True, "status": "waiting", "reason": reason,
                  "live_sender_enabled": False, "retry_after_seconds": RETRY_AFTER_SECONDS}
    except Exception:
        result = {"dry_run": True, "status": "waiting", "reason": "cycle_unavailable",
                  "live_sender_enabled": False, "retry_after_seconds": RETRY_AFTER_SECONDS}
    if handler is not None:
        stamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        try:
            for report in result.get("assessment", ()):
                if report["decision"] == "would_fail":
                    status = report.get("safeguards", {}).get("status")
                    entry = {"event": "would_remove" if status == "fresh_attempt_verified" else "held",
                             "time": stamp, "instance": report["instance"], "hash": report["hash"],
                             "reasons": report["reasons"], "safeguards": report.get("safeguards")}
                    handler.emit(logging.LogRecord("public", logging.INFO, "", 0, json.dumps(entry), (), None))
            if result["status"] == "waiting":
                entry = {"event": "waiting", "time": stamp, "reason": result["reason"]}
                handler.emit(logging.LogRecord("public", logging.INFO, "", 0, json.dumps(entry), (), None))
        finally:
            handler.close()
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
