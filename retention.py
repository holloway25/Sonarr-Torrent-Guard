"""Explicit local journal housekeeping; no Sonarr or downloader requests."""

import argparse
import fcntl
import json
from pathlib import Path

from safety import Journal, SafetyError


# Review candidate: no scheduler and no automatic archive activation.
ARCHIVE_RELEASE_ENABLED = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--batch-limit", type=int, default=100)
    parser.add_argument("--apply", action="store_true", help="Requires separately reviewed archive release")
    args = parser.parse_args()
    try:
        if args.apply and ARCHIVE_RELEASE_ENABLED is not True:
            raise SafetyError("journal_archive_not_authorized")
        # Preview uses a read-only connection: no schema, permissions or rows change.
        if not args.apply:
            journal = Journal(args.journal, read_only=True)
            try:
                result = journal.archive_resolved(batch_limit=args.batch_limit)
            finally:
                journal.close()
        else:
            # Same worker lock, nonblocking; no work races an in-flight sender.
            with open(args.journal.parent / "guard.lock", "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                journal = Journal(args.journal, allow_archive=True)
                try:
                    result = journal.archive_resolved(batch_limit=args.batch_limit, preview=False)
                finally:
                    journal.close()
        print(json.dumps(result))
        return 0
    except SafetyError as error:
        allowed = {"journal_archive_not_authorized", "invalid_archive_request", "journal_capacity_reached",
                   "journal_archive_capacity_reached", "journal_history_limit_reached",
                   "journal_duplicate_archive_key", "invalid_archive_evidence",
                   "journal_requires_private_directory"}
        reason = str(error) if str(error) in allowed else "journal_housekeeping_unavailable"
    except BlockingIOError:
        reason = "another_run_is_active"
    except Exception:
        reason = "journal_housekeeping_unavailable"
    print(json.dumps({"mode": "held", "reason": reason, "archived": 0}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
