"""Fresh public assessment and private worker locking."""

import contextlib
import os
import stat
import time

from workflow import file_policy_removal

DISPATCH_STOP_REASONS = {"fresh_assessment_expired",
                         "live_execution_disabled", "unreviewed_sonarr_version", "dispatch_validation_failed",
                         "sonarr_connectivity_unavailable", "identity_or_manifest_changed",
                         "dispatch_clock_unavailable", "routine_authorization_expired_or_scope_changed",
                         "routine_authorization_revoked_or_changed", "container_live_scope_confirmation_required",
                         "routine_candidate_not_authorized", "target_reappeared", "replacement_already_queued",
                         "replacement_already_grabbed", "replacement_history_ambiguous",
                         "replacement_history_identity_invalid", "replacement_history_event_invalid", "replacement_history_unavailable",
                         "replacement_queue_identity_invalid", "replacement_blocklisted",
                         "replacement_blocklist_uncertain", "run_time_limit_reached",
                         "sonarr_unscoped_blocklist_limit_reached", "torrent_identity_scan_time_limit_reached",
                         "sonarr_blocklist_scope_unverified", "retry_settings_not_ready",
                         "alternate_hash_removal_unverified", "alternate_hash_blocklist_request_uncertain",
                         "qbittorrent_file_exclusion_no_longer_matches", "qbittorrent_file_exclusions_unavailable",
                         "qbittorrent_file_exclusions_incomplete",
                         "metadata_timeout_no_longer_confirmed", "ambiguous_release_title_evidence"}
class SafetyError(Exception):
    pass


@contextlib.contextmanager
def open_lock_file(path):
    flags = os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600)) as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise SafetyError("invalid_worker_lock")
        yield lock


def valid_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def evidence(report):
    """Validate comparison evidence; titles, endpoints and credentials excluded."""
    fields = ("instance", "hash", "ownership_fingerprint", "manifest_fingerprint")
    result = {k: report.get(k) for k in fields}
    if "attempt_fingerprint" in report:
        if not valid_digest(report["attempt_fingerprint"]):
            raise SafetyError("invalid_action_evidence")
        result["attempt_fingerprint"] = report["attempt_fingerprint"]
    if (not isinstance(result["instance"], str) or not result["instance"]
            or not isinstance(result["hash"], str) or len(result["hash"]) not in (40, 64)
            or any(c not in "0123456789abcdef" for c in result["hash"])
            or not all(valid_digest(result[k]) for k in fields[2:])):
        raise SafetyError("invalid_action_evidence")
    return result


def check_fresh(original, refreshed, now=None, maximum_age=10):
    """Require the same identity/selection and still-failing public assessment."""
    now = time.time() if now is None else now
    fresh, readiness = refreshed.get("assessment", {}), refreshed.get("readiness", {})
    before, after = evidence(original), evidence(fresh)
    if before != after:
        raise SafetyError("identity_or_manifest_changed")
    if (fresh.get("decision") != "would_fail" or fresh.get("public_source_confirmed") is not True
            or original.get("decision") != "would_fail" or original.get("public_source_confirmed") is not True):
        raise SafetyError("candidate_no_longer_eligible")
    checked = fresh.get("checked_at")
    if (isinstance(checked, bool) or not isinstance(checked, (int, float))
            or not 0 <= now - checked <= maximum_age):
        raise SafetyError("fresh_assessment_expired")
    if not file_policy_removal(fresh) and (readiness.get("status") != "verified"
            or readiness.get("automatic_retry") is not True or readiness.get("interactive_retry") is not True):
        raise SafetyError("retry_settings_not_ready")
    return after
