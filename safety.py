"""Fresh assessment and private journals; live single tests require a separate gate."""

import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time

OBSERVATION_FIELDS = ("torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")
DISPATCH_STOP_REASONS = {"approval_expired_or_target_mismatch", "fresh_assessment_expired",
                         "unreviewed_sonarr_version", "live_execution_disabled", "dispatch_validation_failed",
                         "sonarr_connectivity_unavailable", "identity_or_manifest_changed",
                         "dispatch_clock_unavailable", "routine_authorization_expired_or_scope_changed",
                         "routine_candidate_not_authorized", "target_reappeared", "replacement_already_queued",
                         "replacement_already_grabbed", "replacement_history_ambiguous", "replacement_client_unknown",
                         "replacement_history_identity_invalid", "replacement_history_event_invalid",
                         "replacement_queue_identity_invalid"}
CANCELLATION_STOP_REASONS = DISPATCH_STOP_REASONS | {"cancellation_validation_failed", "retry_settings_not_ready",
                                                    "candidate_no_longer_eligible"}
ARCHIVE_ROW_LIMIT = 10000
RELATED_RECORD_LIMIT = 1000
ARCHIVE_MINIMUM_AGE = 30 * 24 * 60 * 60
ACTION_FIELDS = ("mode", "stage", "evidence", "observation", "confirmed", "current_observation",
                 "observation_available", "context", "dispatched_at", "stop_reason", "search_command_id")


def clean_observation(observation):
    if not isinstance(observation, dict):
        raise SafetyError("invalid_observation")
    safe = {}
    for field in OBSERVATION_FIELDS:
        val = observation.get(field)
        if val is not None and not isinstance(val, bool):
            raise SafetyError("invalid_observation")
        if field in observation:
            safe[field] = val
    return safe


class SafetyError(Exception):
    pass


def valid_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def evidence(report):
    """Whitelist persisted evidence; titles, endpoints and credentials excluded."""
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
    if (readiness.get("status") != "verified" or readiness.get("automatic_retry") is not True
            or readiness.get("interactive_retry") is not True):
        raise SafetyError("retry_settings_not_ready")
    return after


class Journal:
    """A private SQLite journal under the already-private external config folder.

    Rows are bounded without deleting unresolved evidence. Transactions use FULL
    synchronization. Preview and simulation rows cannot authorize production work.
    """
    def __init__(self, path, limit=1000, allow_single_test=False, allow_public_attempt=False,
                 allow_archive=False, read_only=False):
        self.path = Path(path)
        self.read_only = read_only is True
        if self.path.is_symlink() or self.path.parent.stat().st_mode & 0o077:
            raise SafetyError("journal_requires_private_directory")
        if self.read_only:
            if (self.path.stat().st_mode & 0o077 or allow_single_test or allow_public_attempt or allow_archive):
                raise SafetyError("journal_requires_private_directory")
            self.limit = limit
            self.allow_single_test = self.allow_public_attempt = self.allow_archive = False
            self.db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
            self.has_archive = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                               "AND name='actions_archive'").fetchone() is not None
            return
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.is_symlink():
                raise SafetyError("journal_symlink_refused")
            if sidecar.exists():
                sidecar.chmod(0o600)
        self.limit = limit
        self.allow_single_test = allow_single_test is True
        self.allow_public_attempt = allow_public_attempt is True
        self.allow_archive = allow_archive is True
        self.db = sqlite3.connect(self.path, timeout=5)
        try:
            self._initialize()
            self.has_archive = True
        except BaseException:
            self.db.close()
            raise

    def _initialize(self):
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS actions ("
                        "key TEXT PRIMARY KEY, mode TEXT NOT NULL, stage TEXT NOT NULL, "
                        "evidence TEXT NOT NULL, observation TEXT NOT NULL, updated REAL NOT NULL)")
        self.db.commit()
        # Additive migration preserves existing recovery evidence and row keys.
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            columns = {r[1] for r in self.db.execute("PRAGMA table_info(actions)")}
            additions = {
                "confirmed": "TEXT NOT NULL DEFAULT '{}'",
                "current_observation": "TEXT NOT NULL DEFAULT '{}'",
                "observation_available": "INTEGER NOT NULL DEFAULT 0",
                "context": "TEXT NOT NULL DEFAULT '{}'",
                "dispatched_at": "REAL",
                "stop_reason": "TEXT",
                "search_command_id": "INTEGER",
            }
            for name, declaration in additions.items():
                if name not in columns:
                    self.db.execute("ALTER TABLE actions ADD COLUMN " + name + " " + declaration)
            if "confirmed" not in columns:
                for key, raw in self.db.execute("SELECT key,observation FROM actions").fetchall():
                    old = clean_observation(json.loads(raw))
                    confirmed = {k: True for k, v in old.items() if v is True}
                    self.db.execute("UPDATE actions SET confirmed=? WHERE key=?", (json.dumps(confirmed), key))
            self.db.execute("CREATE TABLE IF NOT EXISTS actions_archive ("
                            "key TEXT PRIMARY KEY, instance TEXT NOT NULL, hash TEXT NOT NULL, "
                            "mode TEXT NOT NULL, payload TEXT NOT NULL, archived_at REAL NOT NULL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS archive_owner_hash ON actions_archive(instance,hash)")

    def close(self):
        self.db.close()

    def get(self, key):
        row = self.db.execute("SELECT " + ",".join(ACTION_FIELDS) + " FROM actions WHERE key=?", (key,)).fetchone()
        cold = self.db.execute("SELECT instance,hash,mode,payload FROM actions_archive WHERE key=?", (key,)).fetchone() if self.has_archive else None
        if row is not None and cold is not None:
            raise SafetyError("journal_duplicate_archive_key")
        if cold is not None:
            raw = json.loads(cold[3])
            if (not isinstance(raw, dict) or raw.get("key") != key or
                    any(field not in raw for field in ACTION_FIELDS) or
                    raw.get("mode") != cold[2] or raw.get("stage") not in ("cleanup_resolved", "complete")):
                raise SafetyError("invalid_archive_evidence")
            identity = json.loads(raw["evidence"])
            if identity.get("instance") != cold[0] or identity.get("hash") != cold[1]:
                raise SafetyError("invalid_archive_evidence")
            row = tuple(raw[field] for field in ACTION_FIELDS)
        return None if row is None else {"key": key, "mode": row[0], "stage": row[1],
                                        "evidence": json.loads(row[2]), "observation": json.loads(row[3]),
                                        "confirmed": json.loads(row[4]), "current_observation": json.loads(row[5]),
                                        "observation_available": bool(row[6]), "context": json.loads(row[7]),
                                        "dispatched_at": row[8], "stop_reason": row[9], "search_command_id": row[10]}

    def prepare(self, report, mode="preview", context=None):
        if mode not in ("preview", "simulation") and not (
                mode == "single_test" and self.allow_single_test) and not (
                mode == "public_attempt" and self.allow_public_attempt):
            raise SafetyError("live_execution_disabled")
        if mode in ("single_test", "public_attempt") and context is None:
            raise SafetyError("operation_context_required")
        if context is not None:
            if mode not in ("single_test", "public_attempt"):
                raise SafetyError("unexpected_action_context")
            from production import validate_context
            context = validate_context(context)
        value = evidence(report)
        if mode == "public_attempt" and ("attempt_fingerprint" not in value
                or context.get("attempt_fingerprint") != value["attempt_fingerprint"]):
            raise SafetyError("attempt_identity_required")
        identity = [mode, value["instance"], value["hash"]]
        # Single-test approval remains one action per hash, including re-grabs.
        # Preview/simulation and the separately gated attempt sender track incarnations.
        if mode != "single_test" and "attempt_fingerprint" in value:
            identity.append(value["attempt_fingerprint"])
        if mode == "public_attempt":
            identity.append(context["approval_digest"])
        key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            old = self.get(key)
            if old is not None:
                if old["evidence"] != value:
                    raise SafetyError("journal_evidence_changed")
                return old
            if self.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0] >= self.limit:
                raise SafetyError("journal_capacity_reached")
            self.db.execute("INSERT INTO actions(key,mode,stage,evidence,observation,updated,context) VALUES(?,?,?,?,?,?,?)",
                            (key, mode, "prepared", json.dumps(value), "{}", time.time(), json.dumps(context or {})))
        return self.get(key)

    def transition(self, key, expected, stage, observation=None, stop_reason=None):
        allowed = {
            "prepared": {"preview_verified", "cancelled", "dispatch_recorded"},
            "dispatch_recorded": {"dispatch_blocked", "uncertain", "replacement_pending", "manual_review", "complete", "cleanup_resolved", "retry_removed"},
            "uncertain": {"uncertain", "replacement_pending", "manual_review", "complete", "cleanup_resolved", "retry_removed"},
            "replacement_pending": {"uncertain", "replacement_pending", "manual_review", "complete", "cleanup_resolved", "retry_removed"},
            "retry_removed": {"retry_search_recorded", "retry_superseded"},
            "retry_search_recorded": {"retry_search_blocked", "retry_search_uncertain"},
        }
        if stage not in allowed.get(expected, set()):
            raise SafetyError("invalid_journal_transition")
        if stage in ("dispatch_blocked", "retry_search_blocked"):
            if stop_reason not in DISPATCH_STOP_REASONS:
                raise SafetyError("invalid_dispatch_stop_reason")
        elif stage == "cancelled":
            # Legacy/test-only cancellations may have no reason. New production
            # cancellations provide an exact safe code, never raw exception text.
            if stop_reason is not None and stop_reason not in CANCELLATION_STOP_REASONS:
                raise SafetyError("invalid_cancellation_stop_reason")
        elif stop_reason is not None:
            raise SafetyError("unexpected_dispatch_stop_reason")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(key)
            if row is None or row["stage"] != expected:
                raise SafetyError("journal_stage_changed")
            if stage.startswith("retry_"):
                if (row["mode"] not in ("single_test", "public_attempt") or
                        row["context"].get("metadata_retry", {}).get("blocklist") is not False):
                    raise SafetyError("invalid_retry_transition")
                if stage in ("retry_search_recorded", "retry_superseded") and not (
                        (row["mode"] == "single_test" and self.allow_single_test) or
                        (row["mode"] == "public_attempt" and self.allow_public_attempt)):
                    raise SafetyError("live_execution_disabled")
            if stage == "dispatch_recorded" and not (row["mode"] == "simulation" or
                    (row["mode"] == "single_test" and self.allow_single_test) or
                    (row["mode"] == "public_attempt" and self.allow_public_attempt)):
                raise SafetyError("live_execution_disabled")
            retained = observation is None and stage.startswith("retry_")
            current = dict(row["current_observation"]) if retained else (
                {} if observation is None else clean_observation(observation))
            if stage == "retry_removed" and (current.get("torrent_absent") is not True
                    or current.get("blocklisted") is True):
                raise SafetyError("cleanup_not_verified")
            if stage == "retry_superseded" and row["current_observation"].get("replacement_observed") is not True:
                raise SafetyError("replacement_not_observed")
            last_known = dict(row["observation"])
            confirmed = dict(row["confirmed"])
            for field, val in current.items():
                if val is not None:
                    last_known[field] = val
                if val is True:
                    confirmed[field] = True
            if stage == "complete" and not all(current.get(field) is True for field in OBSERVATION_FIELDS):
                raise SafetyError("completion_not_verified")
            if stage == "cleanup_resolved" and (row["mode"] != "public_attempt" or not all(
                    current.get(field) is True for field in ("torrent_absent", "failed", "blocklisted"))):
                raise SafetyError("cleanup_not_verified")
            contradiction_fields = ("torrent_absent", "failed", "blocklisted") if row["mode"] == "public_attempt" else OBSERVATION_FIELDS
            if any(current.get(field) is False and row["confirmed"].get(field) is True
                   for field in contradiction_fields):
                stage = "manual_review"
            dispatched_at = time.time() if stage == "dispatch_recorded" else row["dispatched_at"]
            self.db.execute("UPDATE actions SET stage=?,observation=?,confirmed=?,current_observation=?,"
                            "observation_available=?,updated=?,dispatched_at=?,stop_reason=? WHERE key=? AND stage=?",
                            (stage, json.dumps(last_known), json.dumps(confirmed), json.dumps(current),
                             row["observation_available"] if retained else observation is not None, time.time(), dispatched_at,
                             stop_reason if stage in ("dispatch_blocked", "cancelled", "retry_search_blocked") else row["stop_reason"], key, expected))
        return self.get(key)

    def record_search_accepted(self, key, command_id):
        """Persist a validated Sonarr receipt; acceptance is not import/completion."""
        if isinstance(command_id, bool) or not isinstance(command_id, int) or command_id <= 0:
            raise SafetyError("invalid_search_command_id")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(key)
            if (row is None or row["stage"] != "retry_search_recorded" or
                    row["context"].get("metadata_retry", {}).get("blocklist") is not False):
                raise SafetyError("invalid_retry_transition")
            if not ((row["mode"] == "single_test" and self.allow_single_test) or
                    (row["mode"] == "public_attempt" and self.allow_public_attempt)):
                raise SafetyError("live_execution_disabled")
            self.db.execute("UPDATE actions SET stage='retry_requested',search_command_id=?,updated=? WHERE key=?",
                            (command_id, time.time(), key))
        return self.get(key)

    def related(self, instance, hash_value):
        """Bounded active scan plus indexed archive lookup; never forget old holds."""
        result = []
        for (key,) in self.db.execute("SELECT key FROM actions WHERE mode IN ('single_test','public_attempt')").fetchall():
            row = self.get(key)
            if row["evidence"]["instance"] == instance and row["evidence"]["hash"] == hash_value:
                result.append(row)
        keys = self.db.execute("SELECT key FROM actions_archive WHERE instance=? AND hash=? "
                               "AND mode IN ('single_test','public_attempt') LIMIT ?",
                               (instance, hash_value, RELATED_RECORD_LIMIT + 1)).fetchall() if self.has_archive else []
        if len(result) + len(keys) > RELATED_RECORD_LIMIT:
            raise SafetyError("journal_history_limit_reached")
        result.extend(self.get(key) for (key,) in keys)
        return result

    def archive_resolved(self, now=None, batch_limit=100, preview=True):
        """Move old resolved production records atomically, preserving ALL columns.

        Not a purge: get/related continue to consult the indexed archive. No
        uncertain, preview, cancelled or metadata-retry receipt records qualify.
        Explicit housekeeping permission is separate from any sender grant.
        """
        now = time.time() if now is None else now
        if (isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now)
                or now <= 0 or isinstance(batch_limit, bool) or not isinstance(batch_limit, int)
                or not 1 <= batch_limit <= 100 or not isinstance(preview, bool)):
            raise SafetyError("invalid_archive_request")
        if not preview and not self.allow_archive:
            raise SafetyError("journal_archive_not_authorized")
        with self.db:
            self.db.execute("BEGIN" if self.read_only else "BEGIN IMMEDIATE")
            columns = [row[1] for row in self.db.execute("PRAGMA table_info(actions)")]
            cursor = self.db.execute("SELECT * FROM actions WHERE mode IN ('single_test','public_attempt') "
                                     "AND stage IN ('cleanup_resolved','complete') AND updated<=? "
                                     "ORDER BY updated,key LIMIT ?", (now - ARCHIVE_MINIMUM_AGE, self.limit + 1))
            raw_rows = [dict(zip(columns, values)) for values in cursor.fetchall()]
            if len(raw_rows) > self.limit:
                raise SafetyError("journal_capacity_reached")
            candidates = []
            for raw in raw_rows:
                row = self.get(raw["key"])
                # Validate production identity and leave any inconsistent result hot.
                from production import validate_context
                context = validate_context(row["context"])
                identity = evidence(row["evidence"])
                if (any(context.get(k) != identity.get(k) for k in ("instance", "hash")) or
                        ("attempt_fingerprint" in identity and context.get("attempt_fingerprint") != identity["attempt_fingerprint"])):
                    raise SafetyError("invalid_archive_evidence")
                dispatched = row["dispatched_at"]
                if (isinstance(dispatched, bool) or not isinstance(dispatched, (int, float)) or
                        not math.isfinite(dispatched) or not 0 < dispatched <= raw["updated"] or
                        not row["observation_available"] or "metadata_retry" in context):
                    continue
                required = OBSERVATION_FIELDS if row["stage"] == "complete" else ("torrent_absent", "failed", "blocklisted")
                if (row["stage"] == "cleanup_resolved" and row["mode"] != "public_attempt") or not all(
                        row["confirmed"].get(field) is True and row["current_observation"].get(field) is True
                        for field in required):
                    continue
                candidates.append(raw)
                if len(candidates) >= batch_limit:
                    break
            cold_count = self.db.execute("SELECT COUNT(*) FROM actions_archive").fetchone()[0] if self.has_archive else 0
            if cold_count + len(candidates) > ARCHIVE_ROW_LIMIT:
                raise SafetyError("journal_archive_capacity_reached")
            if not preview:
                for raw in candidates:
                    identity = json.loads(raw["evidence"])
                    self.db.execute("INSERT INTO actions_archive(key,instance,hash,mode,payload,archived_at) "
                                    "VALUES(?,?,?,?,?,?)", (raw["key"], identity["instance"], identity["hash"],
                                    raw["mode"], json.dumps(raw, sort_keys=True), now))
                    if self.db.execute("DELETE FROM actions WHERE key=? AND updated=?",
                                       (raw["key"], raw["updated"])).rowcount != 1:
                        raise SafetyError("journal_stage_changed")
            return {"mode": "preview" if preview else "archived", "eligible": len(candidates),
                    "archived": 0 if preview else len(candidates),
                    "active_rows": self.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0],
                    "archive_rows": cold_count if preview else cold_count + len(candidates),
                    "minimum_age_days": 30, "keys": [raw["key"] for raw in candidates]}

    def refresh_baselines(self, key, refreshed):
        """Only the armed, not-yet-sent coordinator may extend baseline IDs.

        Recovery never calls this. Preserve identity, original window and all
        existing baseline IDs; do not change dispatch time or observations.
        """
        from production import validate_context
        refreshed = validate_context(refreshed)
        mutable = {"baseline_history_ids", "baseline_blocklist_ids", "window_start"}
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(key)
            if (row is None or row["stage"] != "dispatch_recorded" or not (
                    (row["mode"] == "single_test" and self.allow_single_test) or
                    (row["mode"] == "public_attempt" and self.allow_public_attempt))):
                raise SafetyError("baseline_refresh_forbidden")
            previous = validate_context(row["context"])
            if ({k: v for k, v in previous.items() if k not in mutable} !=
                    {k: v for k, v in refreshed.items() if k not in mutable}):
                raise SafetyError("identity_or_manifest_changed")
            merged = dict(previous)
            for field in ("baseline_history_ids", "baseline_blocklist_ids"):
                merged[field] = sorted(set(previous[field]) | set(refreshed[field]))
            merged = validate_context(merged)
            self.db.execute("UPDATE actions SET context=?,updated=? WHERE key=? AND stage='dispatch_recorded'",
                            (json.dumps(merged), time.time(), key))
        return self.get(key)


def record_preview(journal, original, recheck, now=None):
    """Persist a successful read-only recheck; never record dispatch intent."""
    check_fresh(original, recheck(), now)
    row = journal.prepare(original)
    if row["stage"] == "prepared":
        row = journal.transition(row["key"], "prepared", "preview_verified")
    return row


def reconcile(journal, key, observe):
    """Read evidence only. No dispatch/retry path exists during recovery."""
    row = journal.get(key)
    if row is None or row["mode"] not in ("simulation", "single_test", "public_attempt"):
        raise SafetyError("live_execution_disabled")
    if row["stage"] not in ("dispatch_recorded", "uncertain", "replacement_pending"):
        return row
    try:
        observation = clean_observation(observe())
    except Exception:
        return journal.transition(key, row["stage"], "uncertain")
    known = dict(row["observation"])
    known.update({k: v for k, v in observation.items() if v is not None})
    if row["context"].get("metadata_retry", {}).get("blocklist") is False:
        if observation.get("blocklisted") is True:
            stage = "manual_review"
        elif observation.get("torrent_absent") is True:
            stage = "retry_removed"
        else:
            stage = "uncertain"
    elif row["mode"] == "public_attempt" and all(
            observation.get(k) is True for k in ("torrent_absent", "failed", "blocklisted")):
        stage = "cleanup_resolved"
    elif all(observation.get(k) is True for k in OBSERVATION_FIELDS):
        stage = "complete"
    elif known.get("torrent_absent") is True and (
            known.get("failed") is False or known.get("blocklisted") is False):
        stage = "manual_review"
    elif all(known.get(k) is True for k in ("torrent_absent", "failed", "blocklisted")):
        stage = "replacement_pending"
    else:
        stage = "uncertain"
    return journal.transition(key, row["stage"], stage, observation)


def simulate_action(journal, original, recheck, fake_send, observe, now=None):
    """Test harness only. Callback outcomes never enable a live API transport.

    Dispatch intent is committed before invoking a simulated sender. On restart,
    every non-prepared record goes to read-only reconciliation, never re-sending.
    """
    row = journal.prepare(original, mode="simulation")
    if row["stage"] != "prepared":
        return reconcile(journal, row["key"], observe)
    try:
        check_fresh(original, recheck(), now)
    except Exception:
        return journal.transition(row["key"], "prepared", "cancelled")
    row = journal.transition(row["key"], "prepared", "dispatch_recorded")
    try:
        fake_send()
    except Exception:
        row = journal.transition(row["key"], "dispatch_recorded", "uncertain")
    return reconcile(journal, row["key"], observe)
