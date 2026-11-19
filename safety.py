"""Fresh assessment and private journals; live single tests require a separate gate."""

import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
import secrets

OBSERVATION_FIELDS = ("torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")
DISPATCH_STOP_REASONS = {"approval_expired_or_target_mismatch", "fresh_assessment_expired",
                         "unreviewed_sonarr_version", "live_execution_disabled", "dispatch_validation_failed",
                         "sonarr_connectivity_unavailable", "identity_or_manifest_changed",
                         "dispatch_clock_unavailable", "routine_authorization_expired_or_scope_changed",
                         "routine_authorization_revoked_or_changed", "container_live_scope_confirmation_required",
                         "routine_candidate_not_authorized", "target_reappeared", "replacement_already_queued",
                         "replacement_already_grabbed", "replacement_history_ambiguous", "replacement_client_unknown",
                         "replacement_history_identity_invalid", "replacement_history_event_invalid", "replacement_history_unavailable",
                         "replacement_queue_identity_invalid", "replacement_blocklisted",
                         "replacement_blocklist_uncertain", "run_time_limit_reached",
                         "container_journal_missing", "container_journal_identity_mismatch",
                         "container_journal_marker_missing", "sonarr_unscoped_blocklist_limit_reached", "torrent_identity_scan_time_limit_reached",
                         "sonarr_blocklist_scope_unverified", "sonarr_blocklist_scope_unverifiable", "retry_settings_not_ready",
                         "metadata_timeout_no_longer_confirmed", "ambiguous_release_title_evidence"}
CANCELLATION_STOP_REASONS = DISPATCH_STOP_REASONS | {"cancellation_validation_failed",
                                                    "candidate_no_longer_eligible", "abandoned_before_dispatch"}
ARCHIVE_ROW_LIMIT = 10000
RELATED_RECORD_LIMIT = 1000
ARCHIVE_MINIMUM_AGE = 30 * 24 * 60 * 60
CONTAINER_JOURNAL_MARKER = "container-live-journal.json"
CONTAINER_JOURNAL_BINDING = "container-journal-binding.json"
ACTION_JOURNAL_FILE = "action-journal.sqlite3"
ACTION_FIELDS = ("mode", "stage", "evidence", "observation", "confirmed", "current_observation",
                 "observation_available", "context", "dispatched_at", "stop_reason", "search_command_id")
ACTION_ADDITIONS = {
    "confirmed": ("TEXT NOT NULL", "'{}'"),
    "current_observation": ("TEXT NOT NULL", "'{}'"),
    "observation_available": ("INTEGER NOT NULL", "0"),
    "context": ("TEXT NOT NULL", "'{}'"),
    "dispatched_at": ("REAL", "NULL"),
    "stop_reason": ("TEXT", "NULL"),
    "search_command_id": ("INTEGER", "NULL"),
}


def replacement_already_observed(row):
    return any(row[view].get(field) is True for view in ("current_observation", "confirmed")
               for field in ("replacement_grab_observed", "any_replacement_observed", "replacement_observed"))


def clean_observation(observation):
    if not isinstance(observation, dict):
        raise SafetyError("invalid_observation")
    safe = {}
    for field in (*OBSERVATION_FIELDS, "any_replacement_observed", "replacement_grab_observed",
                  "replacement_grab_ambiguous"):
        val = observation.get(field)
        if val is not None and not isinstance(val, bool):
            raise SafetyError("invalid_observation")
        if field in observation:
            safe[field] = val
    return safe


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


def read_installation_id(db):
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='installation_identity'").fetchone()
    if exists is None:
        return None
    rows = db.execute("SELECT singleton,id FROM installation_identity").fetchall()
    if len(rows) != 1 or rows[0][0] != 1 or not valid_digest(rows[0][1]):
        raise SafetyError("container_journal_identity_mismatch")
    return rows[0][1]


def validate_journal_sidecars(path, *, harden=False):
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        try:
            mode = sidecar.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise SafetyError("journal_symlink_refused")
        if not stat.S_ISREG(mode):
            raise SafetyError("journal_requires_private_directory")
        if harden:
            sidecar.chmod(0o600)


def recover_bound_journal_rollback(path, expected_id):
    """Recover one existing journal under the shared worker lock."""
    if not valid_digest(expected_id):
        raise SafetyError("container_journal_identity_mismatch")
    if path.parent.stat().st_mode & 0o077:
        raise SafetyError("journal_requires_private_directory")

    def identity():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise SafetyError("journal_requires_private_directory")
        return info.st_dev, info.st_ino

    original_file = identity()
    validate_journal_sidecars(path)
    uri = path.absolute().as_uri()
    # The installation ID is written once and is outside routine transactions.
    # Read only that ID from the main file without triggering rollback. Never
    # use this view for action rows or any other startup validation.
    with contextlib.closing(sqlite3.connect(uri + "?mode=ro&immutable=1", uri=True, timeout=5)) as db:
        if read_installation_id(db) != expected_id:
            raise SafetyError("container_journal_identity_mismatch")
    if identity() != original_file:
        raise SafetyError("container_journal_identity_mismatch")
    validate_journal_sidecars(path)
    with contextlib.closing(sqlite3.connect(uri + "?mode=rw", uri=True, timeout=5)) as db:
        # SQLite applies its rollback before serving this query. No application
        # writes, schema migration or replacement of the database happens here.
        if read_installation_id(db) != expected_id or identity() != original_file:
            raise SafetyError("container_journal_identity_mismatch")


class Journal:
    """A private SQLite journal under the already-private external config folder.

    Rows are bounded without deleting unresolved evidence. Transactions use FULL
    synchronization. Preview and simulation rows cannot authorize production work.
    """
    def __init__(self, path, limit=1000, allow_single_test=False, allow_public_attempt=False,
                 allow_archive=False, read_only=False, expected_installation_id=None, existing_only=False):
        self.path = Path(path)
        self.read_only = read_only is True
        self._action_projection = ",".join(ACTION_FIELDS)
        self._legacy_confirmed = False
        self._bound_inode = None
        if self.path.is_symlink() or self.path.parent.stat().st_mode & 0o077:
            raise SafetyError("journal_requires_private_directory")
        if self.read_only:
            mode = self.path.stat().st_mode
            if (not stat.S_ISREG(mode) or mode & 0o077
                    or allow_single_test or allow_public_attempt or allow_archive):
                raise SafetyError("journal_requires_private_directory")
            validate_journal_sidecars(self.path)
            self.limit = limit
            self.allow_single_test = self.allow_public_attempt = self.allow_archive = False
            self.db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
            try:
                self.has_archive = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                                   "AND name='actions_archive'").fetchone() is not None
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(actions)")}
                missing = ACTION_ADDITIONS.keys() - columns
                # Let read-only consumers inspect valid old rows without migrating them.
                self._action_projection = ",".join(
                    f"{ACTION_ADDITIONS[field][1]} AS {field}" if field in missing else field
                    for field in ACTION_FIELDS)
                self._legacy_confirmed = "confirmed" in missing
            except BaseException:
                self.db.close()
                raise
            return
        flags = os.O_RDWR | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        if expected_installation_id is None and not existing_only:
            flags |= os.O_CREAT
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileNotFoundError:
            if expected_installation_id is not None:
                raise SafetyError("container_journal_missing") from None
            raise
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise SafetyError("journal_requires_private_directory")
            if expected_installation_id is not None:
                if opened.st_mode & 0o077:
                    raise SafetyError("journal_requires_private_directory")
                self._bound_inode = (opened.st_dev, opened.st_ino)
            else:
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        validate_journal_sidecars(self.path, harden=True)
        self.limit = limit
        self.allow_single_test = allow_single_test is True
        self.allow_public_attempt = allow_public_attempt is True
        self.allow_archive = allow_archive is True
        try:
            self.db = sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)
        except sqlite3.OperationalError:
            if expected_installation_id is not None and not self.path.exists():
                raise SafetyError("container_journal_missing") from None
            raise
        try:
            self.check_current_file()
            if expected_installation_id is not None or existing_only:
                self.check_installation_id(expected_installation_id)
            self._initialize()
            self.has_archive = True
        except BaseException:
            self.db.close()
            raise

    def check_current_file(self):
        if self._bound_inode is None:
            return
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            raise SafetyError("container_journal_missing") from None
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != self._bound_inode:
            raise SafetyError("container_journal_identity_mismatch")

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
            for name, (declaration, default) in ACTION_ADDITIONS.items():
                if name not in columns:
                    self.db.execute(f"ALTER TABLE actions ADD COLUMN {name} {declaration} DEFAULT {default}")
            if "confirmed" not in columns:
                for key, raw in self.db.execute("SELECT key,observation FROM actions").fetchall():
                    old = clean_observation(json.loads(raw))
                    confirmed = {k: True for k, v in old.items() if v is True}
                    self.db.execute("UPDATE actions SET confirmed=? WHERE key=?", (json.dumps(confirmed), key))
            self.db.execute("CREATE TABLE IF NOT EXISTS actions_archive ("
                            "key TEXT PRIMARY KEY, instance TEXT NOT NULL, hash TEXT NOT NULL, "
                            "mode TEXT NOT NULL, payload TEXT NOT NULL, archived_at REAL NOT NULL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS archive_owner_hash ON actions_archive(instance,hash)")

    def check_installation_id(self, expected):
        actual = self.installation_id()
        if expected is None and actual is not None:
            raise SafetyError("container_journal_marker_missing")
        if expected is not None and actual != expected:
            raise SafetyError("container_journal_identity_mismatch")

    def installation_id(self, *, create=False, identifier=None):
        """Keep a durable journal identity separate from live scope approval."""
        if create:
            if self.read_only:
                raise SafetyError("container_journal_identity_mismatch")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS installation_identity "
                                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL)")
                if self.db.execute("SELECT 1 FROM installation_identity").fetchone() is None:
                    self.db.execute("INSERT INTO installation_identity VALUES (1,?)",
                                    (identifier if identifier is not None else secrets.token_hex(32),))
        return read_installation_id(self.db)

    def close(self):
        self.db.close()

    def get(self, key):
        row = self.db.execute("SELECT " + self._action_projection + " FROM actions WHERE key=?", (key,)).fetchone()
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
        if row is None:
            return None
        observation = json.loads(row[3])
        confirmed = ({k: True for k, v in clean_observation(observation).items() if v is True}
                     if cold is None and self._legacy_confirmed else json.loads(row[4]))
        return {"key": key, "mode": row[0], "stage": row[1],
                "evidence": json.loads(row[2]), "observation": observation,
                "confirmed": confirmed, "current_observation": json.loads(row[5]),
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
        original_key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        key = original_key
        if mode == "preview":
            # A changed assessment gets its own revision. This never affects production keys.
            identity.append(hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest())
            key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if mode == "preview":
                legacy = self.get(original_key)
                if legacy is not None and legacy["evidence"] == value:
                    return legacy
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
            if stop_reason == "abandoned_before_dispatch" and (
                    row["mode"] not in ("single_test", "public_attempt") or row["dispatched_at"] is not None):
                raise SafetyError("invalid_journal_transition")
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
                    or current.get("blocklisted") is not False):
                raise SafetyError("cleanup_not_verified")
            if stage == "retry_superseded" and not replacement_already_observed(row):
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

    def related(self, instance, hash_value, aliases=(), *, binding=None):
        """Find overlapping identity under the same owner label or durable binding."""
        from guard import torrent_hash

        hashes = json.dumps(sorted({torrent_hash(h) for h in (*aliases, hash_value)}))
        # The read-only legacy projection can supply an empty context when
        # that column predates binding and alias evidence.
        context = "context" if "context" in self._action_projection.split(",") else "'{}'"
        active = self.db.execute(
            "SELECT key FROM actions WHERE mode IN ('single_test','public_attempt') AND "
            f"(json_extract(evidence, '$.instance')=? OR json_extract({context}, '$.binding_digest')=?) AND "
            "(json_extract(evidence, '$.hash') IN (SELECT value FROM json_each(?)) OR EXISTS ("
            f"SELECT 1 FROM json_each({context}, '$.hash_aliases') AS alias "
            "WHERE alias.value IN (SELECT value FROM json_each(?)))) LIMIT ?",
            (instance, binding, hashes, hashes, RELATED_RECORD_LIMIT + 1),
        ).fetchall()
        cold = self.db.execute(
            "SELECT key FROM actions_archive WHERE mode IN ('single_test','public_attempt') AND "
            "(instance=? OR json_extract(json_extract(payload, '$.context'), '$.binding_digest')=?) AND "
            "(hash IN (SELECT value FROM json_each(?)) OR EXISTS ("
            "SELECT 1 FROM json_each(json_extract(payload, '$.context'), '$.hash_aliases') AS alias "
            "WHERE alias.value IN (SELECT value FROM json_each(?)))) LIMIT ?",
            (instance, binding, hashes, hashes, RELATED_RECORD_LIMIT + 1),
        ).fetchall() if self.has_archive else []
        if len(active) + len(cold) > RELATED_RECORD_LIMIT:
            raise SafetyError("journal_history_limit_reached")
        return [self.get(key) for (key,) in active + cold]

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
        mutable = {"baseline_history_ids", "baseline_blocklist_ids", "window_start", "metadata_search_hold"}
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
            if "metadata_search_hold" in refreshed:
                merged.setdefault("metadata_search_hold", refreshed["metadata_search_hold"])
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
        elif observation.get("torrent_absent") is True and observation.get("blocklisted") is False:
            stage = "retry_removed"
        else:
            stage = "uncertain"
    elif row["mode"] == "public_attempt" and all(
            observation.get(k) is True for k in ("torrent_absent", "failed", "blocklisted")):
        stage = "cleanup_resolved"
    elif all(observation.get(k) is True for k in OBSERVATION_FIELDS):
        stage = "complete"
    elif known.get("torrent_absent") is True and (
            observation.get("failed") is False or observation.get("blocklisted") is False):
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
