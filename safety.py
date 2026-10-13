"""Fresh assessment and private journals; live single tests require a separate gate."""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

OBSERVATION_FIELDS = ("torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")


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
    def __init__(self, path, limit=1000, allow_single_test=False):
        self.path = Path(path)
        if self.path.is_symlink() or self.path.parent.stat().st_mode & 0o077:
            raise SafetyError("journal_requires_private_directory")
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
        self.db = sqlite3.connect(self.path, timeout=5)
        try:
            self._initialize()
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
            }
            for name, declaration in additions.items():
                if name not in columns:
                    self.db.execute("ALTER TABLE actions ADD COLUMN " + name + " " + declaration)
            if "confirmed" not in columns:
                for key, raw in self.db.execute("SELECT key,observation FROM actions").fetchall():
                    old = clean_observation(json.loads(raw))
                    confirmed = {k: True for k, v in old.items() if v is True}
                    self.db.execute("UPDATE actions SET confirmed=? WHERE key=?", (json.dumps(confirmed), key))

    def close(self):
        self.db.close()

    def get(self, key):
        row = self.db.execute("SELECT mode,stage,evidence,observation,confirmed,current_observation,"
                              "observation_available,context,dispatched_at FROM actions WHERE key=?", (key,)).fetchone()
        return None if row is None else {"key": key, "mode": row[0], "stage": row[1],
                                        "evidence": json.loads(row[2]), "observation": json.loads(row[3]),
                                        "confirmed": json.loads(row[4]), "current_observation": json.loads(row[5]),
                                        "observation_available": bool(row[6]), "context": json.loads(row[7]),
                                        "dispatched_at": row[8]}

    def prepare(self, report, mode="preview", context=None):
        if mode not in ("preview", "simulation") and not (mode == "single_test" and self.allow_single_test):
            raise SafetyError("live_execution_disabled")
        if mode == "single_test" and context is None:
            raise SafetyError("operation_context_required")
        if context is not None:
            if mode != "single_test":
                raise SafetyError("unexpected_action_context")
            from production import validate_context
            context = validate_context(context)
        value = evidence(report)
        key = hashlib.sha256(json.dumps([mode, value["instance"], value["hash"]]).encode()).hexdigest()
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

    def transition(self, key, expected, stage, observation=None):
        allowed = {
            "prepared": {"preview_verified", "cancelled", "dispatch_recorded"},
            "dispatch_recorded": {"uncertain", "replacement_pending", "manual_review", "complete"},
            "uncertain": {"uncertain", "replacement_pending", "manual_review", "complete"},
            "replacement_pending": {"uncertain", "replacement_pending", "manual_review", "complete"},
        }
        if stage not in allowed.get(expected, set()):
            raise SafetyError("invalid_journal_transition")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(key)
            if row is None or row["stage"] != expected:
                raise SafetyError("journal_stage_changed")
            if stage == "dispatch_recorded" and not (row["mode"] == "simulation" or
                    (row["mode"] == "single_test" and self.allow_single_test)):
                raise SafetyError("live_execution_disabled")
            current = {} if observation is None else clean_observation(observation)
            last_known = dict(row["observation"])
            confirmed = dict(row["confirmed"])
            for field, val in current.items():
                if val is not None:
                    last_known[field] = val
                if val is True:
                    confirmed[field] = True
            if stage == "complete" and not all(current.get(field) is True for field in OBSERVATION_FIELDS):
                raise SafetyError("completion_not_verified")
            if any(val is False and row["confirmed"].get(field) is True for field, val in current.items()):
                stage = "manual_review"
            dispatched_at = time.time() if stage == "dispatch_recorded" else row["dispatched_at"]
            self.db.execute("UPDATE actions SET stage=?,observation=?,confirmed=?,current_observation=?,"
                            "observation_available=?,updated=?,dispatched_at=? WHERE key=? AND stage=?",
                            (stage, json.dumps(last_known), json.dumps(confirmed), json.dumps(current),
                             observation is not None, time.time(), dispatched_at, key, expected))
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
    if row is None or row["mode"] not in ("simulation", "single_test"):
        raise SafetyError("live_execution_disabled")
    if row["stage"] not in ("dispatch_recorded", "uncertain", "replacement_pending"):
        return row
    try:
        observation = clean_observation(observe())
    except Exception:
        return journal.transition(key, row["stage"], "uncertain")
    known = dict(row["observation"])
    known.update({k: v for k, v in observation.items() if v is not None})
    if all(observation.get(k) is True for k in OBSERVATION_FIELDS):
        stage = "complete"
    elif known.get("torrent_absent") is True and (
            known.get("failed") is not True or known.get("blocklisted") is not True):
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
