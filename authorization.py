"""Explicit routine permission; ongoing authority must be separately selected."""

import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

from guard import (endpoint_key, METADATA_TIMEOUT_SECONDS, source_policy_key, classify_source,
                   unique_config_keys)
from safety import SafetyError, valid_digest

RULE = "public-sonarr-cleanup-v3"
MAX_TRIAL_SECONDS = 7 * 24 * 60 * 60
SOURCE_FILES = ("guard.py", "production.py", "safety.py", "maintenance.py", "public.py",
                "authorization.py", "routine.py", "workflow.py", "reports.py", "container_worker.py")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def code_digest():
    root = Path(__file__).parent
    return digest({name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_FILES})


def scope_digest(config):
    scope = {"qbittorrent": endpoint_key(config["qbittorrent"]["url"]), "instances": {}}
    for name, item in config["sonarr"].items():
        scope["instances"][name] = {"url": endpoint_key(item["url"]), "category": item["category"],
            "client_id": item["download_client_binding"]["id"],
            "client_endpoint": endpoint_key(item["download_client_binding"]["endpoint"]),
            **source_policy_key(item["indexers"])}
    scope["minimum_age"] = config.get("minimum_age_seconds", 120)
    scope["work_limit"] = config.get("max_torrents_per_run", 100)
    scope["page_limit"] = config.get("max_pages", 20)
    scope["metadata_timeout_seconds"] = METADATA_TIMEOUT_SECONDS
    scope["metadata_retry_strategy"] = "remove-then-episode-search-without-blocklist"
    return digest(scope)


def read_grant(path):
    try:
        if path.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise ValueError()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as file:
            mode = os.fstat(file.fileno()).st_mode
            if not stat.S_ISREG(mode) or mode & 0o077:
                raise ValueError()
            data = file.read(8193)
        if len(data) > 8192:
            raise ValueError()
        return json.loads(data, object_pairs_hook=unique_config_keys)
    except Exception:
        raise SafetyError("routine_authorization_unavailable") from None


class RoutineAuthorization:
    def __init__(self, value, config):
        fields = {"enabled", "rule", "grant_id", "issued_at", "expires_at", "scope_digest", "code_digest"}
        if (not isinstance(value, dict)
                or set(value) not in (fields, fields | {"authorization_mode"},
                                      fields | {"authorization_mode", "allow_code_updates"})
                or ("authorization_mode" in value and value["authorization_mode"] != "ongoing")
                or (value.get("authorization_mode") == "ongoing" and value["expires_at"] is not None)
                or ("allow_code_updates" in value and value["allow_code_updates"] is not True)):
            raise SafetyError("routine_authorization_invalid")
        self.value = json.loads(json.dumps(value))
        self.identifier = digest(self.value)
        self._path = None
        # The explicit ongoing mode authorizes the configured scope across releases.
        if self.value.get("authorization_mode") != "ongoing" and self.value["code_digest"] != code_digest():
            raise SafetyError("routine_code_not_authorized")
        self.validate(config)

    def validate(self, config, report=None):
        if self._path is not None:
            try:
                current = read_grant(self._path)
            except SafetyError:
                raise SafetyError("routine_authorization_revoked_or_changed") from None
            if digest(current) != self.identifier:
                raise SafetyError("routine_authorization_revoked_or_changed")
        v = self.value
        now = time.time()
        ongoing = v.get("authorization_mode") == "ongoing"
        times = (v["issued_at"],) if ongoing else (v["issued_at"], v["expires_at"])
        time_invalid = any(isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t)
                           for t in times)
        if not time_invalid:
            if ongoing:
                time_invalid = v["issued_at"] > now or v["expires_at"] is not None
            else:
                time_invalid = (not v["issued_at"] <= now < v["expires_at"] or
                    not 0 < v["expires_at"] - v["issued_at"] <= MAX_TRIAL_SECONDS)
        if (digest(v) != self.identifier or v["enabled"] is not True or v["rule"] != RULE
                or not valid_digest(v["grant_id"]) or not valid_digest(v["code_digest"])
                or not valid_digest(v["scope_digest"])
                or time_invalid
                or v["scope_digest"] != scope_digest(config)
                or config.get("minimum_age_seconds", 120) < 120):
            raise SafetyError("routine_authorization_expired_or_scope_changed")
        if report is not None and (report.get("instance") not in config["sonarr"]
                or report.get("decision") != "would_fail" or report.get("public_source_confirmed") is not True
                or classify_source(config["sonarr"][report["instance"]]["indexers"], report.get("indexer")) != "public"):
            raise SafetyError("routine_candidate_not_authorized")

    def execution_expiry(self):
        """Even an ongoing grant delegates at most 120 seconds to one action."""
        expiry = time.time() + 120
        return expiry if self.value.get("authorization_mode") == "ongoing" else min(expiry, self.value["expires_at"])

    @classmethod
    def load(cls, path, config):
        path = Path(path).absolute()
        authority = cls(read_grant(path), config)
        authority._path = path
        return authority
