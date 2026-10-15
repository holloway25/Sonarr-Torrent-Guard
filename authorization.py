"""Explicit, expiring routine permission; never inferred from test approvals."""

import hashlib
import json
import math
from pathlib import Path
import time

from guard import endpoint_key, METADATA_TIMEOUT_SECONDS
from safety import SafetyError, valid_digest

RULE = "public-sonarr-cleanup-v3"
MAX_TRIAL_SECONDS = 7 * 24 * 60 * 60
SOURCE_FILES = ("guard.py", "production.py", "safety.py", "maintenance.py", "public.py",
                "authorization.py", "routine.py", "workflow.py", "reports.py")


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
            "public": sorted(item["indexers"]["public"]), "private": sorted(item["indexers"]["private"])}
    scope["minimum_age"] = config.get("minimum_age_seconds", 120)
    scope["work_limit"] = config.get("max_torrents_per_run", 100)
    scope["page_limit"] = config.get("max_pages", 20)
    scope["metadata_timeout_seconds"] = METADATA_TIMEOUT_SECONDS
    scope["metadata_retry_strategy"] = "remove-then-episode-search-without-blocklist"
    return digest(scope)


class RoutineAuthorization:
    def __init__(self, value, config):
        fields = {"enabled", "rule", "grant_id", "issued_at", "expires_at", "scope_digest", "code_digest"}
        if not isinstance(value, dict) or set(value) != fields:
            raise SafetyError("routine_authorization_invalid")
        self.value = json.loads(json.dumps(value))
        self.identifier = digest(self.value)
        if self.value["code_digest"] != code_digest():
            raise SafetyError("routine_code_not_authorized")
        self.validate(config)

    def validate(self, config, report=None):
        v = self.value
        now = time.time()
        times = (v["issued_at"], v["expires_at"])
        if (digest(v) != self.identifier or v["enabled"] is not True or v["rule"] != RULE
                or not valid_digest(v["grant_id"]) or not valid_digest(v["code_digest"])
                or not valid_digest(v["scope_digest"])
                or any(isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) for t in times)
                or not v["issued_at"] <= now < v["expires_at"]
                or not 0 < v["expires_at"] - v["issued_at"] <= MAX_TRIAL_SECONDS
                or v["scope_digest"] != scope_digest(config)
                or config.get("minimum_age_seconds", 120) < 120):
            raise SafetyError("routine_authorization_expired_or_scope_changed")
        if report is not None and (report.get("instance") not in config["sonarr"]
                or report.get("decision") != "would_fail" or report.get("public_source_confirmed") is not True
                or report.get("indexer") not in config["sonarr"][report["instance"]]["indexers"]["public"]):
            raise SafetyError("routine_candidate_not_authorized")

    @classmethod
    def load(cls, path, config):
        path = Path(path)
        try:
            if path.is_symlink() or path.stat().st_mode & 0o077 or path.parent.stat().st_mode & 0o077:
                raise ValueError()
            if path.stat().st_size > 8192:
                raise ValueError()
            return cls(json.loads(path.read_text()), config)
        except SafetyError:
            raise
        except Exception:
            raise SafetyError("routine_authorization_unavailable") from None
