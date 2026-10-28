"""Public Sonarr dry-run assessment. This command never sends live actions."""

import argparse
import collections
import contextlib
import datetime
import hashlib
import http.cookiejar
import json
import logging
import logging.handlers
import os
from pathlib import Path, PurePosixPath
import signal
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from reports import human_report, json_events
from workflow import preview_failure, read_readiness
from safety import Journal, SafetyError, record_preview

METADATA_TIMEOUT_SECONDS = 30 * 60


class GuardError(Exception):
    pass


@contextlib.contextmanager
def hard_deadline(deadline):
    """Linux/main-thread wall-clock bound, including DNS, headers and body reads."""
    if deadline is None:
        yield
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GuardError("run_time_limit_reached")
    def expired(signum, frame):
        raise GuardError("run_time_limit_reached")
    started = time.monotonic()
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    duration = min(remaining, previous_timer[0]) if previous_timer[0] else remaining
    signal.setitimer(signal.ITIMER_REAL, duration)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL,
                             max(0.000001, previous_timer[0] - (time.monotonic() - started)),
                             previous_timer[1])


def endpoint_key(url, origin_only=False):
    """Conservative origin + base-path identity with normalized default ports."""
    try:
        value = urllib.parse.urlsplit(url)
        if (value.scheme not in ("http", "https") or not value.hostname
                or value.username or value.password
                or (not origin_only and (value.query or value.fragment))):
            raise ValueError()
        port = value.port if value.port is not None else (443 if value.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        return value.scheme, value.hostname, port, value.path.rstrip("/")
    except (ValueError, TypeError, AttributeError):
        raise GuardError("invalid_endpoint") from None


def verify_client_binding(instance, monitored_url, client):
    binding = instance.get("download_client_binding")
    if (not isinstance(binding, dict) or not integer(binding.get("id"))
            or binding["id"] <= 0 or binding["id"] != client.get("id")):
        raise GuardError("missing_or_wrong_downloader_binding")
    pinned = endpoint_key(binding.get("endpoint"))
    if pinned != endpoint_key(monitored_url):
        raise GuardError("monitored_downloader_binding_mismatch")
    fields = {f.get("name"): f.get("value") for f in client.get("fields", [])
              if isinstance(f, dict)}
    host, port, ssl = fields.get("host"), fields.get("port"), fields.get("useSsl")
    base = fields.get("urlBase") or ""
    if (not isinstance(host, str) or not host or not integer(port) or not 1 <= port <= 65535
            or not isinstance(ssl, bool) or not isinstance(base, str)
            or "/" in host or "@" in host or "?" in host or "#" in host):
        raise GuardError("invalid_sonarr_downloader_endpoint")
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    actual = ("https" if ssl else "http") + "://" + host + ":" + str(port)
    if base:
        actual += "/" + base.lstrip("/")
    if endpoint_key(actual) != pinned:
        raise GuardError("sonarr_downloader_binding_mismatch")


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Protect initial/new log files and any existing rotated backups."""
    def __init__(self, filename, maxBytes=1024*1024, backupCount=3):
        for path in [Path(filename), *(Path(str(filename) + "." + str(n))
                                      for n in range(1, backupCount + 1))]:
            if path.is_symlink():
                raise GuardError("log_symlink_refused")
            if path.exists():
                path.chmod(0o600)
        super().__init__(filename, maxBytes=maxBytes, backupCount=backupCount, encoding="utf-8")

    def _open(self):
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.baseFilename, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding)
        except BaseException:
            os.close(fd)
            raise


def load_batch_state(path):
    try:
        if not path.exists():
            return {}
        state = json.loads(path.read_text())
        if not isinstance(state, dict) or set(state) - {"after", "recovery_after"}:
            raise ValueError()
        if "after" in state:
            after = state["after"]
            if (not isinstance(after, list) or len(after) != 2
                    or not isinstance(after[0], str) or not after[0]):
                raise ValueError()
            torrent_hash(after[1])
        if "recovery_after" in state:
            from safety import valid_digest
            if not valid_digest(state["recovery_after"]):
                raise ValueError()
        return state
    except (ValueError, TypeError, AttributeError, OSError, GuardError):
        raise GuardError("invalid_batch_state") from None


def save_batch_state(path, state):
    if not state:
        return
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".batch-")
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(state, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


HISTORY_EVENT_TYPES = {
    1: "grabbed", 2: "seriesFolderImported", 3: "downloadFolderImported",
    4: "downloadFailed", 5: "episodeFileDeleted", 6: "episodeFileRenamed", 7: "downloadIgnored",
}


def history_event_type(row):
    """Normalize known Sonarr enums without bool/float numeric coercion."""
    value = row.get("eventType")
    if integer(value) and value in HISTORY_EVENT_TYPES:
        return HISTORY_EVENT_TYPES[value]
    if isinstance(value, str) and value in HISTORY_EVENT_TYPES.values():
        return value
    raise GuardError("invalid_history_event_type")


def torrent_hash(value):
    if not isinstance(value, str) or len(value) not in (40, 64):
        raise GuardError("missing_or_invalid_hash")
    if any(c not in "0123456789abcdefABCDEF" for c in value):
        raise GuardError("missing_or_invalid_hash")
    return value.lower()


def assess_files(files):
    """Return failure reasons only for a structurally valid full manifest."""
    if not isinstance(files, list) or not files:
        raise GuardError("empty_or_invalid_manifest")
    indexes = set()
    selected = []
    dangerous = set()
    for item in files:
        if not isinstance(item, dict):
            raise GuardError("invalid_manifest_entry")
        name, index = item.get("name"), item.get("index")
        priority, size, progress = item.get("priority"), item.get("size"), item.get("progress")
        if (not isinstance(name, str) or not name or "\x00" in name
                or not integer(index) or index < 0 or index in indexes
                or not integer(priority) or priority not in (0, 1, 6, 7)
                or not integer(size) or size < 0
                or isinstance(progress, bool) or not isinstance(progress, (int, float))
                or not 0 <= progress <= 1):
            raise GuardError("invalid_manifest_entry")
        indexes.add(index)
        suffix = PurePosixPath(name.replace("\\", "/")).suffix.casefold()
        if suffix in (".exe", ".scr"):
            dangerous.add(suffix)
        if priority:
            selected.append(suffix)
    if indexes != set(range(len(files))):
        raise GuardError("incomplete_manifest_indexes")
    reasons = ["contains_" + s[1:] for s in sorted(dangerous)]
    if not selected:
        reasons.append("all_files_unselected")
    elif all(s in (".txt", ".nfo") for s in selected):
        reasons.append("only_txt_nfo_selected")
    return reasons


class Api:
    def __init__(self, config, timeout=15, deadline=None):
        self.config = config
        self.timeout = timeout
        self.deadline = deadline
        self.opener = urllib.request.build_opener(
            SameOriginRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, route, params=None, login=False):
        with hard_deadline(self.deadline):
            return self._call(route, params, login)

    def _call(self, route, params=None, login=False):
        base = self.config["url"].rstrip("/")
        url = base + route
        headers, data = {}, None
        if login:
            # This is the only permitted POST: session authentication.
            if route != "/api/v2/auth/login":
                raise GuardError("mutation_forbidden")
            data = urllib.parse.urlencode({
                "username": self.config["username"],
                "password": self.config["password"],
            }).encode()
            headers["Referer"] = base + "/"
        else:
            if params:
                url += "?" + urllib.parse.urlencode(params)
            if "api_key" in self.config:
                headers["X-Api-Key"] = self.config["api_key"]
        try:
            timeout = self.timeout
            if self.deadline is not None:
                timeout = min(timeout, self.deadline - time.monotonic())
                if timeout <= 0:
                    raise GuardError("run_time_limit_reached")
            with self.opener.open(urllib.request.Request(url, headers=headers, data=data),
                                  timeout=timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise GuardError("response_too_large")
            if login:
                return None
            if route == "/api/v2/app/webapiVersion":
                version = raw.decode().strip()
                if not version or any(c not in "0123456789." for c in version):
                    raise GuardError("authentication_not_verified")
                return version
            return json.loads(raw)
        except GuardError:
            raise
        except Exception:
            # Exception strings can contain endpoints or credentials: never log them.
            raise GuardError("api_request_or_response_failed") from None

    def login(self):
        self.call("/api/v2/auth/login", login=True)
        # Verify the session rather than depending on response body or cookie name.
        result = self.call("/api/v2/app/webapiVersion")
        return result


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if endpoint_key(req.full_url, True)[:3] != endpoint_key(newurl, True)[:3]:
            raise GuardError("cross_origin_redirect_refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def records(api, route, params=None, max_pages=20):
    result, expected = [], None
    params = dict(params or {})
    for page in range(1, max_pages + 1):
        payload = api.call(route, dict(params, page=page, pageSize=100))
        if not isinstance(payload, dict):
            raise GuardError("invalid_paginated_response")
        total, rows = payload.get("totalRecords"), payload.get("records")
        if (not integer(total) or total < 0 or not isinstance(rows, list)
                or any(not isinstance(r, dict) for r in rows)):
            raise GuardError("invalid_paginated_response")
        if expected is None:
            expected = total
        if expected != total:
            raise GuardError("response_changed_during_pagination")
        result.extend(rows)
        if len(result) == total:
            ids = [r.get("id") for r in result]
            if any(not integer(i) for i in ids) or len(set(ids)) != len(ids):
                raise GuardError("duplicate_or_invalid_response_ids")
            return result
        if len(result) > total or not rows:
            raise GuardError("incomplete_paginated_response")
    raise GuardError("pagination_limit_reached")


def source_policy_key(policy):
    """Validate and canonicalize the explicit per-owner source policy."""
    if not isinstance(policy, dict):
        raise GuardError("invalid_source_lists")
    mode = policy.get("mode", "public_allowlist")
    if mode not in ("public_allowlist", "private_exclusions"):
        raise GuardError("invalid_source_policy")
    result = {"mode": mode}
    for kind in ("public", "private"):
        values = policy.get(kind, [] if kind == "public" and mode == "private_exclusions" else None)
        if not isinstance(values, list) or any(not isinstance(x, str) or not x.strip() for x in values):
            raise GuardError("invalid_source_lists")
        result[kind] = sorted(values)
    if mode == "public_allowlist" and set(result["public"]) & set(result["private"]):
        raise GuardError("overlapping_source_lists")
    return result


def classify_source(policy, source):
    policy = source_policy_key(policy)
    if not isinstance(source, str) or not source.strip():
        return "unknown"
    if policy["mode"] == "private_exclusions":
        if source.strip().casefold() in {name.strip().casefold() for name in policy["private"]}:
            return "private"
        return "public"
    if source in policy["private"]:
        return "private"
    return "public" if source in policy["public"] else "unknown"


def source_for(api, hash_value, rows, max_pages, added=None):
    history = records(api, "/api/v3/history", {
        # Preserve Sonarr's original spelling for its case-sensitive DB filter.
        "eventType": 1, "downloadId": rows[0]["downloadId"],
        "sortKey": "date", "sortDirection": "descending",
    }, max_pages)
    matches = []
    for grab in history:
        if str(grab.get("downloadId", "")).lower() != hash_value:
            continue
        if history_event_type(grab) != "grabbed":
            continue
        if any(not integer(grab.get(field)) or grab[field] <= 0 for field in ("seriesId", "episodeId")):
            raise GuardError("unknown_content_identity")
        matches.append(grab)
    if not matches:
        raise GuardError("no_sonarr_grab_history")
    sources, grab_ids, grab_times = set(), set(), []
    for row in rows:
        series_id, episode_id = row.get("seriesId"), row.get("episodeId")
        if not integer(series_id) or series_id <= 0 or not integer(episode_id) or episode_id <= 0:
            raise GuardError("unknown_content_identity")
        matching = [r for r in matches if r.get("seriesId") == series_id
                    and r.get("episodeId") == episode_id]
        if not matching:
            raise GuardError("content_identity_not_in_grab_history")
        # A repeated hash can have older grabs from other sources. Bind only
        # the newest grab for each affected episode to this download incarnation.
        latest = max(matching, key=lambda r: r["id"])
        try:
            stamp = datetime.datetime.fromisoformat(latest["date"].replace("Z", "+00:00"))
            if stamp.tzinfo is None or added is None or abs(stamp.timestamp() - added) > 120:
                raise ValueError()
        except (KeyError, TypeError, AttributeError, ValueError):
            raise GuardError("grab_not_bound_to_current_download") from None
        matching = [latest]
        grab_ids.add(latest["id"])
        grab_times.append(stamp.timestamp())
        for r in matching:
            data = r.get("data")
            if (not isinstance(data, dict) or not isinstance(data.get("indexer"), str)
                    or not data["indexer"].strip()):
                raise GuardError("missing_indexer_identity")
            sources.add(data["indexer"])
    if len(sources) != 1 or not next(iter(sources)):
        raise GuardError("ambiguous_indexer_identity")
    return next(iter(sources)), sorted(grab_ids), min(grab_times)


def run(config, qb, sonarr_apis, now=None, batch_state=None, include_titles=False, target=None):
    """Return one report per matched torrent. Every action is a proposal only."""
    now = time.time() if now is None else now
    maximum = config.get("max_torrents_per_run", 100)
    max_pages = config.get("max_pages", 20)
    minimum_age = config.get("minimum_age_seconds", 120)
    reports, queues, clients = [], {}, {}
    torrents = qb.call("/api/v2/torrents/info")
    if not isinstance(torrents, list) or any(not isinstance(t, dict) for t in torrents):
        raise GuardError("invalid_torrent_response")
    by_hash = {}
    for t in torrents:
        h = torrent_hash(t.get("hash"))
        if h in by_hash:
            raise GuardError("duplicate_torrent_hash")
        by_hash[h] = t
    owners = collections.defaultdict(set)
    for label, api in sonarr_apis.items():
        queues[label] = records(api, "/api/v3/queue", {
            "includeUnknownSeriesItems": "true",
            "includeSeries": "true", "includeEpisode": "true",
        }, max_pages)
        clients[label] = api.call("/api/v3/downloadclient")
        if not isinstance(clients[label], list):
            raise GuardError("invalid_client_response")
        for row in queues[label]:
            try:
                owners[torrent_hash(row.get("downloadId"))].add(label)
            except GuardError:
                pass
    candidates = []
    for label, api in sonarr_apis.items():
        instance = config["sonarr"][label]
        category = instance["category"]
        grouped = collections.defaultdict(list)
        for row in queues[label]:
            try:
                grouped[torrent_hash(row.get("downloadId"))].append(row)
            except GuardError:
                continue
        for h, rows in grouped.items():
            if target is not None and (label, h) != target:
                continue
            report = {"instance": label, "hash": h, "dry_run": True}
            try:
                if owners[h] != {label}:
                    raise GuardError("ambiguous_instance_ownership")
                t = by_hash.get(h)
                if not t or t.get("category") != category:
                    raise GuardError("missing_torrent_or_wrong_category")
                binding = instance.get("download_client_binding")
                if (not isinstance(binding, dict) or not integer(binding.get("id"))
                        or binding["id"] <= 0):
                    raise GuardError("missing_or_wrong_downloader_binding")
                compatible = [x for x in clients[label] if isinstance(x, dict)
                              and integer(x.get("id")) and x["id"] == binding["id"]
                              and x.get("enable") is True and x.get("implementation") == "QBittorrent"
                              and any(isinstance(f, dict) and f.get("name") == "tvCategory"
                                      and f.get("value") == category for f in x.get("fields", []))]
                if len(compatible) != 1:
                    raise GuardError("ambiguous_download_client")
                client = compatible[0]
                verify_client_binding(instance, config["qbittorrent"]["url"], client)
                for row in rows:
                    cid, cname = row.get("downloadClientId"), row.get("downloadClient")
                    if cid is not None and (not integer(cid) or cid <= 0 or cid != client["id"]):
                        raise GuardError("wrong_download_client")
                    if cid is None and (not cname or cname != client.get("name")):
                        raise GuardError("unconfirmed_download_client")
                candidates.append((label, h, rows, t, report))
            except GuardError as e:
                report.update(decision="skip", reason=str(e))
                reports.append(report)

    # Only scoped ownership candidates consume work. A durable key cursor rotates
    # fairly across both instances and survives restarts and queue reordering.
    candidates.sort(key=lambda entry: entry[:2])
    after = tuple((batch_state or {}).get("after", ()))
    if after:
        candidates = ([x for x in candidates if x[:2] > after]
                      + [x for x in candidates if x[:2] <= after])
    for number, (label, h, rows, t, report) in enumerate(candidates):
        if number >= maximum:
            report.update(decision="skip", reason="work_limit_reached")
            reports.append(report)
            continue
        api, instance = sonarr_apis[label], config["sonarr"][label]
        try:
            added = t.get("added_on")
            if not integer(added) or added <= 0 or now - added < minimum_age:
                raise GuardError("torrent_too_new_or_age_unknown")
            source, grab_ids, grab_time_floor = source_for(api, h, rows, max_pages, added)
            classification = classify_source(instance["indexers"], source)
            if classification == "private":
                raise GuardError("private_source_protected")
            if classification != "public":
                raise GuardError("unclassified_source_protected")
            state = t.get("state", "")
            safe_states = {"downloading", "stalledDL", "queuedDL", "pausedDL", "stoppedDL",
                           "uploading", "stalledUP", "queuedUP", "pausedUP", "stoppedUP",
                           "forcedDL", "forcedUP"}
            metadata_pending = state in {"metaDL", "forcedMetaDL"}
            if metadata_pending:
                if now - added < METADATA_TIMEOUT_SECONDS:
                    raise GuardError("metadata_timeout_not_reached")
                if (isinstance(t.get("progress"), bool) or t.get("progress") != 0
                        or not integer(t.get("total_size")) or t["total_size"] not in (-1, 0)):
                    raise GuardError("metadata_state_inconsistent")
            elif state not in safe_states:
                raise GuardError("metadata_or_transitional_state")
            files = qb.call("/api/v2/torrents/files", {"hash": h})
            if metadata_pending:
                if files != []:
                    raise GuardError("metadata_state_inconsistent")
                reasons = ["metadata_timeout"]
            else:
                reasons = assess_files(files)
            report.update(decision="would_fail" if reasons else "keep", reasons=reasons)
            report.update(public_source_confirmed=True, indexer=source,
                          queue_ids=sorted({r["id"] for r in rows}),
                          download_id_spelling=rows[0]["downloadId"],
                          series_ids=sorted({r["seriesId"] for r in rows}),
                          episode_ids=sorted({r["episodeId"] for r in rows}),
                          download_client_id=instance["download_client_binding"]["id"],
                          file_count=len(files), selected_file_count=sum(f["priority"] > 0 for f in files),
                          torrent_state=state)
            report["download_added_on"] = added
            report["grab_ids"] = grab_ids
            report["grab_time_floor"] = grab_time_floor
            report["attempt_fingerprint"] = hashlib.sha256(
                json.dumps([label, h, added, grab_ids]).encode()).hexdigest()
            ownership = {"instance": label, "hash": h, "category": instance["category"], "indexer": source,
                         "source_policy": source_policy_key(instance["indexers"]),
                         "client_id": report["download_client_id"],
                         "sonarr_endpoint": endpoint_key(instance["url"]),
                         "endpoint": endpoint_key(config["qbittorrent"]["url"]),
                         "attempt": report["attempt_fingerprint"],
                         "grab_time_floor": grab_time_floor,
                         "identity": sorted((r["id"], r["seriesId"], r["episodeId"]) for r in rows)}
            manifest = [{k: f[k] for k in ("index", "name", "size", "priority")}
                        for f in sorted(files, key=lambda f: f["index"])]
            if metadata_pending:
                manifest = {"metadata_pending": True, "timeout_seconds": METADATA_TIMEOUT_SECONDS}
            report["ownership_fingerprint"] = hashlib.sha256(
                json.dumps(ownership, sort_keys=True).encode()).hexdigest()
            report["manifest_fingerprint"] = hashlib.sha256(
                json.dumps(manifest, sort_keys=True).encode()).hexdigest()
            report["checked_at"] = time.time() if now is None else now
            if include_titles and isinstance(t.get("name"), str):
                report["title"] = t["name"]
            if reasons:
                report["proposed_actions"] = [
                    "blocklist_release_in_owning_sonarr",
                    "remove_torrent_and_data_through_sonarr",
                    "obtain_targeted_replacement_after_retry_settings_verified",
                ]
                if reasons == ["metadata_timeout"]:
                    report["proposed_actions"] = [
                        "remove_torrent_and_data_through_sonarr_without_blocklisting",
                        "request_owning_sonarr_episode_search_after_confirmed_removal_and_final_checks",
                    ]
                report["live_prerequisite"] = "fresh_ownership_source_and_manifest_recheck"
        except GuardError as e:
            report.update(decision="skip", reason=str(e))
        if batch_state is not None:
            batch_state["after"] = [label, h]
        reports.append(report)
    return reports


def recheck_candidate(original, config, qb, apis):
    """Refetch both queues and the target's complete ownership/manifest evidence."""
    target = (original["instance"], torrent_hash(original["hash"]))
    reports = run(config, qb, apis, target=target)
    if len(reports) != 1 or reports[0].get("decision") != "would_fail":
        raise SafetyError("candidate_no_longer_eligible")
    readiness = read_readiness({target[0]: apis[target[0]]})[target[0]]
    return {"assessment": reports[0], "readiness": readiness}


def load_config(path):
    try:
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise GuardError("config_permissions_must_be_private")
        config = json.loads(path.read_text())
        if config.get("dry_run") is not True:
            raise GuardError("only_dry_run_supported")
        if not isinstance(config.get("sonarr"), dict) or not config["sonarr"]:
            raise GuardError("missing_sonarr_configuration")
        for key, default, limit in (("max_torrents_per_run", 100, 1000), ("max_pages", 20, 100),
                                    ("minimum_age_seconds", 120, 86400)):
            val = config.get(key, default)
            if not integer(val) or not 1 <= val <= limit:
                raise GuardError("invalid_work_limits")
        categories = set()
        for item in config["sonarr"].values():
            if not item.get("api_key") or not isinstance(item.get("category"), str) or not item["category"]:
                raise GuardError("invalid_sonarr_configuration")
            if item["category"] in categories:
                raise GuardError("duplicate_instance_category")
            categories.add(item["category"])
            source_policy_key(item["indexers"])
            binding = item.get("download_client_binding")
            if (not isinstance(binding, dict) or not integer(binding.get("id"))
                    or binding["id"] <= 0):
                raise GuardError("missing_or_wrong_downloader_binding")
            if endpoint_key(binding.get("endpoint")) != endpoint_key(config["qbittorrent"]["url"]):
                raise GuardError("monitored_downloader_binding_mismatch")
        for item in [config["qbittorrent"], *config["sonarr"].values()]:
            url = urllib.parse.urlsplit(item["url"])
            if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise GuardError("invalid_endpoint")
        if not config["qbittorrent"].get("username") or not config["qbittorrent"].get("password"):
            raise GuardError("missing_qbittorrent_credentials")
        return config
    except GuardError:
        raise
    except Exception:
        raise GuardError("invalid_or_missing_configuration") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--show-titles", action="store_true", help="Show escaped release titles in text stdout only")
    parser.add_argument("--check-safeguards", action="store_true",
                        help="Read-only fresh rechecks recorded in an external preview journal")
    args = parser.parse_args()
    if args.show_titles and args.format != "text":
        parser.error("--show-titles requires --format text")
    try:
        config = load_config(args.config)
        # Lock lives beside the external config, never in the repository.
        import fcntl
        with open(args.config.parent / "guard.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError("another_run_is_active") from None
            logger = logging.getLogger("guard")
            logger.setLevel(logging.INFO)
            if args.log_file:
                handler = PrivateRotatingFileHandler(args.log_file)
                logger.addHandler(handler)
            qb = Api(config["qbittorrent"])
            deadline = time.monotonic() + 180
            qb.deadline = deadline
            qb.login()
            batch_path = args.config.parent / "batch-state.json"
            batch_state = load_batch_state(batch_path)
            apis = {name: Api(c, deadline=deadline) for name, c in config["sonarr"].items()}
            try:
                with hard_deadline(deadline):
                    readiness = read_readiness(apis)
                    reports = run(config, qb, apis, batch_state=batch_state, include_titles=args.show_titles)
                    if args.check_safeguards:
                        journal = Journal(args.config.parent / "action-journal.sqlite3")
                        try:
                            for report in reports:
                                if report["decision"] != "would_fail":
                                    continue
                                try:
                                    row = record_preview(journal, report, lambda: recheck_candidate(report, config, qb, apis))
                                    report["safeguards"] = {"status": row["stage"], "live_enabled": False}
                                except (SafetyError, GuardError) as e:
                                    report["safeguards"] = {"status": "blocked", "reason": str(e), "live_enabled": False}
                        finally:
                            journal.close()
            finally:
                # Preserve completed assessments even if a later request aborts.
                save_batch_state(batch_path, batch_state)
            stamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
            for report in reports:
                if report["decision"] == "would_fail":
                    report["workflow"] = preview_failure(report, readiness.get(report["instance"], {}))
            if args.format == "text":
                print(human_report(reports, readiness, stamp))
            for event in json_events(reports, readiness, stamp):
                line = json.dumps(event)
                if args.format == "json":
                    print(line)
                if args.log_file:
                    logger.info(line)
        return 0
    except (GuardError, SafetyError) as e:
        print(json.dumps({"dry_run": True, "error": str(e)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"dry_run": True, "error": "unexpected_failure_no_actions_performed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
