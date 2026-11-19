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
import stat
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from reports import human_report, json_events
from workflow import preview_failure, read_readiness
from safety import Journal, SafetyError, open_lock_file, record_preview

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
        # urlsplit strips some controls before exposing the hostname.
        if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
            raise ValueError()
        value = urllib.parse.urlsplit(url)
        if (value.scheme not in ("http", "https") or not value.hostname
                or value.username is not None or value.password is not None
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
    required = ("host", "port", "useSsl", "urlBase", "tvCategory")
    raw_fields = client.get("fields")
    if not isinstance(raw_fields, list) or any(not isinstance(f, dict) for f in raw_fields):
        raise GuardError("invalid_sonarr_downloader_endpoint")
    fields = {}
    for field in raw_fields:
        name = field.get("name")
        if name not in required:
            continue
        if name in fields:
            raise GuardError("invalid_sonarr_downloader_endpoint")
        fields[name] = field.get("value")
    if set(fields) != set(required):
        raise GuardError("invalid_sonarr_downloader_endpoint")
    host, port, ssl, base, category = (fields[name] for name in required)
    if (not isinstance(host, str) or not host or not integer(port) or not 1 <= port <= 65535
            or not isinstance(ssl, bool) or (base is not None and not isinstance(base, str))
            or "/" in host or "@" in host or "?" in host or "#" in host):
        raise GuardError("invalid_sonarr_downloader_endpoint")
    if not isinstance(category, str) or category != instance["category"]:
        raise GuardError("ambiguous_download_client")
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    actual = ("https" if ssl else "http") + "://" + host + ":" + str(port)
    if base:
        actual += "/" + base.lstrip("/")
    if endpoint_key(actual) != pinned:
        raise GuardError("sonarr_downloader_binding_mismatch")


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Protect initial/new log files and any existing rotated backups."""
    def __init__(self, filename, maxBytes=1024*1024, backupCount=3, *,
                 config_path=None, authorization_path=None):
        paths = [Path(filename), *(Path(f"{filename}.{n}") for n in range(1, backupCount + 1))]
        reserved = set()
        if config_path is not None:
            state_files = ("connections.json", ".connections-validation.json", "guard.lock", "batch-state.json",
                           "routine-authorization.json", "container-live-scope.json", "container-status.json",
                           "container-live-journal.json", "preview-journal.sqlite3", "preview-journal.sqlite3-journal",
                           "preview-journal.sqlite3-wal", "preview-journal.sqlite3-shm",
                           "container-worker.lock", "action-journal.sqlite3", "action-journal.sqlite3-journal",
                           "action-journal.sqlite3-wal", "action-journal.sqlite3-shm")
            reserved = {(config_path.parent / name).resolve() for name in state_files}
            reserved.add(config_path.resolve())
        if authorization_path is not None:
            reserved.add(authorization_path.resolve())
        for path in paths:
            if path.is_symlink():
                raise GuardError("log_symlink_refused")
            if path.resolve() in reserved:
                raise GuardError("log_destination_reserved")
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise GuardError("log_destination_not_private_file")
        for path in paths:
            if path.exists():
                path.chmod(0o600)
        super().__init__(filename, maxBytes=maxBytes, backupCount=backupCount, encoding="utf-8")

    def _open(self):
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.baseFilename, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise GuardError("log_destination_not_private_file")
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding)
        except BaseException:
            os.close(fd)
            raise


IDENTITY_CACHE_LIMIT = 10000
IDENTITY_CACHE_SECONDS = 3600


@contextlib.contextmanager
def open_regular_file(path, *, nofollow=False):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if nofollow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), encoding="utf-8") as file:
        mode = os.fstat(file.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise ValueError("regular_file_required")
        yield file, mode


def load_batch_state(path):
    try:
        with open_regular_file(path, nofollow=True) as (file, mode):
            state = json.load(file)
        if not isinstance(state, dict) or set(state) - {
                "after", "timed_out", "verification_after", "dispatch_after", "recovery_after", "identity_cache"}:
            raise ValueError()
        for key in ("after", "timed_out", "verification_after", "dispatch_after"):
            if key not in state:
                continue
            cursor = state[key]
            if (not isinstance(cursor, list) or len(cursor) != 2
                    or not isinstance(cursor[0], str) or not cursor[0].strip()):
                raise ValueError()
            torrent_hash(cursor[1])
        if "identity_cache" in state:
            if os.name != "nt" and mode & 0o077:
                raise GuardError("invalid_batch_state")
            validate_identity_cache(state["identity_cache"])
        if "recovery_after" in state:
            from safety import valid_digest
            if not valid_digest(state["recovery_after"]):
                raise ValueError()
        return state
    except FileNotFoundError:
        return {}
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
            return json.loads(raw, object_pairs_hook=unique_response_keys)
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


def records(api, route, params=None, max_pages=20, *, since=None, on_page=None):
    result, expected = [], None
    seen_ids = set()
    received = 0
    previous_date = None
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
        received += len(rows)
        if received > total or (not rows and received != total):
            raise GuardError("incomplete_paginated_response")
        if since is not None and received < total and len(rows) != 100:
            raise GuardError("incomplete_paginated_response")
        relevant = []
        for row in rows:
            identifier = row.get("id")
            if not integer(identifier) or identifier in seen_ids:
                raise GuardError("duplicate_or_invalid_response_ids")
            seen_ids.add(identifier)
            if since is not None:
                stamp = grab_timestamp(row)
                if previous_date is not None and stamp > previous_date:
                    raise GuardError("response_changed_during_pagination")
                previous_date = stamp
                if stamp < since:
                    continue
            relevant.append(row)
        if on_page is not None:
            on_page(relevant)
        result.extend(relevant)
        if received == total or (since is not None and previous_date is not None and previous_date < since):
            return result
    raise GuardError("pagination_limit_reached")


def private_source_key(name):
    return name.strip().casefold()


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
    if {private_source_key(name) for name in result["public"]} & {
            private_source_key(name) for name in result["private"]}:
        raise GuardError("overlapping_source_lists")
    return result


def classify_source(policy, source):
    policy = source_policy_key(policy)
    if not isinstance(source, str) or not source.strip():
        return "unknown"
    if private_source_key(source) in {private_source_key(name) for name in policy["private"]}:
        return "private"
    if policy["mode"] == "private_exclusions" or source in policy["public"]:
        return "public"
    return "unknown"


def identity_cache_entry(canonical, entry):
    if (not isinstance(entry, list) or len(entry) != 5
            or any(not integer(value) or value <= 0 for value in entry[:3])):
        raise GuardError("invalid_batch_state")
    return bulk_hashes({"hash": canonical, "infohash_v1": entry[3], "infohash_v2": entry[4]})


def validate_identity_cache(cache):
    from safety import valid_digest
    if (not isinstance(cache, dict) or set(cache) != {"scope", "entries"} or not valid_digest(cache["scope"])
            or not isinstance(cache["entries"], dict) or len(cache["entries"]) > IDENTITY_CACHE_LIMIT):
        raise GuardError("invalid_batch_state")
    for canonical, entry in cache["entries"].items():
        if torrent_hash(canonical) != canonical:
            raise GuardError("invalid_batch_state")
        identity_cache_entry(canonical, entry)


def torrent_incarnation(torrent):
    if torrent.get("state") in ("metaDL", "forcedMetaDL"):
        return None
    keys = [torrent.get("added_on"), torrent.get("total_size")]
    return keys if all(integer(value) and value > 0 for value in keys) else None


def setup_identity_cache(qb, config, torrents, state):
    missing = {key: identity for key, torrent in torrents.items()
               if not {"infohash_v1", "infohash_v2"} <= torrent.keys()
               and (identity := torrent_incarnation(torrent)) is not None}
    if not missing:
        qb.identity_cache = None
        state.pop("identity_cache", None)
        return
    scope = hashlib.sha256(json.dumps(endpoint_key(config["qbittorrent"]["url"])).encode()).hexdigest()
    previous = state.get("identity_cache", {})
    snapshot_time = time.time()
    entries = {key: entry for key, entry in previous.get("entries", {}).items()
               if previous.get("scope") == scope and missing.get(key) == entry[:2]
               and 0 <= snapshot_time - entry[2] < IDENTITY_CACHE_SECONDS}
    qb.identity_cache = entries
    state["identity_cache"] = {"scope": scope, "entries": entries}


def agrees_with_bulk_hashes(torrent, hashes):
    return all(name not in torrent or (
        isinstance(torrent[name], str) and torrent[name].lower() == value.lower())
        for name, value in zip(("infohash_v1", "infohash_v2"), hashes))


def verified_hashes(qb, torrent):
    canonical = torrent_hash(torrent.get("hash"))
    cache = getattr(qb, "identity_cache", None)
    entry = cache.get(canonical) if cache is not None else None
    if entry is not None and not agrees_with_bulk_hashes(torrent, entry[3:]):
        del cache[canonical]
        entry = None
    if {"infohash_v1", "infohash_v2"} <= torrent.keys():
        return bulk_hashes(torrent)
    incarnation = torrent_incarnation(torrent)
    if entry is not None and incarnation == entry[:2] and 0 <= time.time() - entry[2] < IDENTITY_CACHE_SECONDS:
        return identity_cache_entry(canonical, entry)
    properties = qb.call("/api/v2/torrents/properties", {"hash": canonical})
    if not isinstance(properties, dict) or torrent_hash(properties.get("hash")) != canonical:
        raise GuardError("torrent_hash_identity_unavailable")
    aliases = bulk_hashes(properties)
    hashes = (properties["infohash_v1"], properties["infohash_v2"])
    if not agrees_with_bulk_hashes(torrent, hashes):
        raise GuardError("ambiguous_torrent_hash_identity")
    if cache is not None and incarnation is not None and (canonical in cache or len(cache) < IDENTITY_CACHE_LIMIT):
        cache[canonical] = [*incarnation, int(time.time()), *hashes]
    return aliases


def bulk_hashes(torrent):
    values = (torrent.get("infohash_v1"), torrent.get("infohash_v2"))
    if not all(isinstance(value, str) for value in values) or not any(values):
        raise GuardError("torrent_hash_identity_unavailable")
    canonical = torrent_hash(torrent.get("hash"))
    aliases = {canonical}
    identities = set()
    for length, value in zip((40, 64), values):
        if not value:
            continue
        value = torrent_hash(value)
        if len(value) != length or set(value) == {"0"}:
            raise GuardError("torrent_hash_identity_unavailable")
        identities.add(value)
        aliases.add(value)
        if length == 64:
            identities.add(value[:40])
            aliases.add(value[:40])
    if canonical not in identities:
        raise GuardError("torrent_hash_identity_unavailable")
    return sorted(aliases)


def torrents_by_hash(torrents):
    if not isinstance(torrents, list) or any(not isinstance(t, dict) for t in torrents):
        raise GuardError("invalid_torrent_response")
    indexed = {torrent_hash(t.get("hash")): t for t in torrents}
    if len(indexed) != len(torrents):
        raise GuardError("duplicate_torrent_hash")
    return indexed


def torrent_hash_ownership(torrents, read_hashes):
    claims = collections.defaultdict(set)
    aliases_by_hash, errors = {}, {}
    for canonical, torrent in torrents.items():
        claims[canonical].add(canonical)
        try:
            aliases = read_hashes(torrent)
        except GuardError as error:
            if str(error) == "run_time_limit_reached":
                raise
            errors[canonical] = str(error)
            continue
        aliases_by_hash[canonical] = aliases
        for alias in aliases:
            claims[alias].add(canonical)
    return claims, aliases_by_hash, errors


def grab_timestamp(row):
    try:
        stamp = datetime.datetime.fromisoformat(row["date"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError()
        return stamp.timestamp()
    except (KeyError, TypeError, AttributeError, ValueError, OverflowError, OSError):
        raise GuardError("grab_not_bound_to_current_download") from None


def latest_history_grabs(api, hashes, identities, max_pages, added):
    if not integer(added) or added <= 0:
        raise GuardError("grab_not_bound_to_current_download")
    query = {"eventType": 1, "sortKey": "date", "sortDirection": "descending"}
    history = []
    for series, episode in sorted(identities):
        rows = records(api, "/api/v3/history", dict(query, seriesIds=series, episodeId=episode),
                       max_pages, since=added - 120)
        if any(not integer(row.get("seriesId")) or not integer(row.get("episodeId"))
               or (row["seriesId"], row["episodeId"]) != (series, episode) for row in rows):
            raise GuardError("unknown_content_identity")
        history.extend(rows)
    if len({row["id"] for row in history}) != len(history):
        raise GuardError("duplicate_or_invalid_response_ids")
    latest = select_latest_grabs(history, hashes, identities)
    if any(abs(grab_timestamp(grab) - added) > 120 for grab in latest):
        raise GuardError("grab_not_bound_to_current_download")
    return latest


def select_latest_grabs(history, hashes, identities, require_all=True):
    aliases = set(hashes)
    matches = collections.defaultdict(list)
    has_matching_hash = False
    for grab in history:
        identity = (grab.get("seriesId"), grab.get("episodeId"))
        valid_identity = all(integer(value) and value > 0 for value in identity)
        try:
            grab_hash = torrent_hash(grab.get("downloadId"))
        except GuardError:
            # A malformed grab can hide the true source. Only a known
            # unrelated identity can rule it out.
            if (not valid_identity or identity in identities) and history_event_type(grab) == "grabbed":
                raise GuardError("invalid_history_download_id") from None
            continue
        if grab_hash not in aliases or history_event_type(grab) != "grabbed":
            continue
        has_matching_hash = True
        if not valid_identity:
            raise GuardError("unknown_content_identity")
        if identity in identities:
            matches[identity].append(grab)
    if require_all and not has_matching_hash:
        raise GuardError("no_sonarr_grab_history")
    if require_all and matches.keys() != identities:
        raise GuardError("content_identity_not_in_grab_history")
    latest = []
    for grabs in matches.values():
        newest_id = max(grabs, key=lambda grab: grab["id"])
        newest_id_stamp = grab_timestamp(newest_id)
        source = grab_source(newest_id)
        if any(grab_timestamp(grab) > newest_id_stamp and grab_source(grab) != source
               for grab in grabs):
            raise GuardError("conflicting_grab_source_order")
        latest.append(newest_id)
    return latest


def grab_source(grab):
    data = grab.get("data")
    return (data.get("indexer"), data.get("downloadClientName")) if isinstance(data, dict) else (None, None)


def unique_client_name(client, clients):
    name = client.get("name")
    if not isinstance(name, str) or not name.strip():
        raise GuardError("missing_client_name")
    if sum(isinstance(c, dict) and isinstance(c.get("name"), str)
           and c["name"].strip().casefold() == name.strip().casefold()
           for c in clients) != 1:
        raise GuardError("ambiguous_download_client")
    return name


def grab_indexer(grab, client_name):
    data = grab.get("data")
    if not isinstance(data, dict) or data.get("downloadClientName") != client_name:
        raise GuardError("unconfirmed_grab_download_client")
    if not isinstance(data.get("indexer"), str) or not data["indexer"].strip():
        raise GuardError("missing_indexer_identity")
    return data["indexer"]


def source_for(api, hashes, rows, max_pages, added, client_name):
    identities = set()
    for row in rows:
        identity = (row.get("seriesId"), row.get("episodeId"))
        if any(not integer(value) or value <= 0 for value in identity):
            raise GuardError("unknown_content_identity")
        identities.add(identity)
    grabs = latest_history_grabs(api, hashes, identities, max_pages, added)
    sources = {grab_indexer(grab, client_name) for grab in grabs}
    grab_ids = sorted(grab["id"] for grab in grabs)
    grab_time_floor = min(grab_timestamp(grab) for grab in grabs)
    if len(sources) != 1:
        raise GuardError("ambiguous_indexer_identity")
    return next(iter(sources)), grab_ids, grab_time_floor


def run(config, qb, sonarr_apis, now=None, batch_state=None, include_titles=False, target=None):
    """Return one report per matched torrent. Every action is a proposal only."""
    now = time.time() if now is None else now
    maximum = config.get("max_torrents_per_run", 100)
    max_pages = config.get("max_pages", 20)
    minimum_age = config.get("minimum_age_seconds", 120)
    deadlines = (getattr(api, "deadline", None) for api in (qb, *sonarr_apis.values()))
    deadline = min((stamp for stamp in deadlines if stamp is not None), default=float("inf"))
    reports, queues, clients = [], {}, {}
    by_hash = torrents_by_hash(qb.call("/api/v2/torrents/info"))
    if batch_state is not None:
        setup_identity_cache(qb, config, by_hash, batch_state)
    owners = collections.defaultdict(set)
    for label, api in sonarr_apis.items():
        queues[label] = records(api, "/api/v3/queue", {"includeUnknownSeriesItems": "true"}, max_pages)
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
                              and x.get("enable") is True and x.get("implementation") == "QBittorrent"]
                if len(compatible) != 1:
                    raise GuardError("ambiguous_download_client")
                client = compatible[0]
                verify_client_binding(instance, config["qbittorrent"]["url"], client)
                client_name = unique_client_name(client, clients[label])
                for row in rows:
                    cid, cname = row.get("downloadClientId"), row.get("downloadClient")
                    if cid is not None and (not integer(cid) or cid <= 0 or cid != client["id"]):
                        raise GuardError("wrong_download_client")
                    if cid is None and cname != client_name:
                        raise GuardError("unconfirmed_download_client")
                    if "downloadClient" in row and cname != client_name:
                        raise GuardError("wrong_download_client")
                candidates.append((label, h, rows, t, report, client_name))
            except GuardError as e:
                report.update(decision="skip", reason=str(e))
                reports.append(report)

    # Only scoped ownership candidates consume work. A durable key cursor rotates
    # fairly across both instances and survives restarts and queue reordering.
    candidates.sort(key=lambda entry: entry[:2])
    cursor = batch_state or {}
    after = tuple(cursor.get("timed_out", cursor.get("after", ())))
    if after:
        candidates = ([x for x in candidates if x[:2] > after]
                      + [x for x in candidates if x[:2] <= after])
    hash_ownership = None
    for number, (label, h, rows, t, report, client_name) in enumerate(candidates):
        if number >= maximum:
            report.update(decision="skip", reason="work_limit_reached")
            reports.append(report)
            continue
        api, instance = sonarr_apis[label], config["sonarr"][label]
        started = time.monotonic() < deadline
        try:
            if not started:
                raise GuardError("run_time_limit_reached")
            added = t.get("added_on")
            if not integer(added) or added <= 0 or now - added < minimum_age:
                raise GuardError("torrent_too_new_or_age_unknown")
            if hash_ownership is None:
                try:
                    hash_ownership = torrent_hash_ownership(by_hash, lambda torrent: verified_hashes(qb, torrent))
                except GuardError as error:
                    if str(error) == "run_time_limit_reached":
                        raise GuardError("torrent_identity_scan_time_limit_reached") from None
                    raise
            claims, aliases_by_hash, hash_errors = hash_ownership
            if h in hash_errors:
                raise GuardError(hash_errors[h])
            aliases = aliases_by_hash[h]
            for alias in aliases:
                if owners.get(alias, set()) - {label}:
                    raise GuardError("ambiguous_instance_ownership")
                if claims[alias] != {h}:
                    raise GuardError("ambiguous_torrent_hash_identity")
                if alias != h and label in owners.get(alias, ()):
                    raise GuardError("ambiguous_alias_queue_ownership")
            if hash_errors:
                raise GuardError("torrent_hash_identity_unavailable")
            policy = instance["indexers"]
            if any(classify_source(policy, row.get("indexer")) == "private" for row in rows):
                raise GuardError("private_queue_source_protected")
            if len(aliases) > 1:
                report["hash_aliases"] = aliases
            source, grab_ids, grab_time_floor = source_for(api, aliases, rows, max_pages, added, client_name)
            classification = classify_source(policy, source)
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
                          download_client_name_digest=hashlib.sha256(
                              json.dumps(client_name).encode()).hexdigest(),
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
                         "client_name_digest": report["download_client_name_digest"],
                         "sonarr_endpoint": endpoint_key(instance["url"]),
                         "endpoint": endpoint_key(config["qbittorrent"]["url"]),
                         "attempt": report["attempt_fingerprint"],
                         "grab_time_floor": grab_time_floor,
                         "identity": sorted((r["id"], r["seriesId"], r["episodeId"]) for r in rows)}
            if "hash_aliases" in report:
                ownership["hash_aliases"] = aliases
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
                    report["queue_rows"] = sorted([r["id"], r["episodeId"], h] for r in rows)
                    report["proposed_actions"] = [
                        "remove_torrent_and_data_through_sonarr_without_blocklisting",
                        "request_owning_sonarr_episode_search_after_confirmed_removal_and_final_checks",
                    ]
                report["live_prerequisite"] = "fresh_ownership_source_and_manifest_recheck"
        except GuardError as e:
            reason = str(e)
            if reason in ("run_time_limit_reached", "torrent_identity_scan_time_limit_reached") or time.monotonic() >= deadline:
                # Move past a stalled first candidate next cycle without
                # advancing the cursor that records completed assessments.
                if started and number == 0 and batch_state is not None:
                    batch_state["timed_out"] = [label, h]
                reports.append({"instance": label, "hash": h, "dry_run": True, "decision": "skip",
                                "reason": reason if reason == "torrent_identity_scan_time_limit_reached"
                                else "run_time_limit_reached"})
                break
            report.update(decision="skip", reason=str(e))
        if batch_state is not None:
            batch_state["after"] = [label, h]
            batch_state.pop("timed_out", None)
        reports.append(report)
    return reports


def recheck_candidate(original, config, qb, apis):
    """Refetch both queues and the target's complete ownership/manifest evidence."""
    target = (original["instance"], torrent_hash(original["hash"]))
    reports = run(config, qb, apis, target=target)
    if len(reports) == 1 and reports[0].get("reason") == "torrent_identity_scan_time_limit_reached":
        raise SafetyError("torrent_identity_scan_time_limit_reached")
    if len(reports) != 1 or reports[0].get("decision") != "would_fail":
        raise SafetyError("candidate_no_longer_eligible")
    readiness = read_readiness({target[0]: apis[target[0]]})[target[0]]
    return {"assessment": reports[0], "readiness": readiness}


def unique_keys(pairs, reason):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError(reason)
        result[key] = value
    return result


def unique_config_keys(pairs):
    return unique_keys(pairs, "duplicate_configuration_key")


def unique_response_keys(pairs):
    return unique_keys(pairs, "duplicate_api_response_key")


def load_config(path):
    try:
        with open_regular_file(path) as (file, mode):
            if os.name != "nt" and mode & 0o077:
                raise GuardError("config_permissions_must_be_private")
            config = json.load(file, object_pairs_hook=unique_config_keys)
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
        for label, item in config["sonarr"].items():
            if (not label.strip() or not isinstance(item, dict) or
                    any(not isinstance(item.get(key), str) or not item[key].strip()
                        for key in ("api_key", "category"))):
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
            endpoint_key(item["url"])
        qbittorrent = config["qbittorrent"]
        if any(not isinstance(qbittorrent.get(key), str) or not qbittorrent[key].strip()
               for key in ("username", "password")):
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
        with open_lock_file(args.config.parent / "guard.lock") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError("another_run_is_active") from None
            logger = logging.getLogger("guard")
            logger.setLevel(logging.INFO)
            if args.log_file:
                handler = PrivateRotatingFileHandler(args.log_file, config_path=args.config)
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
                        journal = Journal(args.config.parent / "preview-journal.sqlite3")
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
