"""Public Sonarr torrent assessment. No live action implementation is present."""

import argparse
import collections
import datetime
import http.cookiejar
import json
import logging
import logging.handlers
import os
from pathlib import Path, PurePosixPath
import sys
import time
import urllib.parse
import urllib.request


class GuardError(Exception):
    pass


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


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
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
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


def source_for(api, hash_value, rows, max_pages):
    history = records(api, "/api/v3/history", {
        # Preserve Sonarr's original spelling for its case-sensitive DB filter.
        "eventType": 1, "downloadId": rows[0]["downloadId"],
        "sortKey": "date", "sortDirection": "descending",
    }, max_pages)
    matches = [r for r in history if r.get("eventType") in ("grabbed", 1)
               and str(r.get("downloadId", "")).lower() == hash_value]
    if not matches:
        raise GuardError("no_sonarr_grab_history")
    sources = set()
    for row in rows:
        series_id, episode_id = row.get("seriesId"), row.get("episodeId")
        if not integer(series_id) or series_id <= 0 or not integer(episode_id) or episode_id <= 0:
            raise GuardError("unknown_content_identity")
        matching = [r for r in matches if r.get("seriesId") == series_id
                    and r.get("episodeId") == episode_id]
        if not matching:
            raise GuardError("content_identity_not_in_grab_history")
        for r in matching:
            data = r.get("data")
            if not isinstance(data, dict) or not isinstance(data.get("indexer"), str):
                raise GuardError("missing_indexer_identity")
            sources.add(data["indexer"])
    if len(sources) != 1 or not next(iter(sources)):
        raise GuardError("ambiguous_indexer_identity")
    return next(iter(sources))


def run(config, qb, sonarr_apis, now=None):
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
    processed = 0
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
            if processed >= maximum:
                reports.append({"instance": label, "decision": "skip", "reason": "work_limit_reached"})
                return reports
            processed += 1
            report = {"instance": label, "hash": h, "dry_run": True}
            try:
                if owners[h] != {label}:
                    raise GuardError("ambiguous_instance_ownership")
                t = by_hash.get(h)
                if not t or t.get("category") != category:
                    raise GuardError("missing_torrent_or_wrong_category")
                compatible = [x for x in clients[label] if isinstance(x, dict)
                              and x.get("enable") is True and x.get("implementation") == "QBittorrent"
                              and any(isinstance(f, dict) and f.get("name") == "tvCategory"
                                      and f.get("value") == category for f in x.get("fields", []))]
                if len(compatible) != 1:
                    raise GuardError("ambiguous_download_client")
                client = compatible[0]
                for row in rows:
                    cid, cname = row.get("downloadClientId"), row.get("downloadClient")
                    if cid is not None and cid != client.get("id"):
                        raise GuardError("wrong_download_client")
                    if cid is None and (not cname or cname != client.get("name")):
                        raise GuardError("unconfirmed_download_client")
                source = source_for(api, h, rows, max_pages)
                policy = instance["indexers"]
                if source in policy["private"]:
                    raise GuardError("private_source_protected")
                if source not in policy["public"]:
                    raise GuardError("unclassified_source_protected")
                state = t.get("state", "")
                safe_states = {"downloading", "stalledDL", "queuedDL", "pausedDL", "stoppedDL",
                               "uploading", "stalledUP", "queuedUP", "pausedUP", "stoppedUP",
                               "forcedDL", "forcedUP"}
                if state not in safe_states:
                    raise GuardError("metadata_or_transitional_state")
                added = t.get("added_on")
                if not integer(added) or added <= 0 or now - added < minimum_age:
                    raise GuardError("torrent_too_new_or_age_unknown")
                files = qb.call("/api/v2/torrents/files", {"hash": h})
                reasons = assess_files(files)
                report.update(decision="would_fail" if reasons else "keep", reasons=reasons)
                if reasons:
                    report["proposed_actions"] = [
                        "blocklist_release_in_owning_sonarr",
                        "remove_torrent_and_data_through_sonarr",
                        "obtain_targeted_replacement_after_retry_settings_verified",
                    ]
                    report["live_prerequisite"] = "fresh_ownership_source_and_manifest_recheck"
            except GuardError as e:
                report.update(decision="skip", reason=str(e))
            reports.append(report)
    return reports


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
            lists = item["indexers"]
            for kind in ("public", "private"):
                if not isinstance(lists[kind], list) or any(not isinstance(x, str) or not x for x in lists[kind]):
                    raise GuardError("invalid_source_lists")
            if set(lists["public"]) & set(lists["private"]):
                raise GuardError("overlapping_source_lists")
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
    args = parser.parse_args()
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
            logger.addHandler(logging.StreamHandler(sys.stdout))
            if args.log_file:
                handler = logging.handlers.RotatingFileHandler(args.log_file, maxBytes=1024*1024, backupCount=3)
                os.chmod(args.log_file, 0o600)
                logger.addHandler(handler)
            qb = Api(config["qbittorrent"])
            deadline = time.monotonic() + 180
            qb.deadline = deadline
            qb.login()
            reports = run(config, qb, {name: Api(c, deadline=deadline) for name, c in config["sonarr"].items()})
            from zoneinfo import ZoneInfo
            stamp = datetime.datetime.now(ZoneInfo("Australia/Sydney")).isoformat(timespec="seconds")
            for report in reports:
                logger.info(json.dumps(dict(time=stamp, **report)))
            logger.info(json.dumps({"dry_run": True, "summary": dict(collections.Counter(r["decision"] for r in reports))}))
        return 0
    except GuardError as e:
        print(json.dumps({"dry_run": True, "error": str(e)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"dry_run": True, "error": "unexpected_failure_no_actions_performed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
