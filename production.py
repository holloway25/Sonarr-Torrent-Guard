"""Read-only outcome verification and a disabled, exact-target single-test sender.

The command line supports preflight and observation of existing journal entries.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import math
import re
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request

from authorization import (ContainerAuthorization, read_bound_container_journal_id,
                           read_container_journal_binding, read_container_journal_id)
from guard import (Api, FILE_ASSESSMENT_STATES, GuardError, assess_files, classify_source, endpoint_key, grab_indexer, grab_timestamp,
                   hard_deadline, history_event_type, integer, latest_history_grabs, load_config,
                   manifest_fingerprint, metadata_still_pending, records, recheck_candidate, run, select_latest_grabs, torrent_hash,
                   torrent_hash_ownership, torrents_by_hash, unique_client_name, unique_response_keys, verified_hashes,
                   verify_client_binding)
from safety import (ACTION_JOURNAL_FILE, Journal, SafetyError, DISPATCH_STOP_REASONS, CANCELLATION_STOP_REASONS,
                    check_fresh, evidence, open_lock_file, reconcile, replacement_already_observed, valid_digest)
from maintenance import require_connectivity
import workflow
from workflow import file_policy_removal, read_readiness, removal_without_blocklist


# Deliberately false until code review and explicit human approval for one test.
SINGLE_TEST_RELEASE_ENABLED = False
PUBLIC_ATTEMPT_RELEASE_ENABLED = False
ROUTINE_RELEASE_ENABLED = False
# Reviewed metadata policy; sender gates and explicit grants still required.
METADATA_RETRY_RELEASE_ENABLED = True
SONARR_V4_VERSION = re.compile(r"4(?:\.[0-9]+){1,3}")
EVENT_CLOCK_SKEW_SECONDS = 120
CONTEXT_FIELDS = {"instance", "hash", "series_id", "episode_ids", "queue_id", "client_id",
                  "indexer", "binding_digest", "client_name_digest", "release_title_digest",
                  "window_start", "baseline_history_ids", "baseline_blocklist_ids", "approval_digest"}
ATTEMPT_CONTEXT_FIELDS = {"attempt_fingerprint", "download_added_on", "grab_ids"}
METADATA_SEARCH_HOLDS = {"replacement_already_grabbed", "replacement_history_ambiguous",
                         "replacement_client_unknown", "replacement_history_identity_invalid",
                         "replacement_history_event_invalid", "replacement_blocklisted",
                         "replacement_blocklist_uncertain", "dispatch_validation_failed"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_context(value):
    optional = {"routine_grant_digest", "metadata_retry", "file_cleanup", "hash_aliases", "queue_rows",
                "metadata_search_hold"}
    if (not isinstance(value, dict) or not set(value) <= CONTEXT_FIELDS | ATTEMPT_CONTEXT_FIELDS | optional
            or set(value) - optional not in (CONTEXT_FIELDS, CONTEXT_FIELDS | ATTEMPT_CONTEXT_FIELDS)
            or (set(value) & optional and not ATTEMPT_CONTEXT_FIELDS <= set(value))):
        raise SafetyError("invalid_operation_context")
    try:
        if torrent_hash(value["hash"]) != value["hash"]:
            raise ValueError()
        if "hash_aliases" in value:
            aliases = value["hash_aliases"]
            if (not isinstance(aliases, list) or not 2 <= len(aliases) <= 3
                    or sorted(set(aliases)) != aliases or value["hash"] not in aliases
                    or any(torrent_hash(h) != h for h in aliases)):
                raise ValueError()
        for field in ("instance", "indexer"):
            if not isinstance(value[field], str) or not value[field]:
                raise ValueError()
        for field in ("series_id", "queue_id", "client_id"):
            if not integer(value[field]) or value[field] <= 0:
                raise ValueError()
        for field in ("episode_ids", "baseline_history_ids", "baseline_blocklist_ids"):
            ids = value[field]
            if (not isinstance(ids, list) or len(ids) > 10000 or len(set(ids)) != len(ids)
                    or any(not integer(i) or i <= 0 for i in ids)):
                raise ValueError()
        if not value["episode_ids"]:
            raise ValueError()
        if "queue_rows" in value:
            rows = value["queue_rows"]
            aliases = value.get("hash_aliases", [value["hash"]])
            if not isinstance(rows, list) or not 1 <= len(rows) <= 10000:
                raise ValueError()
            if any(not isinstance(row, list) or len(row) != 3
                   or not integer(row[0]) or row[0] <= 0
                   or not integer(row[1]) or row[1] not in value["episode_ids"]
                   or row[2] not in aliases for row in rows):
                raise ValueError()
            if (len({row[0] for row in rows}) != len(rows)
                    or {row[1] for row in rows} != set(value["episode_ids"])
                    or min(row[0] for row in rows) != value["queue_id"]):
                raise ValueError()
        for field in ("binding_digest", "client_name_digest", "release_title_digest", "approval_digest"):
            if not valid_digest(value[field]):
                raise ValueError()
        stamp = value["window_start"]
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(stamp) or stamp <= 0:
            raise ValueError()
        if "attempt_fingerprint" in value:
            added, grabs = value["download_added_on"], value["grab_ids"]
            if (not integer(added) or added <= 0 or not isinstance(grabs, list) or not grabs
                    or len(grabs) > 10000 or any(not integer(i) or i <= 0 for i in grabs)
                    or sorted(set(grabs)) != grabs or value["attempt_fingerprint"] != digest(
                        [value["instance"], value["hash"], added, grabs])):
                raise ValueError()
        if "routine_grant_digest" in value and not valid_digest(value["routine_grant_digest"]):
            raise ValueError()
        if "metadata_retry" in value:
            policy = value["metadata_retry"]
            if ("attempt_fingerprint" not in value or not isinstance(policy, dict)
                    or set(policy) != {"blocklist", "search"}
                    or policy["blocklist"] is not False or policy["search"] != "EpisodeSearch"):
                raise ValueError()
        if "file_cleanup" in value and (
                value["file_cleanup"] is not True or "metadata_retry" in value or "queue_rows" not in value):
            raise ValueError()
        if "metadata_search_hold" in value and (
                not removal_without_blocklist(value) or value["metadata_search_hold"] not in METADATA_SEARCH_HOLDS):
            raise ValueError()
    except (ValueError, TypeError, GuardError):
        raise SafetyError("invalid_operation_context") from None
    return json.loads(json.dumps(value))


def require_sonarr_v4(api):
    status = api.call("/api/v3/system/status")
    version = status.get("version") if isinstance(status, dict) else None
    if not isinstance(version, str) or SONARR_V4_VERSION.fullmatch(version) is None:
        raise SafetyError("unreviewed_sonarr_version")


def binding_digest(config, label):
    item = config["sonarr"][label]
    return digest({"sonarr": endpoint_key(item["url"]), "qbittorrent": endpoint_key(config["qbittorrent"]["url"]),
                   "category": item["category"], "client_id": item["download_client_binding"]["id"]})


def bound_client(config, api, label):
    item = config["sonarr"][label]
    clients = api.call("/api/v3/downloadclient")
    if not isinstance(clients, list):
        raise SafetyError("invalid_client_response")
    matches = [c for c in clients if isinstance(c, dict) and integer(c.get("id"))
               and c["id"] == item["download_client_binding"]["id"]
               and c.get("enable") is True and c.get("implementation") == "QBittorrent"]
    if len(matches) != 1:
        raise SafetyError("ambiguous_download_client")
    verify_client_binding(item, config["qbittorrent"]["url"], matches[0])
    try:
        unique_client_name(matches[0], clients)
    except GuardError as error:
        raise SafetyError(str(error)) from None
    return matches[0]


def history_since(api, start):
    date = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).isoformat()
    rows = api.call("/api/v3/history/since", {"date": date})
    if (not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(r, dict)
            or not integer(r.get("id")) or r["id"] <= 0 for r in rows)
            or len({r["id"] for r in rows}) != len(rows)):
        raise SafetyError("invalid_history_response")
    return rows


def outcome_history(api, series, episodes, start, max_pages, *, on_page=None):
    rows = []
    ids = set()
    for episode in episodes:
        def validate_page(page):
            for row in page:
                if (not all(integer(row.get(key)) and row[key] == expected
                            for key, expected in (("seriesId", series), ("episodeId", episode)))
                        or row["id"] <= 0 or row["id"] in ids or len(ids) >= 10000):
                    raise SafetyError("invalid_history_response")
                ids.add(row["id"])
            if on_page is not None:
                on_page(page)

        rows.extend(records(api, "/api/v3/history", {
            "seriesIds": series, "episodeId": episode, "sortKey": "date", "sortDirection": "descending",
        }, max_pages, since=start, on_page=validate_page))
    return rows


def blocklist_records(api, series_id, start, max_pages):
    unscoped = False

    def detect_unscoped(page):
        nonlocal unscoped
        unscoped = unscoped or any(
            integer(row.get("seriesId")) and row["seriesId"] > 0 and row["seriesId"] != series_id for row in page)

    # Keep the entire boundary second so truncated Sonarr timestamps remain evidence.
    try:
        return records(api, "/api/v3/blocklist",
                       {"seriesIds": series_id, "sortKey": "date", "sortDirection": "descending"},
                       max_pages, since=math.floor(start), on_page=detect_unscoped)
    except GuardError as error:
        if unscoped and str(error) == "pagination_limit_reached":
            raise GuardError("sonarr_unscoped_blocklist_limit_reached") from None
        raise


def event_time(row):
    value = row.get("date")
    if not isinstance(value, str):
        raise SafetyError("missing_event_timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except ValueError:
        raise SafetyError("invalid_event_timestamp") from None


def event_after(row, boundary):
    """A truncated timestamp represents an interval, not an exact instant."""
    start = event_time(row)
    if start > time.time() + EVENT_CLOCK_SKEW_SECONDS:
        return None
    match = re.search(r"T\d{2}:\d{2}:\d{2}(?:[.,](\d+))?", row["date"])
    if match is None:
        raise SafetyError("invalid_event_timestamp")
    precision = min(len(match[1]), 6) if match[1] else 0
    if start >= boundary:
        return True
    if start + 10 ** (-precision) <= boundary:
        return False
    return None


def event_boundary_reached(dispatched_at):
    now = time.time()
    return math.isfinite(now) and now >= math.floor(dispatched_at) + 1


def wait_for_event_boundary(dispatched_at):
    """Keep whole-second outcome timestamps after fractional durable intent.

    This changes sending, never the verifier's acceptance of old evidence.
    Bound the wait and fail closed on a backward/stalled wall clock.
    """
    if (isinstance(dispatched_at, bool) or not isinstance(dispatched_at, (int, float))
            or not math.isfinite(dispatched_at) or dispatched_at <= 0):
        raise SafetyError("dispatch_clock_unavailable")
    boundary = math.floor(dispatched_at) + 1
    stop = time.monotonic() + 1.1
    while not event_boundary_reached(dispatched_at):
        now = time.time()
        if not math.isfinite(now):
            raise SafetyError("dispatch_clock_unavailable")
        remaining = min(boundary - now + .01, stop - time.monotonic())
        if remaining <= 0:
            raise SafetyError("dispatch_clock_unavailable")
        time.sleep(min(remaining, .1))
    return boundary


def check_blocklist_scope(api, download_id, context, max_pages):
    """Sonarr uses all grabs for the exact queue download ID, sorted by date."""
    try:
        rows = records(api, "/api/v3/history", {
            "downloadId": download_id, "eventType": 1, "sortKey": "date", "sortDirection": "descending",
        }, max_pages)
        if not rows or any(
                row["id"] <= 0 or row.get("downloadId") != download_id
                or history_event_type(row) != "grabbed" or not integer(row.get("seriesId"))
                or row["seriesId"] != context["series_id"] or not integer(row.get("episodeId"))
                for row in rows):
            raise ValueError()
        if {row["episodeId"] for row in rows} != set(context["episode_ids"]):
            raise ValueError()
        dated = [(grab_timestamp(row), row) for row in rows]
        latest = max(stamp for stamp, _ in dated)
        for stamp, row in dated:
            if stamp != latest:
                continue
            data = row.get("data")
            name = data.get("downloadClientName") if isinstance(data, dict) else None
            if (row["id"] not in context["grab_ids"] or not isinstance(name, str) or not name.strip()
                    or digest(name) != context["client_name_digest"]
                    or grab_indexer(row, name) != context["indexer"]
                    or digest(row.get("sourceTitle")) != context["release_title_digest"]):
                raise ValueError()
    except (GuardError, ValueError) as error:
        if str(error) == "run_time_limit_reached":
            raise
        raise SafetyError("sonarr_blocklist_scope_unverified") from None


def check_visible_native_grabs(api, instance, report, max_pages):
    """Hold contradictory public API records before using Sonarr's native action."""
    try:
        download_id = report["download_id_spelling"]
        rows = records(api, "/api/v3/history", {
            "downloadId": download_id, "eventType": 1, "sortKey": "date", "sortDirection": "descending",
        }, max_pages)
        episodes = set(report["episode_ids"])
        approved = set(report["grab_ids"])
        if (not rows or len(report["series_ids"]) != 1
                or {row.get("episodeId") for row in rows} != episodes):
            raise ValueError()
        newest = max(grab_timestamp(row) for row in rows)
        for row in rows:
            data, title = row.get("data"), row.get("sourceTitle")
            name = data.get("downloadClientName") if isinstance(data, dict) else None
            if (row["id"] <= 0 or row.get("downloadId") != download_id or history_event_type(row) != "grabbed"
                    or not integer(row.get("seriesId")) or row["seriesId"] != report["series_ids"][0]
                    or not integer(row.get("episodeId"))
                    or not isinstance(name, str) or not name.strip()
                    or digest(name) != report["download_client_name_digest"]
                    or not isinstance(title, str) or not title.strip()):
                raise ValueError()
            source = grab_indexer(row, name)
            if (classify_source(instance["indexers"], source) != "public"
                    or (grab_timestamp(row) == newest and (row["id"] not in approved or source != report["indexer"]))):
                raise ValueError()
        if not approved <= {row["id"] for row in rows}:
            raise ValueError()
    except (GuardError, TypeError, ValueError) as error:
        if str(error) == "run_time_limit_reached":
            raise
        raise SafetyError("sonarr_blocklist_scope_unverified") from None


def execute_native_file_removal(config, qb, apis, report, authority, lock_path):
    """Ask the owning Sonarr to remove, blocklist and natively retry once this pass."""
    from authorization import RoutineAuthorization

    if config.get("dry_run") is not False or ROUTINE_RELEASE_ENABLED is not True or not file_policy_removal(report):
        raise SafetyError("live_execution_disabled")
    if not isinstance(authority, (ContainerAuthorization, RoutineAuthorization)):
        raise SafetyError("routine_authorization_invalid")
    validate = authority.validate_scope if isinstance(authority, ContainerAuthorization) else authority.validate
    validate(config, report)
    label = report["instance"]
    api, instance = apis[label], config["sonarr"][label]
    if endpoint_key(api.config["url"]) != endpoint_key(instance["url"]):
        raise SafetyError("identity_or_manifest_changed")
    with open_lock_file(lock_path) as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafetyError("another_run_is_active") from None
        require_sonarr_v4(api)
        require_connectivity(config, api, label)
        refreshed = run(config, qb, apis, target=(label, report["hash"]))
        if len(refreshed) != 1 or not file_policy_removal(refreshed[0]):
            raise SafetyError("candidate_no_longer_eligible")
        current = refreshed[0]
        fresh = {"assessment": current}
        check_fresh(report, fresh)
        check_visible_native_grabs(api, instance, current, config.get("max_pages", 20))
        require_current_file_failure(qb, current, instance["category"], current["manifest_fingerprint"])
        validate(config, current)
        check_fresh(report, fresh)
        _send_queue_delete(api, min(current["queue_ids"]), blocklist=True, native_file_cleanup=True)


def capture_context(config, api, report, approval_digest, now=None, *, dispatch=None):
    """Capture bounded pre-dispatch baselines from the fresh, validated target."""
    evidence(report)
    if report.get("decision") != "would_fail" or report.get("public_source_confirmed") is not True:
        raise SafetyError("not_a_public_failure_candidate")
    series = report.get("series_ids")
    if (not isinstance(series, list) or len(series) != 1
            or not integer(series[0]) or series[0] <= 0):
        raise SafetyError("single_series_required_for_controlled_test")
    episodes = report.get("episode_ids")
    if (not isinstance(episodes, list) or not episodes
            or any(not integer(i) or i <= 0 for i in episodes)):
        raise SafetyError("invalid_operation_context")
    require_sonarr_v4(api)
    client = bound_client(config, api, report["instance"])
    if digest(client["name"]) != report.get("download_client_name_digest"):
        raise SafetyError("identity_or_manifest_changed")
    aliases = report.get("hash_aliases", [report["hash"]])
    if torrent_hash(report.get("download_id_spelling")) not in aliases:
        raise SafetyError("invalid_history_download_id")
    identities = {(series[0], episode) for episode in episodes}
    try:
        grabs = latest_history_grabs(api, aliases, identities, config.get("max_pages", 20),
                                     report.get("download_added_on"))
        sources = {grab_indexer(grab, client["name"]) for grab in grabs}
    except GuardError:
        raise SafetyError("identity_or_manifest_changed") from None
    if sorted(grab["id"] for grab in grabs) != report["grab_ids"] or sources != {report["indexer"]}:
        raise SafetyError("identity_or_manifest_changed")
    titles = [grab.get("sourceTitle") for grab in grabs]
    if any(not isinstance(title, str) or not title.strip() for title in titles) or len(set(titles)) != 1:
        raise SafetyError("ambiguous_release_title_evidence")
    policy = metadata_policy(report)
    start = (time.time() if now is None else now) - 300
    baseline_history = history_since(api, start)
    approved_by_id = {grab["id"]: grab for grab in grabs}
    approved_ids = {(grab["seriesId"], grab["episodeId"]): grab["id"] for grab in grabs}
    # Recent history is a second read. Do not hide evidence that arrived
    # between the targeted lookup and this baseline behind a baseline ID.
    try:
        for row in baseline_history:
            approved = approved_by_id.get(row["id"])
            if approved is None:
                continue
            if (torrent_hash(row.get("downloadId")) not in aliases
                    or history_event_type(row) != "grabbed"
                    or any(not integer(row.get(key)) or row[key] != approved[key]
                           for key in ("seriesId", "episodeId"))
                    or grab_indexer(row, client["name"]) != report["indexer"]
                    or grab_timestamp(row) != grab_timestamp(approved)
                    or row.get("sourceTitle") != approved["sourceTitle"]):
                raise SafetyError("identity_or_manifest_changed")
        recent_grabs = select_latest_grabs(
            [*grabs, *(row for row in baseline_history if row["id"] not in approved_by_id)],
            aliases, identities, require_all=False)
        for grab in recent_grabs:
            approved_id = approved_ids[(grab["seriesId"], grab["episodeId"])]
            if grab["id"] > approved_id:
                raise SafetyError("identity_or_manifest_changed")
    except GuardError:
        raise SafetyError("identity_or_manifest_changed") from None
    if policy is None:
        try:
            latest = max(grab_timestamp(grab) for grab in grabs)
            for row in baseline_history:
                if row.get("downloadId") != report["download_id_spelling"] or history_event_type(row) != "grabbed":
                    continue
                identity = (row.get("seriesId"), row.get("episodeId"))
                if (not all(integer(i) for i in identity) or identity not in identities
                        or (row["id"] not in approved_by_id and grab_timestamp(row) >= latest)):
                    raise SafetyError("sonarr_blocklist_scope_unverified")
        except GuardError:
            raise SafetyError("sonarr_blocklist_scope_unverified") from None
    blocklist = blocklist_records(api, series[0], start, config.get("max_pages", 20))
    context = {
        "instance": report["instance"], "hash": report["hash"], "series_id": series[0],
        "episode_ids": report["episode_ids"], "queue_id": min(report["queue_ids"]),
        "client_id": client["id"], "indexer": report["indexer"],
        "binding_digest": binding_digest(config, report["instance"]),
        "client_name_digest": digest(client["name"]), "release_title_digest": digest(titles[0]),
        "window_start": start, "baseline_history_ids": [r["id"] for r in baseline_history],
        "baseline_blocklist_ids": [r["id"] for r in blocklist], "approval_digest": approval_digest,
    }
    context.update({k: report[k] for k in ATTEMPT_CONTEXT_FIELDS})
    if policy is not None:
        context["queue_rows"] = report["queue_rows"]
        context["metadata_retry"] = policy
        if dispatch is not None:
            previous = dispatch["context"]
            try:
                check_metadata_blocklist(blocklist, previous, dispatch["dispatched_at"])
                check_replacement_grabs(baseline_history, previous, dispatch["dispatched_at"])
            except (GuardError, SafetyError) as error:
                # Preserve an observed veto even if the later read no longer contains the row.
                reason = str(error)
                context["metadata_search_hold"] = reason if reason in METADATA_SEARCH_HOLDS else "dispatch_validation_failed"
    if "hash_aliases" in report:
        context["hash_aliases"] = aliases
    if policy is None and dispatch is None:
        check_blocklist_scope(api, report["download_id_spelling"], context, config.get("max_pages", 20))
    return validate_context(context)


def require_current_metadata_timeout(qb, context, category):
    """Recheck only the target immediately before the Sonarr removal."""
    target = context["hash"]
    torrents = torrents_by_hash(qb.call("/api/v2/torrents/info", {"hashes": target}))
    if set(torrents) != {target}:
        raise SafetyError("metadata_timeout_no_longer_confirmed")
    torrent = torrents[target]
    added = torrent.get("added_on")
    if (not integer(added) or added != context["download_added_on"]
            or torrent.get("category") != category or not metadata_still_pending(torrent)
            or qb.call("/api/v2/torrents/files", {"hash": target}) != []):
        raise SafetyError("metadata_timeout_no_longer_confirmed")


def require_current_file_failure(qb, context, category, expected_manifest):
    """Check the target's incarnation and full file policy immediately before removal."""
    target = context["hash"]
    try:
        torrents = torrents_by_hash(qb.call("/api/v2/torrents/info", {"hashes": target}))
        if set(torrents) != {target}:
            raise SafetyError("identity_or_manifest_changed")
        torrent = torrents[target]
        added, state = torrent.get("added_on"), torrent.get("state")
        if (not integer(added) or added != context["download_added_on"] or torrent.get("category") != category
                or not isinstance(state, str) or state not in FILE_ASSESSMENT_STATES
                or sorted(verified_hashes(qb, torrent)) != context.get("hash_aliases", [target])):
            raise SafetyError("identity_or_manifest_changed")
        files = qb.call("/api/v2/torrents/files", {"hash": target})
        if not assess_files(files) or manifest_fingerprint(files) != expected_manifest:
            raise SafetyError("identity_or_manifest_changed")
    except GuardError as error:
        if str(error) == "run_time_limit_reached":
            raise
        raise SafetyError("identity_or_manifest_changed") from None


def observed_torrent(qb, context):
    """Use the same identity evidence as assessment, under the caller's deadline."""
    by_hash = torrents_by_hash(qb.call("/api/v2/torrents/info"))
    claims, aliases_by_hash, errors = torrent_hash_ownership(
        by_hash, lambda torrent: verified_hashes(qb, torrent))
    aliases = context.get("hash_aliases", [context["hash"]])
    matching = {key for alias in aliases for key in claims.get(alias, ())}
    canonical = next(iter(matching), None)
    if len(matching) > 1 or any(claims[alias] != {canonical} for alias in aliases_by_hash.get(canonical, ())):
        raise GuardError("ambiguous_torrent_hash_identity")
    if errors:
        raise GuardError("torrent_hash_identity_unavailable")
    return by_hash.get(canonical), aliases_by_hash.get(canonical, ())


def blocklist_observation(rows, context, not_before, *, any_episode=False):
    required = set(context["episode_ids"])
    matched, ambiguous = set(), set()
    for row in rows:
        if not integer(row.get("seriesId")) or row["seriesId"] <= 0:
            raise SafetyError("invalid_blocklist_identity")
        if row["id"] in context["baseline_blocklist_ids"] or row["seriesId"] != context["series_id"]:
            continue
        protocol = row.get("protocol")
        if isinstance(protocol, str):
            protocol = protocol.casefold()
        elif not integer(protocol):
            protocol = None
        if protocol in ("usenet", 1):
            continue
        torrent_protocol = protocol in ("torrent", 2)
        indexer, title = row.get("indexer"), row.get("sourceTitle")
        indexer_known = isinstance(indexer, str) and bool(indexer.strip())
        title_known = isinstance(title, str) and bool(title.strip())
        if (indexer_known and indexer != context["indexer"]
                or title_known and digest(title) != context["release_title_digest"]):
            continue
        after = event_after(row, not_before)
        if after is False:
            continue
        ids = row.get("episodeIds")
        if row["id"] <= 0 or not isinstance(ids, list) or any(not integer(i) or i <= 0 for i in ids):
            raise SafetyError("invalid_blocklist_identity")
        if not ids:
            ambiguous.update(required)
            continue
        definite = after is True and indexer_known and title_known and torrent_protocol
        (matched if definite else ambiguous).update(required.intersection(ids))
    if matched == required or (any_episode and matched):
        return True
    return None if ambiguous - matched else False


class OutcomeVerifier:
    def __init__(self, config, qb, apis, context, not_before=None):
        self.config, self.qb, self.apis = config, qb, apis
        self.context = validate_context(context)
        self.not_before = self.context["window_start"] if not_before is None else not_before

    def observe(self):
        c = self.context
        label = c["instance"]
        if label not in self.config["sonarr"]:
            matches = [name for name in self.config["sonarr"]
                       if binding_digest(self.config, name) == c["binding_digest"]]
            if len(matches) != 1:
                raise SafetyError("observation_binding_changed")
            label = matches[0]
        if label not in self.apis or binding_digest(self.config, label) != c["binding_digest"]:
            raise SafetyError("observation_binding_changed")
        api = self.apis[label]
        if endpoint_key(api.config["url"]) != endpoint_key(self.config["sonarr"][label]["url"]):
            raise SafetyError("observation_binding_changed")
        client = bound_client(self.config, api, label)
        require_sonarr_v4(api)
        if client["id"] != c["client_id"] or digest(client["name"]) != c["client_name_digest"]:
            raise SafetyError("observation_client_changed")
        # APIs cannot prove download-side file deletion. Never infer this from absence.
        result = {k: None for k in ("torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")}
        without_blocklist = removal_without_blocklist(c)
        if without_blocklist:
            result["any_replacement_observed"] = None
            result["replacement_grab_observed"] = None
            result["replacement_grab_ambiguous"] = None
        current_torrent = None
        current_aliases = ()
        identity_available = False
        try:
            current_torrent, current_aliases = observed_torrent(self.qb, c)
            identity_available = True
            result["torrent_absent"] = current_torrent is None
            if current_torrent is not None and "download_added_on" in c and (
                    current_torrent.get("added_on") != c["download_added_on"]):
                # A different incarnation needs corroborating new Sonarr grabs.
                result["torrent_absent"] = None
        except Exception:
            pass
        baseline_ids = set(c["baseline_history_ids"])

        def observe_history_page(rows):
            for event in rows:
                if event["id"] in baseline_ids:
                    continue
                try:
                    if history_event_type(event) != "grabbed":
                        continue
                    after = event_after(event, self.not_before)
                    if after is False:
                        continue
                    data = event.get("data")
                    name = data.get("downloadClientName") if isinstance(data, dict) else None
                    client_known = isinstance(name, str) and bool(name.strip())
                    if client_known and digest(name) != c["client_name_digest"]:
                        continue
                    torrent_hash(event.get("downloadId"))
                    if after is True and client_known:
                        result["replacement_grab_observed"] = True
                        continue
                except (GuardError, SafetyError):
                    pass
                result["replacement_grab_ambiguous"] = True

        try:
            # Preserve a known grab even if a later history page fails to load.
            rows = outcome_history(api, c["series_id"], c["episode_ids"], math.floor(self.not_before),
                                   self.config.get("max_pages", 20),
                                   on_page=observe_history_page if without_blocklist else None)
            new = [r for r in rows if r["id"] not in baseline_ids]
            failed, replacement, ambiguous_failed, ambiguous_replacement = set(), set(), set(), set()
            regrab = set()
            aliases = set(c.get("hash_aliases", [c["hash"]]))
            aliases.update(current_aliases)
            latest_grab_id = max(c.get("grab_ids", ()), default=None)
            for r in new:
                kind = history_event_type(r)
                after = event_after(r, self.not_before)
                if after is False:
                    continue
                data = r.get("data")
                name = data.get("downloadClientName") if isinstance(data, dict) else None
                client_known = isinstance(name, str) and bool(name.strip())
                if client_known and digest(name) != c["client_name_digest"]:
                    continue
                try:
                    h = torrent_hash(r.get("downloadId"))
                except GuardError:
                    h = None
                confirmed = client_known and after is True
                if kind == "downloadFailed":
                    title = r.get("sourceTitle")
                    title_known = isinstance(title, str) and bool(title.strip())
                    if ((identity_available and h is not None and h not in aliases)
                            or (title_known and digest(title) != c["release_title_digest"])):
                        continue
                    definite = confirmed and h in aliases and title_known
                    (failed if definite else ambiguous_failed).add(r["episodeId"])
                elif kind == "grabbed" and h is not None:
                    if h not in aliases:
                        (replacement if confirmed and identity_available else ambiguous_replacement).add(r["episodeId"])
                        continue
                    if latest_grab_id is None or r["id"] <= latest_grab_id:
                        continue
                    added = current_torrent.get("added_on") if current_torrent else None
                    if not identity_available or (current_torrent is not None and not integer(added)):
                        ambiguous_replacement.add(r["episodeId"])
                    elif (integer(added) and added > max(c["download_added_on"], self.not_before)
                          and abs(event_time(r) - added) <= 120):
                        (regrab if confirmed else ambiguous_replacement).add(r["episodeId"])
            required = set(c["episode_ids"])
            result["failed"] = True if failed == required else (None if ambiguous_failed - failed else False)
            covered = replacement | regrab
            result["replacement_observed"] = True if covered == required else (
                None if ambiguous_replacement - covered else False)
            if without_blocklist:
                result["any_replacement_observed"] = True if covered else (
                    None if ambiguous_replacement else False)
                if result["replacement_grab_ambiguous"] is not True:
                    result["replacement_grab_ambiguous"] = False
                    if result["replacement_grab_observed"] is not True:
                        result["replacement_grab_observed"] = False
            if regrab == required:
                result["torrent_absent"] = True  # Original incarnation, not all copies of this hash.
        except Exception:
            pass
        try:
            rows = blocklist_records(api, c["series_id"], self.not_before, self.config.get("max_pages", 20))
            result["blocklisted"] = blocklist_observation(
                rows, c, self.not_before, any_episode=without_blocklist)
        except Exception:
            pass
        return result


def validate_approval(approval, report, now=None):
    now = time.time() if now is None else now
    fields = {"operation", "expires_at", "nonce", "instance", "hash", "ownership_fingerprint", "manifest_fingerprint"}
    if not isinstance(approval, dict) or set(approval) != fields:
        raise SafetyError("explicit_single_target_approval_required")
    expires = approval["expires_at"]
    if (approval["operation"] != "sonarr_fail_remove_retry" or not valid_digest(approval["nonce"])
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not 0 < expires - now <= 300
            or any(approval.get(k) != v for k, v in evidence(report).items() if k in fields)):
        raise SafetyError("approval_expired_or_target_mismatch")


class RejectDeleteRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SafetyError("delete_redirect_refused")


def _send_queue_delete(api, queue_id, blocklist=True, *, native_file_cleanup=False):
    """Narrow transport; called only after the coordinator's gates and durable intent."""
    if (SINGLE_TEST_RELEASE_ENABLED is not True and PUBLIC_ATTEMPT_RELEASE_ENABLED is not True
            and ROUTINE_RELEASE_ENABLED is not True):
        raise SafetyError("live_execution_disabled")
    if not integer(queue_id) or queue_id <= 0:
        raise SafetyError("invalid_queue_id")
    if (not isinstance(blocklist, bool) or (not blocklist and METADATA_RETRY_RELEASE_ENABLED is not True)
            or (native_file_cleanup and (not blocklist or ROUTINE_RELEASE_ENABLED is not True))):
        raise SafetyError("live_execution_disabled")
    if blocklist and not native_file_cleanup and not workflow.BLOCKLIST_SCOPE_VERIFIABLE:
        raise SafetyError(workflow.BLOCKLIST_MANUAL_REASON)
    params = {"removeFromClient": "true", "blocklist": "true" if blocklist else "false",
              "skipRedownload": "false" if blocklist else "true", "changeCategory": "false"}
    url = api.config["url"].rstrip("/") + "/api/v3/queue/" + str(queue_id) + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"X-Api-Key": api.config["api_key"]}, method="DELETE")
    opener = urllib.request.build_opener(RejectDeleteRedirect())
    deadline = min(api.deadline or float("inf"), time.monotonic() + 15)
    try:
        with hard_deadline(deadline):
            with opener.open(request, timeout=min(15, deadline - time.monotonic())) as response:
                if not 200 <= response.status < 300 or len(response.read(4097)) > 4096:
                    raise SafetyError("delete_response_uncertain")
    except Exception:
        raise SafetyError("delete_request_outcome_uncertain") from None


def _send_episode_search(api, episode_ids):
    """One Sonarr command, no redirect/retry; no release or indexer is selected here."""
    if (METADATA_RETRY_RELEASE_ENABLED is not True or not any(flag is True for flag in (
            SINGLE_TEST_RELEASE_ENABLED, PUBLIC_ATTEMPT_RELEASE_ENABLED, ROUTINE_RELEASE_ENABLED))):
        raise SafetyError("live_execution_disabled")
    if (not isinstance(episode_ids, list) or not episode_ids or len(episode_ids) > 10000
            or any(not integer(i) or i <= 0 for i in episode_ids) or len(set(episode_ids)) != len(episode_ids)):
        raise SafetyError("invalid_episode_search")
    payload = json.dumps({"name": "EpisodeSearch", "episodeIds": episode_ids}).encode()
    request = urllib.request.Request(api.config["url"].rstrip("/") + "/api/v3/command", data=payload,
        headers={"X-Api-Key": api.config["api_key"], "Content-Type": "application/json"}, method="POST")
    deadline = min(api.deadline or float("inf"), time.monotonic() + 15)
    try:
        with hard_deadline(deadline):
            with urllib.request.build_opener(RejectDeleteRedirect()).open(
                    request, timeout=min(15, deadline - time.monotonic())) as response:
                raw = response.read(65537)
                if not 200 <= response.status < 300 or len(raw) > 65536:
                    raise ValueError()
                result = json.loads(raw, object_pairs_hook=unique_response_keys)
                if (not isinstance(result, dict) or not integer(result.get("id")) or result["id"] <= 0
                        or result.get("name") != "EpisodeSearch"):
                    raise ValueError()
                body = result.get("body")
                ids = body.get("episodeIds") if isinstance(body, dict) else None
                if (not isinstance(ids, list) or any(not integer(i) or i <= 0 for i in ids)
                        or sorted(ids) != sorted(episode_ids)):
                    raise ValueError()
                return result["id"]
    except Exception:
        raise SafetyError("episode_search_outcome_uncertain") from None


def metadata_policy(report):
    """Metadata retrieval is not malware evidence; no timeout-based blocklisting."""
    if report.get("reasons") != ["metadata_timeout"]:
        return None
    if METADATA_RETRY_RELEASE_ENABLED is not True:
        raise SafetyError("metadata_retry_not_released")
    return {"blocklist": False, "search": "EpisodeSearch"}


def metadata_history_type(event):
    """Known v4 history types only; Unknown=0 is not a safe non-grab exclusion."""
    try:
        return history_event_type(event)
    except GuardError:
        raise SafetyError("replacement_history_event_invalid") from None


def check_replacement_grabs(events, context, not_before):
    for event in events:
        series = event.get("seriesId")
        if integer(series) and series > 0:
            if series != context["series_id"]:
                continue
            episode = event.get("episodeId")
            if integer(episode) and episode > 0 and episode not in context["episode_ids"]:
                continue
        if metadata_history_type(event) != "grabbed":
            continue
        # A late grab can belong to the refreshed outcome baseline. Its
        # presence can still make a new search redundant.
        if event["id"] in context["baseline_history_ids"] and event_after(event, not_before) is False:
            continue
        if any(not integer(event.get(field)) or event[field] <= 0 for field in ("seriesId", "episodeId")):
            raise SafetyError("replacement_history_identity_invalid")
        after = event_after(event, not_before)
        if after is None:
            raise SafetyError("replacement_history_ambiguous")
        if after is False:
            continue
        data = event.get("data")
        name = data.get("downloadClientName") if isinstance(data, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise SafetyError("replacement_client_unknown")
        if digest(name) != context["client_name_digest"]:
            continue
        torrent_hash(event.get("downloadId"))
        raise SafetyError("replacement_already_grabbed")


def check_metadata_blocklist(rows, context, not_before):
    blocklisted = blocklist_observation(rows, context, not_before, any_episode=True)
    if blocklisted is not False:
        raise SafetyError("replacement_blocklisted" if blocklisted else "replacement_blocklist_uncertain")


def finish_replacement_search(config, qb, apis, journal, row, validate):
    """Only the original removal coordinator can request a replacement search."""
    if row["stage"] != "retry_removed" or "metadata_retry" not in row["context"]:
        return row
    if replacement_already_observed(row):
        return journal.transition(row["key"], "retry_removed", "retry_superseded")
    row = journal.transition(row["key"], "retry_removed", "retry_search_recorded")
    c = row["context"]
    try:
        if "metadata_search_hold" in c:
            raise SafetyError(c["metadata_search_hold"])
        if row["confirmed"].get("replacement_grab_ambiguous") is True:
            raise SafetyError("replacement_history_ambiguous")
        # Only a complete observation can rule out a replacement at this point.
        if row["current_observation"].get("replacement_grab_observed") is not False:
            raise SafetyError("replacement_history_unavailable")
        require_connectivity(config, apis[c["instance"]], c["instance"])
        # The first absence observation is insufficient if another actor has
        # re-added the hash or queued a replacement while intent was committed.
        torrent, _ = observed_torrent(qb, c)
        if torrent is not None:
            raise SafetyError("target_reappeared")
        queue = records(apis[c["instance"]], "/api/v3/queue",
                        {"includeUnknownSeriesItems": "true"}, config.get("max_pages", 20))
        original_rows = {tuple(row) for row in c.get("queue_rows", ())}
        for queued in queue:
            if not integer(queued.get("seriesId")) or queued["seriesId"] <= 0:
                raise SafetyError("replacement_queue_identity_invalid")
            # Sonarr permits unmapped episode IDs. A known different series is
            # already unrelated; only potentially affected rows need episode IDs.
            if queued["seriesId"] != c["series_id"]:
                continue
            if not integer(queued.get("episodeId")) or queued["episodeId"] <= 0:
                raise SafetyError("replacement_queue_identity_invalid")
            if queued["episodeId"] not in c["episode_ids"]:
                continue
            try:
                queued_hash = torrent_hash(queued.get("downloadId"))
            except GuardError:
                raise SafetyError("replacement_already_queued") from None
            if (queued["id"], queued["episodeId"], queued_hash) not in original_rows:
                raise SafetyError("replacement_already_queued")
        # Queue visibility can lag a successful grab. Refresh history AFTER the
        # search-intent commit too; any affected episode already grabbed makes
        # searching the whole set redundant. This is request evidence only,
        # not proof of original removal, successful download or import.
        events = history_since(apis[c["instance"]], c["window_start"])
        client = bound_client(config, apis[c["instance"]], c["instance"])
        if client["id"] != c["client_id"] or digest(client["name"]) != c["client_name_digest"]:
            raise SafetyError("identity_or_manifest_changed")
        check_replacement_grabs(events, c, row["dispatched_at"])
        require_sonarr_v4(apis[c["instance"]])
        if (binding_digest(config, c["instance"]) != c["binding_digest"] or
                endpoint_key(apis[c["instance"]].config["url"]) != endpoint_key(config["sonarr"][c["instance"]]["url"])):
            raise SafetyError("identity_or_manifest_changed")
        blocks = blocklist_records(apis[c["instance"]], c["series_id"], row["dispatched_at"],
                                  config.get("max_pages", 20))
        check_metadata_blocklist(blocks, c, row["dispatched_at"])
        readiness = read_readiness({c["instance"]: apis[c["instance"]]})[c["instance"]]
        if any(readiness[field] is not True for field in ("automatic_retry", "interactive_retry")):
            raise SafetyError("retry_settings_not_ready")
        validate()
        if METADATA_RETRY_RELEASE_ENABLED is not True:
            raise SafetyError("live_execution_disabled")
    except Exception as error:
        reason = str(error) if isinstance(error, (SafetyError, GuardError)) else "dispatch_validation_failed"
        if reason not in DISPATCH_STOP_REASONS:
            reason = "dispatch_validation_failed"
        return journal.transition(row["key"], "retry_search_recorded", "retry_search_blocked", stop_reason=reason)
    try:
        command_id = _send_episode_search(apis[c["instance"]], c["episode_ids"])
        return journal.record_search_accepted(row["key"], command_id)
    except Exception:
        return journal.transition(row["key"], "retry_search_recorded", "retry_search_uncertain")


def execute_single_test(config, qb, apis, journal, report, approval):
    """Disabled production coordinator. No approval file or CLI live mode exists."""
    return _execute(config, qb, apis, journal, report, approval, "single_test")


def execute_public_attempt(config, qb, apis, journal, report, approval):
    """Disabled per-attempt sender; still requires exact short-lived approval.

    No automatic policy approval is inferred from a timer or a previous approval.
    """
    return _execute(config, qb, apis, journal, report, approval, "public_attempt")


def execute_routine_attempt(config, qb, apis, journal, report, authority):
    """Explicit delegated permission still produces an expiring per-action token."""
    from authorization import RoutineAuthorization
    import secrets
    if not isinstance(authority, (ContainerAuthorization, RoutineAuthorization)):
        raise SafetyError("routine_authorization_invalid")
    authority.validate(config, report)
    # Each action still needs an exact short-lived execution token.
    approval = {k: report[k] for k in ("instance", "hash", "ownership_fingerprint", "manifest_fingerprint")}
    approval.update(operation="sonarr_fail_remove_retry", nonce=secrets.token_hex(32),
                    expires_at=authority.execution_expiry())
    return _execute(config, qb, apis, journal, report, approval, "public_attempt", authority=authority)


def _enabled(config, journal, mode, authority=None):
    if authority is not None:
        return (mode == "public_attempt" and ROUTINE_RELEASE_ENABLED is True
                and config.get("dry_run") is False and journal.allow_public_attempt)
    return config.get("dry_run") is False and (
        (mode == "single_test" and SINGLE_TEST_RELEASE_ENABLED is True and journal.allow_single_test)
        or (mode == "public_attempt" and PUBLIC_ATTEMPT_RELEASE_ENABLED is True and journal.allow_public_attempt))


def confirmed_successor(previous, report, config):
    """A current validated grab can supersede a hold on an older incarnation.

    No release from a hash/name/file match alone, missing new-grab identity, or a
    changed downloader binding. Earlier observations and stages remain intact.
    """
    if config is None or previous["dispatched_at"] is None:
        return False
    prior = previous["context"]
    anchors = prior.get("grab_ids") or prior.get("baseline_history_ids")
    grab_time = report.get("grab_time_floor")
    return bool(valid_digest(report.get("attempt_fingerprint"))
                and prior.get("binding_digest") == binding_digest(config, report["instance"])
                and integer(report.get("download_added_on"))
                and report["download_added_on"] > previous["dispatched_at"]
                and report["download_added_on"] > prior.get("download_added_on", 0)
                and isinstance(grab_time, (int, float)) and not isinstance(grab_time, bool)
                and math.isfinite(grab_time) and grab_time > previous["dispatched_at"]
                and report.get("grab_ids") and (not anchors or min(report["grab_ids"]) > max(anchors))
                and report.get("attempt_fingerprint") != previous["evidence"].get("attempt_fingerprint"))


def check_prior_attempts(journal, report, approval_digest=None, config=None):
    binding = binding_digest(config, report["instance"]) if config is not None else None
    for previous in journal.related(report["instance"], report["hash"], report.get("hash_aliases", ()),
                                    binding=binding):
        if previous["stage"] in ("cancelled", "dispatch_blocked"):
            if approval_digest is not None and previous["context"].get("approval_digest") == approval_digest:
                raise SafetyError("approval_already_consumed")
            continue
        if confirmed_successor(previous, report, config):
            continue
        if previous["stage"] in ("cleanup_resolved", "complete", "retry_requested", "retry_superseded"):
            raise SafetyError("new_attempt_not_confirmed")
        raise SafetyError("previous_attempt_unresolved")


def _execute(config, qb, apis, journal, report, approval, mode, authority=None):
    if not _enabled(config, journal, mode, authority):
        raise SafetyError("live_execution_disabled")
    def validate():
        journal.check_current_file()
        if not _enabled(config, journal, mode, authority):
            raise SafetyError("live_execution_disabled")
        if authority is not None:
            authority.validate(config, report)
            if isinstance(authority, ContainerAuthorization):
                journal.check_installation_id(authority.journal_id)
        validate_approval(approval, report)
    validate()
    with open_lock_file(journal.path.parent / "guard.lock") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafetyError("another_run_is_active") from None
        identity = [mode, report["instance"], report["hash"]]
        if mode == "public_attempt":
            if not valid_digest(report.get("attempt_fingerprint")):
                raise SafetyError("attempt_identity_required")
            identity.append(report["attempt_fingerprint"])
            identity.append(digest(approval["nonce"]))
        key = digest(identity)
        old = journal.get(key)
        if old is not None:
            if old["stage"] == "prepared":
                return journal.transition(key, "prepared", "cancelled", stop_reason="abandoned_before_dispatch")
            verifier = OutcomeVerifier(config, qb, apis, old["context"], old["dispatched_at"])
            return reconcile(journal, key, verifier.observe)
        if file_policy_removal(report):
            raise SafetyError("native_file_cleanup_requires_routine")
        reason = workflow.manual_handling_reason(report)
        if reason is not None:
            raise SafetyError(reason)
        # Both sender modes share related-record holds. A single-test approval
        # must never provide an alternate route around a public-attempt hold.
        # Recovery of this exact existing operation above remains read-only.
        check_prior_attempts(journal, report, digest(approval["nonce"]), config=config)
        require_connectivity(config, apis[report["instance"]], report["instance"])
        fresh = recheck_candidate(report, config, qb, apis)
        check_fresh(report, fresh)
        reason = workflow.manual_handling_reason(fresh["assessment"])
        if reason is not None:
            raise SafetyError(reason)
        context = capture_context(config, apis[report["instance"]], fresh["assessment"], digest(approval["nonce"]))
        if authority is not None:
            context["routine_grant_digest"] = authority.identifier
        row = journal.prepare(report, mode=mode, context=context)
        try:
            final_snapshot = recheck_candidate(report, config, qb, apis)
            check_fresh(report, final_snapshot)
            validate()
            require_connectivity(config, apis[report["instance"]], report["instance"])
        except Exception as error:
            reason = str(error) if isinstance(error, (SafetyError, GuardError)) else "cancellation_validation_failed"
            if reason not in CANCELLATION_STOP_REASONS:
                reason = "cancellation_validation_failed"
            return journal.transition(row["key"], "prepared", "cancelled", stop_reason=reason)
        row = journal.transition(row["key"], "prepared", "dispatch_recorded")
        # FULL-sync commits and requests may take time. Re-read permission
        # after them, then check the local expiry and freshness before send.
        try:
            wait_for_event_boundary(row["dispatched_at"])
            check_fresh(report, final_snapshot)
            validate()
            # Recheck after waiting. Refresh and durably retain the baselines so
            # events already present before this send cannot become its outcome.
            final_snapshot = recheck_candidate(report, config, qb, apis)
            check_fresh(report, final_snapshot)
            reason = workflow.manual_handling_reason(final_snapshot["assessment"])
            if reason is not None:
                raise SafetyError(reason)
            validate()
            refreshed_context = capture_context(config, apis[report["instance"]],
                final_snapshot["assessment"], digest(approval["nonce"]),
                dispatch=row)
            if authority is not None:
                refreshed_context["routine_grant_digest"] = authority.identifier
            row = journal.refresh_baselines(row["key"], refreshed_context)
            context = row["context"]
            require_connectivity(config, apis[report["instance"]], report["instance"])
            require_sonarr_v4(apis[report["instance"]])
            if not _enabled(config, journal, mode, authority):
                raise SafetyError("live_execution_disabled")
            if (binding_digest(config, report["instance"]) != context["binding_digest"] or
                    endpoint_key(apis[report["instance"]].config["url"]) !=
                    endpoint_key(config["sonarr"][report["instance"]]["url"])):
                raise SafetyError("identity_or_manifest_changed")
            if not removal_without_blocklist(context):
                check_blocklist_scope(apis[report["instance"]],
                                      final_snapshot["assessment"]["download_id_spelling"], context,
                                      config.get("max_pages", 20))
            else:
                require_current_metadata_timeout(qb, context, config["sonarr"][report["instance"]]["category"])
            validate()
            check_fresh(report, final_snapshot)
            if not event_boundary_reached(row["dispatched_at"]):
                raise SafetyError("dispatch_clock_unavailable")
        except Exception as error:
            reason = str(error) if isinstance(error, (SafetyError, GuardError)) else "dispatch_validation_failed"
            if reason not in DISPATCH_STOP_REASONS:
                reason = "dispatch_validation_failed"
            return journal.transition(row["key"], "dispatch_recorded", "dispatch_blocked", stop_reason=reason)
        try:
            if removal_without_blocklist(context):
                _send_queue_delete(apis[report["instance"]], context["queue_id"], blocklist=False)
            else:
                _send_queue_delete(apis[report["instance"]], context["queue_id"])
        except Exception:
            journal.transition(row["key"], "dispatch_recorded", "uncertain")
        row = reconcile(journal, row["key"], OutcomeVerifier(config, qb, apis, context, row["dispatched_at"]).observe)
        return finish_replacement_search(config, qb, apis, journal, row, validate)


def main():
    parser = argparse.ArgumentParser(description="Read-only production checks; never sends live requests")
    parser.add_argument("--config", required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preflight", nargs=2, metavar=("INSTANCE", "HASH"))
    group.add_argument("--observe", nargs=2, metavar=("INSTANCE", "HASH"),
                       help="Reconcile an existing single-test journal entry without sending")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        deadline = time.monotonic() + 180
        qb = Api(config["qbittorrent"], deadline=deadline)
        apis = {k: Api(v, deadline=deadline) for k, v in config["sonarr"].items()}
        selection = args.preflight or args.observe
        target = (selection[0], torrent_hash(selection[1]))
        if args.preflight and target[0] not in apis:
            raise SafetyError("unknown_sonarr_instance")
        if args.observe:
            with open_lock_file(args.config.parent / "guard.lock") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise SafetyError("another_run_is_active") from None
                directory = args.config.parent
                journal_id = (read_bound_container_journal_id(directory)
                              if read_container_journal_binding(directory) is not None
                              else read_container_journal_id(directory))
                try:
                    journal = Journal(args.config.parent / ACTION_JOURNAL_FILE, existing_only=True,
                                      expected_installation_id=journal_id)
                except FileNotFoundError:
                    raise SafetyError("no_recorded_single_test") from None
                try:
                    key = digest(["single_test", target[0], target[1]])
                    row = journal.get(key)
                    if row is None:
                        raise SafetyError("no_recorded_single_test")
                    qb.login()
                    verifier = OutcomeVerifier(config, qb, apis, row["context"], row["dispatched_at"])
                    row = reconcile(journal, key, verifier.observe)
                    print(json.dumps({"live_sender_enabled": False, "instance": target[0], "hash": target[1],
                                      "stage": row["stage"], "confirmed": row["confirmed"],
                                      "stop_reason": row["stop_reason"],
                                      "observation": row["observation"], "current_observation": row["current_observation"],
                                      "observation_available": row["observation_available"]}))
                    return 0
                finally:
                    journal.close()
        qb.login()
        result = {"dry_run": True, "live_sender_enabled": False, "instance": target[0], "hash": target[1]}
        with hard_deadline(deadline):
            reports = run(config, qb, apis, target=target)
            if len(reports) != 1:
                raise SafetyError("target_not_in_owned_queue")
            report = reports[0]
            reason = workflow.manual_handling_reason(report)
            if reason is not None:
                result.update(preflight="manual_review", reason=reason)
            elif file_policy_removal(report):
                fresh = recheck_candidate(report, config, qb, apis)
                check_fresh(report, fresh)
                api = apis[target[0]]
                require_sonarr_v4(api)
                check_visible_native_grabs(api, config["sonarr"][target[0]], fresh["assessment"],
                                           config.get("max_pages", 20))
                result.update(preflight="verified", operation="sonarr_remove_and_blocklist")
            else:
                fresh = recheck_candidate(report, config, qb, apis)
                check_fresh(report, fresh)
                context = capture_context(config, apis[target[0]], fresh["assessment"], digest("preflight_only"))
                observation = OutcomeVerifier(config, qb, apis, context).observe()
                result.update(preflight="verified", observation=observation,
                              data_deletion_note="requires_independent_verification")
        print(json.dumps(result))
        return 0
    except (SafetyError, GuardError) as e:
        print(json.dumps({"dry_run": True, "error": str(e)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"dry_run": True, "error": "preflight_failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
