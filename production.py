"""Read-only outcome verification and a disabled, exact-target single-test sender.

The command line exposes preflight only. No live approval is generated here.
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

from guard import (Api, GuardError, endpoint_key, hard_deadline, integer, load_config,
                   records, recheck_candidate, run, torrent_hash, verify_client_binding)
from safety import (Journal, SafetyError, DISPATCH_STOP_REASONS, CANCELLATION_STOP_REASONS,
                    check_fresh, evidence, reconcile, valid_digest)
from maintenance import require_connectivity


# Deliberately false until code review and explicit human approval for one test.
SINGLE_TEST_RELEASE_ENABLED = False
PUBLIC_ATTEMPT_RELEASE_ENABLED = False
ROUTINE_RELEASE_ENABLED = False
# Review candidate only: separately enable after review and deployment approval.
METADATA_RETRY_RELEASE_ENABLED = False
SUPPORTED_SONARR_VERSION = "4.0.20.3014"
CONTEXT_FIELDS = {"instance", "hash", "series_id", "episode_ids", "queue_id", "client_id",
                  "indexer", "binding_digest", "client_name_digest", "release_title_digest",
                  "window_start", "baseline_history_ids", "baseline_blocklist_ids", "approval_digest"}
ATTEMPT_CONTEXT_FIELDS = {"attempt_fingerprint", "download_added_on", "grab_ids"}
HISTORY_EVENT_TYPES = {
    1: "grabbed", 2: "seriesFolderImported", 3: "downloadFolderImported",
    4: "downloadFailed", 5: "episodeFileDeleted", 6: "episodeFileRenamed", 7: "downloadIgnored",
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_context(value):
    optional = {"routine_grant_digest", "metadata_retry"}
    if (not isinstance(value, dict) or not set(value) <= CONTEXT_FIELDS | ATTEMPT_CONTEXT_FIELDS | optional
            or set(value) - optional not in (CONTEXT_FIELDS, CONTEXT_FIELDS | ATTEMPT_CONTEXT_FIELDS)
            or (set(value) & optional and not ATTEMPT_CONTEXT_FIELDS <= set(value))):
        raise SafetyError("invalid_operation_context")
    try:
        if torrent_hash(value["hash"]) != value["hash"]:
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
    except (ValueError, TypeError, GuardError):
        raise SafetyError("invalid_operation_context") from None
    return json.loads(json.dumps(value))


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
               and c.get("enable") is True and c.get("implementation") == "QBittorrent"
               and any(isinstance(f, dict) and f.get("name") == "tvCategory" and
                       f.get("value") == item["category"] for f in c.get("fields", []))]
    if len(matches) != 1:
        raise SafetyError("ambiguous_download_client")
    verify_client_binding(item, config["qbittorrent"]["url"], matches[0])
    if not isinstance(matches[0].get("name"), str) or not matches[0]["name"]:
        raise SafetyError("missing_client_name")
    return matches[0]


def history_since(api, start):
    date = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).isoformat()
    rows = api.call("/api/v3/history/since", {"date": date})
    if (not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(r, dict)
            or not integer(r.get("id")) or r["id"] <= 0 for r in rows)
            or len({r["id"] for r in rows}) != len(rows)):
        raise SafetyError("invalid_history_response")
    return rows


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


def capture_context(config, api, report, approval_digest, now=None):
    """Capture bounded pre-dispatch baselines from the fresh, validated target."""
    evidence(report)
    if report.get("decision") != "would_fail" or report.get("public_source_confirmed") is not True:
        raise SafetyError("not_a_public_failure_candidate")
    series = report.get("series_ids")
    if not isinstance(series, list) or len(series) != 1:
        raise SafetyError("single_series_required_for_controlled_test")
    status = api.call("/api/v3/system/status")
    if not isinstance(status, dict) or status.get("version") != SUPPORTED_SONARR_VERSION:
        raise SafetyError("unreviewed_sonarr_version")
    client = bound_client(config, api, report["instance"])
    if torrent_hash(report.get("download_id_spelling")) != report["hash"]:
        raise SafetyError("invalid_history_download_id")
    grabs = records(api, "/api/v3/history", {"eventType": 1,
                    "downloadId": report["download_id_spelling"]}, config.get("max_pages", 20))
    grabs = [g for g in grabs if str(g.get("downloadId", "")).lower() == report["hash"]
             and g.get("eventType") in (1, "grabbed") and g.get("seriesId") == series[0]
             and g.get("episodeId") in report["episode_ids"]
             and g.get("id") in report["grab_ids"]]
    titles = {g.get("sourceTitle") for g in grabs}
    if (not grabs or len(titles) != 1 or not all(isinstance(t, str) and t for t in titles)
            or {g["episodeId"] for g in grabs} != set(report["episode_ids"])):
        raise SafetyError("ambiguous_release_title_evidence")
    start = (time.time() if now is None else now) - 300
    baseline_history = history_since(api, start)
    blocklist = records(api, "/api/v3/blocklist", {"seriesIds": series[0]}, config.get("max_pages", 20))
    context = {
        "instance": report["instance"], "hash": report["hash"], "series_id": series[0],
        "episode_ids": report["episode_ids"], "queue_id": min(report["queue_ids"]),
        "client_id": client["id"], "indexer": report["indexer"],
        "binding_digest": binding_digest(config, report["instance"]),
        "client_name_digest": digest(client["name"]), "release_title_digest": digest(next(iter(titles))),
        "window_start": start, "baseline_history_ids": [r["id"] for r in baseline_history],
        "baseline_blocklist_ids": [r["id"] for r in blocklist], "approval_digest": approval_digest,
    }
    context.update({k: report[k] for k in ATTEMPT_CONTEXT_FIELDS})
    return validate_context(context)


class OutcomeVerifier:
    def __init__(self, config, qb, apis, context, not_before=None):
        self.config, self.qb, self.apis = config, qb, apis
        self.context = validate_context(context)
        self.not_before = self.context["window_start"] if not_before is None else not_before

    def observe(self):
        c = self.context
        label = c["instance"]
        api = self.apis[label]
        if binding_digest(self.config, label) != c["binding_digest"]:
            raise SafetyError("observation_binding_changed")
        client = bound_client(self.config, api, label)
        status = api.call("/api/v3/system/status")
        if not isinstance(status, dict) or status.get("version") != SUPPORTED_SONARR_VERSION:
            raise SafetyError("unreviewed_sonarr_version")
        if client["id"] != c["client_id"] or digest(client["name"]) != c["client_name_digest"]:
            raise SafetyError("observation_client_changed")
        # APIs cannot prove download-side file deletion. Never infer this from absence.
        result = {k: None for k in ("torrent_absent", "data_deleted", "failed", "blocklisted", "replacement_observed")}
        current_torrent = None
        try:
            torrents = self.qb.call("/api/v2/torrents/info")
            if not isinstance(torrents, list) or any(not isinstance(t, dict) for t in torrents):
                raise ValueError()
            hashes = [torrent_hash(t.get("hash")) for t in torrents]
            if len(hashes) != len(set(hashes)):
                raise ValueError()
            result["torrent_absent"] = c["hash"] not in hashes
            current_torrent = next((t for t in torrents if torrent_hash(t["hash"]) == c["hash"]), None)
            if current_torrent is not None and "download_added_on" in c and (
                    current_torrent.get("added_on") != c["download_added_on"]):
                # A different incarnation needs corroborating new Sonarr grabs.
                result["torrent_absent"] = None
        except Exception:
            pass
        try:
            rows = history_since(api, c["window_start"])
            new = [r for r in rows if r["id"] not in c["baseline_history_ids"]]
            failed, replacement, ambiguous_failed, ambiguous_replacement = set(), set(), set(), set()
            regrab = set()
            for r in new:
                if not integer(r.get("seriesId")) or not integer(r.get("episodeId")):
                    raise SafetyError("invalid_history_identity")
                if r.get("seriesId") != c["series_id"] or r.get("episodeId") not in c["episode_ids"]:
                    continue
                after = event_after(r, self.not_before)
                if after is False:
                    continue
                data = r.get("data")
                if not isinstance(data, dict) or digest(data.get("downloadClientName")) != c["client_name_digest"]:
                    continue
                h = str(r.get("downloadId", "")).lower()
                added = current_torrent.get("added_on") if current_torrent else None
                if (r.get("eventType") in (1, "grabbed") and h == c["hash"] and after is True
                        and "grab_ids" in c and r["id"] > max(c["grab_ids"])
                        and integer(added) and added > max(c["download_added_on"], self.not_before)
                        and abs(event_time(r) - added) <= 120):
                    regrab.add(r["episodeId"])
                if (r.get("eventType") in (4, "downloadFailed") and h == c["hash"]
                        and digest(r.get("sourceTitle")) == c["release_title_digest"]):
                    (failed if after else ambiguous_failed).add(r["episodeId"])
                if r.get("eventType") in (1, "grabbed") and h != c["hash"]:
                    try:
                        torrent_hash(h)
                    except GuardError:
                        continue
                    (replacement if after else ambiguous_replacement).add(r["episodeId"])
            required = set(c["episode_ids"])
            result["failed"] = True if failed == required else (None if ambiguous_failed - failed else False)
            result["replacement_observed"] = True if replacement == required else (
                None if ambiguous_replacement - replacement else False)
            if regrab == required:
                result["torrent_absent"] = True  # Original incarnation, not all copies of this hash.
                result["replacement_observed"] = True  # Observed is not verified safe/imported.
        except Exception:
            pass
        try:
            rows = records(api, "/api/v3/blocklist", {"seriesIds": c["series_id"]}, self.config.get("max_pages", 20))
            matched, ambiguous = set(), set()
            for r in rows:
                if not integer(r.get("seriesId")):
                    raise SafetyError("invalid_blocklist_identity")
                if (r["id"] in c["baseline_blocklist_ids"] or r.get("seriesId") != c["series_id"]
                        or r.get("indexer") != c["indexer"]
                        or digest(r.get("sourceTitle")) != c["release_title_digest"]):
                    continue
                after = event_after(r, self.not_before)
                if after is False:
                    continue
                ids = r.get("episodeIds")
                if not isinstance(ids, list) or any(not integer(i) or i <= 0 for i in ids):
                    raise ValueError()
                (matched if after else ambiguous).update(set(ids) & set(c["episode_ids"]))
            result["blocklisted"] = True if matched == set(c["episode_ids"]) else (
                None if ambiguous - matched else False)
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


def _send_queue_delete(api, queue_id, blocklist=True):
    """Narrow transport; called only after the coordinator's gates and durable intent."""
    if (SINGLE_TEST_RELEASE_ENABLED is not True and PUBLIC_ATTEMPT_RELEASE_ENABLED is not True
            and ROUTINE_RELEASE_ENABLED is not True):
        raise SafetyError("live_execution_disabled")
    if not integer(queue_id) or queue_id <= 0:
        raise SafetyError("invalid_queue_id")
    if not isinstance(blocklist, bool) or (not blocklist and METADATA_RETRY_RELEASE_ENABLED is not True):
        raise SafetyError("live_execution_disabled")
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
                result = json.loads(raw)
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
    value = event.get("eventType")
    if integer(value) and value in HISTORY_EVENT_TYPES:
        return HISTORY_EVENT_TYPES[value]
    if isinstance(value, str) and value in HISTORY_EVENT_TYPES.values():
        return value
    raise SafetyError("replacement_history_event_invalid")


def finish_metadata_retry(config, qb, apis, journal, row, validate):
    """Only the original coordinator can request a search; recovery stays read-only."""
    if row["stage"] != "retry_removed":
        return row
    if row["current_observation"].get("replacement_observed") is True:
        return journal.transition(row["key"], "retry_removed", "retry_superseded")
    row = journal.transition(row["key"], "retry_removed", "retry_search_recorded")
    c = row["context"]
    try:
        require_connectivity(config, apis[c["instance"]], c["instance"])
        # The first absence observation is insufficient if another actor has
        # re-added the hash or queued a replacement while intent was committed.
        torrents = qb.call("/api/v2/torrents/info")
        if not isinstance(torrents, list) or any(not isinstance(t, dict) for t in torrents):
            raise SafetyError("dispatch_validation_failed")
        if c["hash"] in [torrent_hash(t.get("hash")) for t in torrents]:
            raise SafetyError("target_reappeared")
        queue = records(apis[c["instance"]], "/api/v3/queue", {}, config.get("max_pages", 20))
        for queued in queue:
            if any(not integer(queued.get(field)) or queued[field] <= 0 for field in ("seriesId", "episodeId")):
                raise SafetyError("replacement_queue_identity_invalid")
            if (queued["seriesId"] == c["series_id"] and queued["episodeId"] in c["episode_ids"]
                    and queued["id"] != c["queue_id"]):
                raise SafetyError("replacement_already_queued")
        # Queue visibility can lag a successful grab. Refresh history AFTER the
        # search-intent commit too; any affected episode already grabbed makes
        # searching the whole set redundant. This is request evidence only,
        # not proof of original removal, successful download or import.
        for event in history_since(apis[c["instance"]], c["window_start"]):
            event_type = metadata_history_type(event)
            if event["id"] in c["baseline_history_ids"] or event_type != "grabbed":
                continue
            # Unknown content identity cannot establish that a new grab is
            # unrelated. Reject bools, coercible strings/floats and nonpositive IDs.
            if any(not integer(event.get(field)) or event[field] <= 0 for field in ("seriesId", "episodeId")):
                raise SafetyError("replacement_history_identity_invalid")
            if event["seriesId"] != c["series_id"] or event["episodeId"] not in c["episode_ids"]:
                continue
            after = event_after(event, row["dispatched_at"])
            if after is None:
                raise SafetyError("replacement_history_ambiguous")
            if after is False:
                continue
            data = event.get("data")
            client_name = data.get("downloadClientName") if isinstance(data, dict) else None
            if not isinstance(client_name, str) or not client_name.strip():
                raise SafetyError("replacement_client_unknown")
            # Only a positively named different client may be excluded. Missing
            # identity is uncertainty, not evidence of no replacement.
            if digest(client_name) != c["client_name_digest"]:
                continue
            torrent_hash(event.get("downloadId"))
            raise SafetyError("replacement_already_grabbed")
        status = apis[c["instance"]].call("/api/v3/system/status")
        if not isinstance(status, dict) or status.get("version") != SUPPORTED_SONARR_VERSION:
            raise SafetyError("unreviewed_sonarr_version")
        if (binding_digest(config, c["instance"]) != c["binding_digest"] or
                endpoint_key(apis[c["instance"]].config["url"]) != endpoint_key(config["sonarr"][c["instance"]]["url"])):
            raise SafetyError("identity_or_manifest_changed")
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
    """Delegated permission is explicit and expiring, not a fabricated human test approval."""
    from authorization import RoutineAuthorization
    import secrets
    if not isinstance(authority, RoutineAuthorization):
        raise SafetyError("routine_authorization_invalid")
    authority.validate(config, report)
    # Exact short-lived execution token is derived under the routine grant. It
    # cannot authorize another target or outlive the grant; no user is prompted.
    approval = {k: report[k] for k in ("instance", "hash", "ownership_fingerprint", "manifest_fingerprint")}
    approval.update(operation="sonarr_fail_remove_retry", nonce=secrets.token_hex(32),
                    expires_at=min(time.time() + 120, authority.value["expires_at"]))
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
    for previous in journal.related(report["instance"], report["hash"]):
        if previous["stage"] in ("cancelled", "dispatch_blocked"):
            if approval_digest is not None and previous["context"].get("approval_digest") == approval_digest:
                raise SafetyError("approval_already_consumed")
            continue
        if previous["stage"] not in ("cleanup_resolved", "complete", "retry_requested", "retry_superseded"):
            if confirmed_successor(previous, report, config):
                continue
            raise SafetyError("previous_attempt_unresolved")
        prior = previous["context"]
        if ("download_added_on" not in prior or
                report["download_added_on"] <= prior["download_added_on"] or
                (previous["dispatched_at"] is not None and
                 report["download_added_on"] <= previous["dispatched_at"]) or
                min(report["grab_ids"]) <= max(prior["grab_ids"])):
            raise SafetyError("new_attempt_not_confirmed")


def _execute(config, qb, apis, journal, report, approval, mode, authority=None):
    if not _enabled(config, journal, mode, authority):
        raise SafetyError("live_execution_disabled")
    def validate():
        if not _enabled(config, journal, mode, authority):
            raise SafetyError("live_execution_disabled")
        validate_approval(approval, report)
        if authority is not None:
            authority.validate(config, report)
    validate()
    with open(journal.path.parent / "guard.lock", "a") as lock:
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
            verifier = OutcomeVerifier(config, qb, apis, old["context"], old["dispatched_at"])
            return reconcile(journal, key, verifier.observe)
        # Both sender modes share related-record holds. A single-test approval
        # must never provide an alternate route around a public-attempt hold.
        # Recovery of this exact existing operation above remains read-only.
        check_prior_attempts(journal, report, digest(approval["nonce"]), config=config)
        require_connectivity(config, apis[report["instance"]], report["instance"])
        fresh = recheck_candidate(report, config, qb, apis)
        check_fresh(report, fresh)
        context = capture_context(config, apis[report["instance"]], fresh["assessment"], digest(approval["nonce"]))
        policy = metadata_policy(fresh["assessment"])
        if policy is not None:
            context["metadata_retry"] = policy
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
        # FULL-sync commit and the status request may take time. There must be no
        # disk/network work between the final local expiry checks and send.
        try:
            wait_for_event_boundary(row["dispatched_at"])
            check_fresh(report, final_snapshot)
            validate()
            # Recheck after waiting. Refresh and durably retain the baselines so
            # events already present before this send cannot become its outcome.
            final_snapshot = recheck_candidate(report, config, qb, apis)
            check_fresh(report, final_snapshot)
            validate()
            refreshed_context = capture_context(config, apis[report["instance"]],
                final_snapshot["assessment"], digest(approval["nonce"]))
            refreshed_policy = metadata_policy(final_snapshot["assessment"])
            if refreshed_policy is not None:
                refreshed_context["metadata_retry"] = refreshed_policy
            if authority is not None:
                refreshed_context["routine_grant_digest"] = authority.identifier
            row = journal.refresh_baselines(row["key"], refreshed_context)
            context = row["context"]
            require_connectivity(config, apis[report["instance"]], report["instance"])
            status = apis[report["instance"]].call("/api/v3/system/status")
            if not isinstance(status, dict) or status.get("version") != SUPPORTED_SONARR_VERSION:
                raise SafetyError("unreviewed_sonarr_version")
            if not _enabled(config, journal, mode, authority):
                raise SafetyError("live_execution_disabled")
            if (binding_digest(config, report["instance"]) != context["binding_digest"] or
                    endpoint_key(apis[report["instance"]].config["url"]) !=
                    endpoint_key(config["sonarr"][report["instance"]]["url"])):
                raise SafetyError("identity_or_manifest_changed")
            check_fresh(report, final_snapshot)
            validate()
            if not event_boundary_reached(row["dispatched_at"]):
                raise SafetyError("dispatch_clock_unavailable")
        except Exception as error:
            reason = str(error) if isinstance(error, (SafetyError, GuardError)) else "dispatch_validation_failed"
            if reason not in DISPATCH_STOP_REASONS:
                reason = "dispatch_validation_failed"
            return journal.transition(row["key"], "dispatch_recorded", "dispatch_blocked", stop_reason=reason)
        try:
            if context.get("metadata_retry", {}).get("blocklist") is False:
                _send_queue_delete(apis[report["instance"]], context["queue_id"], blocklist=False)
            else:
                _send_queue_delete(apis[report["instance"]], context["queue_id"])
        except Exception:
            journal.transition(row["key"], "dispatch_recorded", "uncertain")
        row = reconcile(journal, row["key"], OutcomeVerifier(config, qb, apis, context, row["dispatched_at"]).observe)
        return finish_metadata_retry(config, qb, apis, journal, row, validate)


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
        qb.login()
        selection = args.preflight or args.observe
        target = (selection[0], torrent_hash(selection[1]))
        if target[0] not in apis:
            raise SafetyError("unknown_sonarr_instance")
        if args.observe:
            journal = Journal(args.config.parent / "action-journal.sqlite3")
            try:
                key = digest(["single_test", target[0], target[1]])
                row = journal.get(key)
                if row is None:
                    raise SafetyError("no_recorded_single_test")
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
        with hard_deadline(deadline):
            reports = run(config, qb, apis, target=target)
            if len(reports) != 1:
                raise SafetyError("target_not_in_owned_queue")
            fresh = recheck_candidate(reports[0], config, qb, apis)
            check_fresh(reports[0], fresh)
            context = capture_context(config, apis[target[0]], fresh["assessment"], digest("preflight_only"))
            observation = OutcomeVerifier(config, qb, apis, context).observe()
        print(json.dumps({"dry_run": True, "live_sender_enabled": False, "instance": target[0],
                          "hash": target[1], "preflight": "verified", "observation": observation,
                          "data_deletion_note": "requires_independent_verification"}))
        return 0
    except (SafetyError, GuardError) as e:
        print(json.dumps({"dry_run": True, "error": str(e)}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"dry_run": True, "error": "preflight_failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
