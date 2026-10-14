"""Read-only outcome verification and a disabled, exact-target single-test sender.

The command line exposes preflight only. No live approval is generated here.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import math
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request

from guard import (Api, GuardError, endpoint_key, hard_deadline, integer, load_config,
                   records, recheck_candidate, run, torrent_hash, verify_client_binding)
from safety import Journal, SafetyError, DISPATCH_STOP_REASONS, check_fresh, evidence, reconcile, valid_digest


# Deliberately false until code review and explicit human approval for one test.
SINGLE_TEST_RELEASE_ENABLED = False
SUPPORTED_SONARR_VERSION = "4.0.20.3014"
CONTEXT_FIELDS = {"instance", "hash", "series_id", "episode_ids", "queue_id", "client_id",
                  "indexer", "binding_digest", "client_name_digest", "release_title_digest",
                  "window_start", "baseline_history_ids", "baseline_blocklist_ids", "approval_digest"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_context(value):
    if not isinstance(value, dict) or set(value) != CONTEXT_FIELDS:
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
             and g.get("episodeId") in report["episode_ids"]]
    titles = {g.get("sourceTitle") for g in grabs}
    if (not grabs or len(titles) != 1 or not all(isinstance(t, str) and t for t in titles)
            or {g["episodeId"] for g in grabs} != set(report["episode_ids"])):
        raise SafetyError("ambiguous_release_title_evidence")
    start = (time.time() if now is None else now) - 300
    baseline_history = history_since(api, start)
    blocklist = records(api, "/api/v3/blocklist", {"seriesIds": series[0]}, config.get("max_pages", 20))
    return validate_context({
        "instance": report["instance"], "hash": report["hash"], "series_id": series[0],
        "episode_ids": report["episode_ids"], "queue_id": min(report["queue_ids"]),
        "client_id": client["id"], "indexer": report["indexer"],
        "binding_digest": binding_digest(config, report["instance"]),
        "client_name_digest": digest(client["name"]), "release_title_digest": digest(next(iter(titles))),
        "window_start": start, "baseline_history_ids": [r["id"] for r in baseline_history],
        "baseline_blocklist_ids": [r["id"] for r in blocklist], "approval_digest": approval_digest,
    })


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
        try:
            torrents = self.qb.call("/api/v2/torrents/info")
            if not isinstance(torrents, list) or any(not isinstance(t, dict) for t in torrents):
                raise ValueError()
            hashes = [torrent_hash(t.get("hash")) for t in torrents]
            if len(hashes) != len(set(hashes)):
                raise ValueError()
            result["torrent_absent"] = c["hash"] not in hashes
        except Exception:
            pass
        try:
            rows = history_since(api, c["window_start"])
            new = [r for r in rows if r["id"] not in c["baseline_history_ids"]]
            failed, replacement = set(), set()
            for r in new:
                if not integer(r.get("seriesId")) or not integer(r.get("episodeId")):
                    raise SafetyError("invalid_history_identity")
                if r.get("seriesId") != c["series_id"] or r.get("episodeId") not in c["episode_ids"]:
                    continue
                if event_time(r) < self.not_before:
                    continue
                data = r.get("data")
                if not isinstance(data, dict) or digest(data.get("downloadClientName")) != c["client_name_digest"]:
                    continue
                h = str(r.get("downloadId", "")).lower()
                if (r.get("eventType") in (4, "downloadFailed") and h == c["hash"]
                        and digest(r.get("sourceTitle")) == c["release_title_digest"]):
                    failed.add(r["episodeId"])
                if r.get("eventType") in (1, "grabbed") and h != c["hash"]:
                    try:
                        torrent_hash(h)
                    except GuardError:
                        continue
                    replacement.add(r["episodeId"])
            result["failed"] = failed == set(c["episode_ids"])
            result["replacement_observed"] = replacement == set(c["episode_ids"])
        except Exception:
            pass
        try:
            rows = records(api, "/api/v3/blocklist", {"seriesIds": c["series_id"]}, self.config.get("max_pages", 20))
            matched = set()
            for r in rows:
                if not integer(r.get("seriesId")):
                    raise SafetyError("invalid_blocklist_identity")
                if (r["id"] in c["baseline_blocklist_ids"] or r.get("seriesId") != c["series_id"]
                        or r.get("indexer") != c["indexer"]
                        or digest(r.get("sourceTitle")) != c["release_title_digest"]):
                    continue
                if event_time(r) < self.not_before:
                    continue
                ids = r.get("episodeIds")
                if not isinstance(ids, list) or any(not integer(i) or i <= 0 for i in ids):
                    raise ValueError()
                matched.update(set(ids) & set(c["episode_ids"]))
            result["blocklisted"] = matched == set(c["episode_ids"])
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
            or any(approval.get(k) != v for k, v in evidence(report).items())):
        raise SafetyError("approval_expired_or_target_mismatch")


class RejectDeleteRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SafetyError("delete_redirect_refused")


def _send_queue_delete(api, queue_id):
    """Narrow transport; called only after the coordinator's gates and durable intent."""
    if SINGLE_TEST_RELEASE_ENABLED is not True:
        raise SafetyError("live_execution_disabled")
    if not integer(queue_id) or queue_id <= 0:
        raise SafetyError("invalid_queue_id")
    params = {"removeFromClient": "true", "blocklist": "true", "skipRedownload": "false", "changeCategory": "false"}
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


def execute_single_test(config, qb, apis, journal, report, approval):
    """Disabled production coordinator. No approval file or CLI live mode exists."""
    if SINGLE_TEST_RELEASE_ENABLED is not True or config.get("dry_run") is not False or not journal.allow_single_test:
        raise SafetyError("live_execution_disabled")
    validate_approval(approval, report)
    with open(journal.path.parent / "guard.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafetyError("another_run_is_active") from None
        key = digest(["single_test", report["instance"], report["hash"]])
        old = journal.get(key)
        if old is not None:
            verifier = OutcomeVerifier(config, qb, apis, old["context"], old["dispatched_at"])
            return reconcile(journal, key, verifier.observe)
        fresh = recheck_candidate(report, config, qb, apis)
        check_fresh(report, fresh)
        context = capture_context(config, apis[report["instance"]], fresh["assessment"], digest(approval["nonce"]))
        row = journal.prepare(report, mode="single_test", context=context)
        try:
            final_snapshot = recheck_candidate(report, config, qb, apis)
            check_fresh(report, final_snapshot)
            validate_approval(approval, report)
        except Exception:
            return journal.transition(row["key"], "prepared", "cancelled")
        row = journal.transition(row["key"], "prepared", "dispatch_recorded")
        # FULL-sync commit and the status request may take time. There must be no
        # disk/network work between the final local expiry checks and send.
        try:
            status = apis[report["instance"]].call("/api/v3/system/status")
            if not isinstance(status, dict) or status.get("version") != SUPPORTED_SONARR_VERSION:
                raise SafetyError("unreviewed_sonarr_version")
            if (SINGLE_TEST_RELEASE_ENABLED is not True or config.get("dry_run") is not False
                    or not journal.allow_single_test):
                raise SafetyError("live_execution_disabled")
            check_fresh(report, final_snapshot)
            validate_approval(approval, report)
        except Exception as error:
            reason = str(error) if isinstance(error, (SafetyError, GuardError)) else "dispatch_validation_failed"
            if reason not in DISPATCH_STOP_REASONS:
                reason = "dispatch_validation_failed"
            return journal.transition(row["key"], "dispatch_recorded", "dispatch_blocked", stop_reason=reason)
        try:
            _send_queue_delete(apis[report["instance"]], context["queue_id"])
        except Exception:
            journal.transition(row["key"], "dispatch_recorded", "uncertain")
        return reconcile(journal, row["key"], OutcomeVerifier(config, qb, apis, context, row["dispatched_at"]).observe)


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
