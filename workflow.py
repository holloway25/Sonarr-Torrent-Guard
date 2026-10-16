"""Read-only readiness checks and request previews; contains no live executor."""


def read_readiness(apis):
    result = {}
    fields = ("autoRedownloadFailed", "autoRedownloadFailedFromInteractiveSearch")
    for label, api in apis.items():
        try:
            data = api.call("/api/v3/config/downloadclient")
            if not isinstance(data, dict) or any(not isinstance(data.get(k), bool) for k in fields):
                raise ValueError()
            result[label] = {
                "status": "verified",
                "automatic_retry": data[fields[0]],
                "interactive_retry": data[fields[1]],
            }
        except Exception:
            # The real API adapter also redacts failures. Do not expose raw errors.
            result[label] = {"status": "unavailable", "automatic_retry": None, "interactive_retry": None}
    return result


def preview_failure(report, readiness):
    """Describe one future Sonarr operation per torrent, never send it.

    A preview is not authorization or a substitute for a fresh assessment.
    Both retry switches are required conservatively, regardless of grab origin.
    """
    plan = {"status": "preview_only", "live_enabled": False,
            "blockers": ["live_sender_disabled", "fresh_recheck_required"],
            "request_preview": None, "replacement_owner": "sonarr", "extra_search": False}
    ids = report.get("queue_ids")
    if (report.get("decision") != "would_fail" or report.get("public_source_confirmed") is not True
            or not isinstance(ids, list) or not ids
            or any(not isinstance(i, int) or isinstance(i, bool) or i <= 0 for i in ids)):
        plan["blockers"].append("not_a_verified_public_candidate")
        return plan
    if readiness.get("status") != "verified":
        plan["blockers"].append("retry_settings_unverified")
    else:
        if readiness.get("automatic_retry") is not True:
            plan["blockers"].append("automatic_retry_disabled")
        if readiness.get("interactive_retry") is not True:
            plan["blockers"].append("interactive_retry_disabled")
    plan["request_preview"] = {
        "method": "DELETE", "path": "/api/v3/queue/" + str(min(ids)),
        "params": {"removeFromClient": True, "blocklist": True,
                   "skipRedownload": False, "changeCategory": False},
    }
    if report.get("reasons") == ["metadata_timeout"]:
        plan["blockers"].append("explicit_metadata_retry_authorization_required")
        plan["request_preview"]["params"].update(blocklist=False, skipRedownload=True)
        plan["extra_search"] = True
        plan["search_preview"] = {"method": "POST", "path": "/api/v3/command",
                                  "body": {"name": "EpisodeSearch", "episodeIds": report["episode_ids"]},
                                  "requires": "confirmed_removal_and_fresh_authorization"}
    return plan
