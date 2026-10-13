"""Human-readable stdout and versioned, title-free JSON report events."""

import collections
import json


REASONS = {
    "contains_exe": "contains an .exe (selected or unselected)",
    "contains_scr": "contains an .scr (selected or unselected)",
    "all_files_unselected": "all files are unselected",
    "only_txt_nfo_selected": "only .txt/.nfo files are selected",
    "private_source_protected": "private source protected",
    "unclassified_source_protected": "source has not been classified",
    "work_limit_reached": "deferred to a later batch",
    "sonarr_downloader_binding_mismatch": "Sonarr downloader no longer matches its binding",
    "torrent_too_new_or_age_unknown": "torrent is too new or its age is unknown",
    "metadata_or_transitional_state": "metadata/state is not ready for assessment",
}


def display(value):
    # Quotes and ASCII escapes prevent titles/config labels injecting terminal
    # controls, new lines or bidi formatting. Limit optional title display size.
    return json.dumps(str(value)[:320], ensure_ascii=True)


def human_report(reports, readiness, timestamp):
    counts = collections.Counter(r["decision"] for r in reports)
    lines = ["DRY RUN — no torrent or Sonarr changes", "Checked: " + timestamp,
             "Summary: {0} failure candidates, {1} kept, {2} skipped/deferred".format(
                 counts["would_fail"], counts["keep"], counts["skip"])]
    for label, state in readiness.items():
        if state.get("status") != "verified":
            message = "retry settings unavailable; future live workflow blocked"
        elif state.get("automatic_retry") is not True:
            message = "automatic retry OFF; future replacement workflow blocked"
        elif state.get("interactive_retry") is not True:
            message = "interactive retry OFF; future workflow needs review"
        else:
            message = "automatic and interactive retries ON (read-only check)"
        lines.append(display(label) + ": " + message)
    for report in reports:
        decision = {"would_fail": "WOULD FAIL", "keep": "KEEP", "skip": "SKIP"}[report["decision"]]
        reasons = report.get("reasons") or [report.get("reason", "useful selected files; no .exe/.scr")]
        explanation = "; ".join(REASONS.get(r, r.replace("_", " ")) for r in reasons)
        lines.append(decision + " | " + display(report["instance"]) + " | "
                     + report.get("hash", "batch")[:12] + " | " + explanation)
        if "title" in report:
            lines.append("  Title: " + display(report["title"]))
        if report["decision"] == "would_fail":
            lines.append("  Proposed after approval/checks: Sonarr removes torrent/data, blocklists and handles retry.")
            blockers = report.get("workflow", {}).get("blockers", [])
            lines.append("  Not enabled: " + ", ".join(b.replace("_", " ") for b in blockers))
    lines.append("No removal, blocklisting, replacement search or setting changes were sent.")
    return "\n".join(lines)


def json_events(reports, readiness, timestamp):
    common = {"schema_version": 1, "time": timestamp, "dry_run": True}
    for label, state in readiness.items():
        yield dict(common, event="readiness", instance=label, readiness=state)
    for report in reports:
        safe = {k: v for k, v in report.items() if k != "title"}
        yield dict(common, **safe, event="assessment")
    counts = collections.Counter(r["decision"] for r in reports)
    yield dict(common, event="summary", summary={k: counts[k] for k in ("would_fail", "keep", "skip")})
