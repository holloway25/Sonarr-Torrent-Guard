# Explicit unattended public trial

`routine.py` is the actual unattended entry point. Unlike `public.py`, it may
send qualifying actions under a separate explicit routine grant; it does not ask
the user for a new approval per torrent or reuse a controlled-test approval.
This is a bounded trial, not indefinite live permission. Unit defaults and the
ordinary guard/public commands remain non-live.

## Required grant

The operator must issue an external `routine-authorization.json` only after
approving the reviewed code and configured public workflow. The file and parent
directory must be owner-private, outside the checkout. It contains exactly:

- `enabled`: true only for an explicitly approved trial.
- `rule`: `public-sonarr-cleanup-v2` (includes the explicitly agreed metadata timeout).
- `grant_id`: a random lowercase 64-hex identifier, not an API credential.
- `issued_at`, `expires_at`: UTC epoch times, no longer than 48 hours apart.
- `scope_digest`: `authorization.scope_digest(config)` for the approved configuration.
- `code_digest`: `authorization.code_digest()` for the reviewed application files.

There is no automatically issued or installed grant. Missing, disabled, expired,
future-dated, malformed, publicly readable or wrong-code grants fail closed.
The scope binds all Sonarr/downloader endpoints, pinned clients, categories,
public/private source lists, work/page limits and minimum age without storing raw
deployment details in the grant. Secret rotations alone do not expand scope.
Source changes require a new reviewed grant. Grant contents are immutable within
an active run; scope and expiry are revalidated at every dispatch phase, including
after journal commits. Permission is loaded once per run: remove/disable the file
to prevent the next run; stop the service as well to interrupt an in-flight run.

## One pass

Explicit `--live` and a valid grant are both required. The CLI enables only its
process-local routine gate, restoring it on exit; manual/test gates stay disabled.
Normal stored connection configuration stays dry-run. The cycle first locks and
checks Sonarr-side connectivity, assesses a bounded fair batch, and performs
bounded rotating read-only recovery. It then releases that assessment lock and
uses the existing locked coordinator for each eligible snapshot. Concurrent
workers may cause a hold, but cannot bypass fresh checks or duplicate dispatch.

Only the current pass's assessed attempts are handled. Replacements are checked
on a later ten-minute run, never chased in an inner loop. All existing client,
public-source, age, manifest, retry, version, endpoint, timestamp alignment,
baseline, expiry and durable-intent guards remain. Public removal/data removal,
blocklisting and native retries are requested through owning Sonarr only.

Per-action execution tokens are generated under this delegated permission, bound
to one assessment and capped by the grant expiry. They are not fabricated human
test approvals. Each action context records the routine-grant digest so the
authority can be correlated with the protected external grant and operational
reports. Save the issued grant with operational records outside the repository.

## Old holds versus new grabs

Uncertainty still prevents a repeat send against the SAME attempt. A newly
validated Sonarr attempt can supersede an older hold only if its downloader
addition and all latest episode-grab timestamps are strictly after the earlier
dispatch, its attempt fingerprint differs, and the normalized Sonarr/downloader
binding is unchanged. Grab IDs must also advance beyond retained earlier IDs
where available. Legacy records may lack those IDs; strictly later grab-time and
addition evidence is still mandatory. Dates are bound into the fresh ownership
fingerprint. A renamed torrent, file match or hash match alone never releases a hold.

This is not an automatic rewriting of uncertain historical results. Old stages,
observations and confirmations remain intact; the independently proven new
incarnation is assessed on its own merits. A changed endpoint, missing provenance,
same-second ambiguous grab date, manual re-add using old history, or unchanged
addition time remains held. Both manual sender modes use these same rules.

## Public metadata timeout

The v2 rule may fail a confirmed public Sonarr-owned attempt still in `metaDL` or
`forcedMetaDL` after 30 elapsed minutes since addition. qBittorrent's active-time
counter is not used: it can stall during metadata retrieval. It requires zero
progress, unknown total size (-1 or 0), and a successfully retrieved EMPTY file
list. Contradictory size/progress/files, API failures, other transitional states and paused/stopped
downloads are not evidence for this rule. Private/unknown sources, unmatched
downloads and wrong clients remain protected before timeout assessment.
The elapsed age includes earlier pauses; a resumed, still-unresolved magnet
older than the limit can qualify immediately, but cannot qualify while stopped.

`metadata_timeout` is a failed metadata-retrieval outcome, NOT proof of malware.
An empty list here is not classified as all-files-unselected. The metadata sentinel
is separately fingerprinted; if metadata arrives before dispatch, the fresh
check cancels this action (even if the now-visible files independently qualify)
and a later pass reassesses the files. Owning Sonarr alone removes/blocklists and
handles native retry. No DHT/PeX/tracker settings are changed. New rule/code/scope
digests require reissuing explicit permission; an existing trial deadline must
not be extended merely to deploy the fix.

## Scheduling, reporting and bounds

`deploy/sonarr-torrent-guard-live.service` and `.timer` are user-unit templates,
not automatically installed. They invoke the real worker with an explicit grant,
start after activation and run ten minutes after completion, without catch-up
bursts. User-service persistence after reboot requires operator-managed user
service setup. Review installation paths rather than copying private deployment
paths into source. Public dry-run units remain separate.

The worker logs each finished/held action immediately and a cycle summary to
owner-private rotating `routine.log` beside the configuration. It also prints a
sanitized summary for the service journal. This preserves evidence of earlier
actions even if the shared three-minute deadline interrupts a later action.
Waiting, grant expiry/code mismatch and held results are visible; no credentials,
raw endpoints or file paths are logged. No application file deletion is added.

Pre-dispatch validation failures retain `stage: cancelled`, an exact allowlisted
`stop_reason` and the grant reference in both the private journal and routine
action report. Unknown errors use `cancellation_validation_failed`; raw exception
text is never logged. Cancellation is definitely unsent and has no dispatch
timestamp. Existing legacy cancellations without a reason are left unchanged.

Trial expiry stops new actions automatically, though an installed timer may keep
recording waiting runs until disabled. Journal capacity remains 1000 rows and
fails closed when full; no old or uncertain action is purged. This bounds the
trial safely without introducing an unreviewed retention policy. Indefinite
operation still needs reviewed archive/retention management and renewed authority.
