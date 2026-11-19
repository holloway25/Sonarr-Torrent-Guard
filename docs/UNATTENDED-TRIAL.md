# Explicit unattended public authorization

`routine.py` is the actual unattended entry point. Unlike `public.py`, it may
send qualifying actions under a separate explicit routine grant; it does not ask
the user for a new approval per torrent or reuse a controlled-test approval.
Seven-day trials and separately approved ongoing operation are supported. Trial
permission never becomes ongoing implicitly. Unit defaults and the ordinary
guard/public commands remain non-live.

For Docker, set `STGUARD_MODE=live` to enable the routine worker. Docker uses that
switch and does not read or generate the standalone grant described here. See
[container setup](CONTAINER.md).

## Required grant for standalone workers

The operator must issue an external `routine-authorization.json` only after
approving the reviewed code and configured public workflow. The file and parent
directory must be owner-private, outside the checkout. It contains exactly:

- `enabled`: true only for explicitly approved operation.
- `rule`: `public-sonarr-cleanup-v3` (native remove-and-blocklist for file
  failures and the separate journal-based metadata policy).
- `grant_id`: a random lowercase 64-hex identifier, not an API credential.
- `issued_at`, `expires_at`: UTC epoch times, no longer than seven days apart.
  Increasing the code limit does not extend an existing grant. Any extension
  requires explicit operator approval and a newly issued grant; no automatic renewal.
- `scope_digest`: `authorization.scope_digest(config)` for the approved configuration.
- `code_digest`: `authorization.code_digest()` for the reviewed application files.
  Trials and ongoing grants require an exact match by default.

An ongoing grant additionally requires `authorization_mode: "ongoing"` and
`expires_at: null`. Its finite, non-future `issued_at`, scope and rule checks are
still required. An operator can add `"allow_code_updates": true` to an ongoing
standalone grant to authorize reviewed releases within the same scope and rule.
A scope or workflow change requires a new reviewed grant. Null expiry without
ongoing mode, duplicate keys, unknown modes and extra fields fail closed.

Missing, disabled, expired, future-dated, malformed or publicly readable grants
fail closed. A code mismatch also fails unless an ongoing grant explicitly
allows code updates.
The scope binds all Sonarr/downloader endpoints, pinned clients, categories,
source-policy mode and public/private lists, work/page limits and minimum age without storing raw
deployment details in the grant. Secret rotations alone do not expand scope.
Source changes require a new reviewed grant. Grant contents are immutable within
an active run; scope and expiry are revalidated at every dispatch phase, including
after journal commits. Guard re-reads the grant and connection file before
sending a removal or search request. A missing or changed grant, unreadable
configuration, or a changed cleanup scope blocks the request at the final check.
A request already sent can still complete.

New containers use identified sources as public except configured private
exceptions; legacy allowlist behavior is retained until explicit migration.
Missing/malformed/ambiguous source identities remain protected. Routine candidate
authorization uses the same classification as assessment, not a stale public
list membership check. See [source policy](SOURCE-POLICY.md).

## One pass

Explicit `--live` and a valid grant are both required. The CLI enables only its
process-local routine gate, restoring it on exit; manual/test gates stay disabled.
Normal stored connection configuration stays dry-run. The cycle first locks and
checks Sonarr-side connectivity, assesses a bounded fair batch, and performs
bounded rotating recovery. The first half of the three-minute cycle is available
for connectivity and assessment. Fresh proposal checks can run through the
two-thirds mark, and recovery stops before the three-quarter mark. At least
the final quarter is reserved for the coordinator's mandatory fresh checks and
dispatch. After recovery, the worker releases the assessment lock and uses the
existing locked coordinator for each eligible snapshot. Concurrent
workers may cause a hold, but cannot bypass fresh checks or duplicate dispatch.

The worker acts on candidates from the current assessment. It checks
replacements on later scheduled passes. The two live paths are:

- [File-policy cleanup](PUBLIC-WORKFLOW.md#live-file-policy-cleanup) repeats the
  ownership, source, file and grant checks, then sends Sonarr's native Remove
  and Blocklist action. Sonarr handles its own retry. If a torrent is still
  queued on a later run, Guard can act after a fresh check. This path needs
  neither an action-journal record nor a separate execution token.
- [Metadata retry](METADATA-RETRY.md) records intent in SQLite, uses a
  short-lived per-action token and can ask Sonarr for one affected-episode
  search after confirmed removal. Tokens are bound to the assessment and
  expire after at most 120 seconds or when the trial expires, whichever
  comes first. An unavailable journal holds metadata actions.

Both paths include the grant digest in the action report. Metadata also
stores that digest in its operation context. Save the issued grant with private
operational records outside the repository.

## Metadata holds and new grabs

An uncertain journal-based action holds the same attempt. A newly
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

The v3 rule may remove a confirmed public Sonarr-owned attempt still in `metaDL` or
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
and a later pass reassesses the files. The reviewed policy requests removal without
blocklisting, confirms original-incarnation absence, and then asks owning Sonarr
for one EpisodeSearch. It never escalates metadata timeouts to blocklisting.
The metadata policy gate is enabled, but sender gates and explicit permission
still apply. The v3 grant requires its own approval. Qualified file-policy failures
use [Sonarr's native remove-and-blocklist action](PUBLIC-WORKFLOW.md#live-file-policy-cleanup).
No DHT/PeX/tracker settings are changed. Rule or scope changes
require reissuing permission. Code changes require a matching grant unless an ongoing grant allows updates.
Preserve the original trial deadline when reissuing for a code update.

## Scheduling, reporting and bounds

`deploy/sonarr-torrent-guard-live.service` and `.timer` are user-unit templates,
not automatically installed. They invoke the real worker with an explicit grant,
start after activation and run ten minutes after completion, without catch-up
bursts. User-service persistence after reboot requires operator-managed user
service setup. Review installation paths rather than copying private deployment
paths into source. Public dry-run units remain separate.

The worker logs each finished/held action immediately and a cycle summary to
owner-private rotating `routine.log` beside the configuration. The active log
and its backup paths must be separate from the configuration, grant, journal
and other reserved state files. The worker also prints a
sanitized summary for the service journal. If the shared three-minute deadline
or a handled error interrupts the live pass, the summary says `interrupted`
and includes the actions already reported. The worker saves a separate live
dispatch cursor before each attempt, so an interruption gives the next
verified candidate first turn on a later cycle.
Waiting, grant expiry/code mismatch and held results are visible; no credentials,
raw endpoints or file paths are logged. No application file deletion is added.

File-policy reports use `held` for an unsent action, `uncertain` for a lost
or unverified response, and `sonarr_remove_blocklist_accepted` for acceptance.
For a journal-based action, failure before recording dispatch retains a
`cancelled` stage and an allowlisted `stop_reason`. Failure after intent but
before transport can record `dispatch_blocked`. Raw exception text is never logged.

Trial expiry stops new actions automatically, though an installed timer may keep
recording waiting runs until disabled. The 1,000-row journal capacity holds new
journal-based actions when full. File-policy cleanup evaluates the current queue
independently. Ongoing permission keeps the same bounds and leaves archival
disabled.
Inspect capacity and explicitly approve retention application when needed.
An explicit [retention candidate](JOURNAL-RETENTION.md) is now implemented with
application disabled. It preserves archived records in duplicate/ownership safety
checks and never archives unresolved records. It neither extends a trial nor
enables housekeeping or live sending automatically.
