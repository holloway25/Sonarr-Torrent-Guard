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
- `rule`: `public-sonarr-cleanup-v5` (native remove-and-blocklist for file
  failures and the separate metadata-timeout policy).
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
an active run. Guard re-reads the grant and connection file and checks scope
and expiry immediately before a removal or search request. A missing or changed grant, unreadable
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
checks Sonarr-side connectivity and assesses a bounded fair batch. The first
half of the three-minute cycle is available for connectivity and assessment.
At least the final quarter is reserved for the mandatory fresh checks and
dispatch. Guard releases the assessment lock and locks each action while
performing its final checks.

The worker acts on current candidates and checks replacements on later passes.
[File-policy cleanup](PUBLIC-WORKFLOW.md#live-file-policy-cleanup) uses Sonarr's
native Remove and Blocklist action. [Metadata retry](METADATA-RETRY.md) uses
removal without blocklisting and may request an affected-episode search during
the same pass. Logs include the grant digest for inspection.

An older grant requires review under v5 because qBittorrent’s enabled filename
exclusions now determine the selected-file rule. Later edits to that list take
effect automatically. A reviewed code update also
requires a matching grant unless the existing ongoing grant explicitly opted
into code updates within the same rule and scope. Preserve the original trial
deadline when reissuing a grant for a code update.

## Scheduling, reporting and bounds

`deploy/sonarr-torrent-guard-live.service` and `.timer` are user-unit templates,
not automatically installed. They invoke the real worker with an explicit grant,
start after activation and run ten minutes after completion, without catch-up
bursts. User-service persistence after reboot requires operator-managed user
service setup. Review installation paths rather than copying private deployment
paths into source. Public dry-run units remain separate.

The worker logs each finished/held action immediately and a cycle summary to
owner-private rotating `routine.log` beside the configuration. The active log
and its backup paths must be separate from the configuration, grant
and other reserved state files. The worker also prints a
sanitized summary for system service logs. If the shared three-minute deadline
or a handled error interrupts the live pass, the summary says `interrupted`
and includes the actions already reported. The worker saves a separate live
dispatch cursor before each attempt, so an interruption gives the next
verified candidate first turn on a later cycle.
Waiting, grant expiry/code mismatch and held results are visible; no credentials,
raw endpoints or file paths are logged. No application file deletion is added.

Live logs record accepted requests, holds and uncertain responses. A received
response is not a filesystem check. The worker prints a cycle summary separately.
Trial expiry stops new actions automatically, though an installed timer may keep
recording waiting runs until disabled.
