# Metadata-only removal and retry: review candidate

This is a disabled implementation for code review, not authorization to deploy
or send requests. `METADATA_RETRY_RELEASE_ENABLED` remains false. Review and
explicit deployment approval, plus a new code/scope-bound v3 routine grant, are
required. Existing live checkouts/grants are not changed automatically.

## Policy

Keep the existing 30-minute eligibility test: elapsed time since qBittorrent
addition, current metaDL/forcedMetaDL, zero progress, unknown size and a
successfully read empty file list. Ownership, exact client/endpoints, known public
source, age, retry readiness, supported Sonarr version and fresh fingerprints
remain mandatory. Private/unknown, manual/unowned, paused/stopped or inconsistent
downloads remain protected. Metadata arrival before dispatch cancels the action.

Metadata unavailability is not proof of malware. Request owning Sonarr remove
the current download without blocklisting, then ask Sonarr to search its affected
episode IDs once. Sonarr uses its normal quality/custom-format scoring and may
choose the same release, another release, or nothing. A later proven new attempt
is checked on a later scheduled pass. There is **no three-attempt hard failure**,
no hash/indexer timeout ban and no new attempt-counter database. Repeated metadata
timeouts may therefore lead to repeated searches until the trial expires or the
existing bounded journal reaches capacity and fails closed.

File-policy failures are unchanged: immediately blocklist and let Sonarr's native
failed-download retry run. Never add a second search for those failures. Existing
blocklist entries are not removed or bypassed: Sonarr can reject the same known
hash across indexers for the series. No direct qBittorrent deletion, file deletion,
selection, resume, tracker/DHT change, indexer selection or scoring change is added.

## Requests and evidence

For metadata-only timeouts, the locked coordinator persists a validated immutable
`metadata_retry` context (`blocklist: false`, `search: EpisodeSearch`) alongside
the existing attempt identity, exact episode IDs, owner/binding, baselines and
grant reference. All pre-dispatch checks and cancellation reasons still apply.

```text
DELETE /api/v3/queue/{currentQueueId}
removeFromClient=true
blocklist=false
skipRedownload=true
changeCategory=false
```

In the reviewed Sonarr v4 source, `blocklist=false` means this request does not
mark the download failed or invoke native failed-download retry. Thus failure and
blocklist observations may correctly be false; never invent positive evidence.
`retry_removed` requires a CURRENT positive original-incarnation absence
observation, not queue disappearance, HTTP success or historical confirmation.
Unexpected positive blocklisting requires manual review. Data deletion stays
unknown and remains Sonarr's responsibility.

If a new replacement grab has already been positively observed, mark
`retry_superseded` and do not search again. Otherwise durably record
`retry_search_recorded` BEFORE the second request. After this commit, repeat
Sonarr-side connectivity, reviewed version and endpoint checks; reject a
reappearing original hash or newly queued affected episode. A stale original
queue row alone is ignored only while qBittorrent confirms that hash is absent.
Refresh replacement grab history after the intent commit as well: queue
visibility can lag history. A new post-removal-intent grab for ANY affected
episode from the bound client (same hash or different hash) suppresses the entire
extra search with `replacement_already_grabbed`. Baseline/pre-intent/other-client
grabs do not qualify. Unavailable, malformed or ambiguous relevant history
blocks the search rather than treating missing evidence as no replacement.
For a new relevant grab, missing/non-object `data`, missing/non-string/blank
`downloadClientName` blocks with `replacement_client_unknown`. Only a valid
nonblank different client name may be excluded; unknown identity is not a
different client. Pre-intent grabs remain excluded before that identity check.
Revalidate the exact execution token, routine permission and live gates
immediately before transport. No network/disk work follows those final local
permission checks before the search call.

```json
{"name":"EpisodeSearch","episodeIds":[123]}
```

The second request is POST `/api/v3/command` to the same owning Sonarr endpoint.
It never performs a full-series search. The bounded response must contain a
positive integer command ID, `name: EpisodeSearch` and the exact episode IDs in
`body.episodeIds`. Store the command receipt as `search_command_id` and mark
`retry_requested`. This proves command acceptance only, NOT completion, a new
download, successful import or safe replacement.

Both transports refuse redirects and automatic HTTP retries. Authorization is
checked separately for removal and search; it may expire between them. A
definitely unsent search is `retry_search_blocked` with an allowlisted reason.
A lost/malformed search response or failed receipt commit becomes
`retry_search_uncertain`; the search may have happened and must never be blindly
repeated. An interruption before recording that result can leave
`retry_search_recorded` with the same conservative meaning.

## Recovery and deployment boundaries

Recovery remains read-only: it may confirm removal and reach `retry_removed`,
but it never issues a deferred search. Crashes between removal and search, lost
responses, or blocked searches need operator inspection; leaving a download
absent is preferable to duplicate commands. No replay of either request occurs.
Restart tests reopen the journal and re-enter the actual coordinator at both
`retry_removed` and `retry_search_recorded`, not just the reconciliation helper.
The same attempt remains held. Strictly newer proven Sonarr grabs may supersede
older holds under the existing identity/time/binding rules without erasing them.

The existing SQLite migration only adds the nullable command receipt column;
old context/observations/keys remain unchanged. Legacy metadata failures are not
reclassified or unblocked. Journal capacity and no-purge rules remain in force.
Routine action logs include policy, command receipt, grant reference and safe
stop reason, without raw exception strings or deployment secrets.

Before activation, review mocks for both transports, changed metadata, expiry
after commits, outage/version drift, partial results, receipt validation and
restart/no-replay behavior. This branch has not established live integration.
Deploy only after user approval, stopping the worker first and preserving the
already approved trial deadline when issuing the new grant.

Source references for the supported version:

- [Queue removal](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs)
- [Command submission](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Commands/CommandController.cs)
- [Command resource](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Commands/CommandResource.cs)
- [Blocklist matching](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Blocklisting/BlocklistService.cs)
