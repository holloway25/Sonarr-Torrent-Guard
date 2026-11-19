# Metadata-only removal and retry

The reviewed policy gate `METADATA_RETRY_RELEASE_ENABLED` is enabled, but does
not authorize requests on its own. Manual/test sender gates remain disabled;
Docker requires explicit live mode. Standalone routine execution also requires
a valid scope-bound v3 grant. Ordinary commands stay dry-run.

## Policy

Keep the existing 30-minute eligibility test: elapsed time since qBittorrent
addition, current metaDL/forcedMetaDL, zero progress, unknown size and a
successfully read empty file list. Ownership, exact client/endpoints, identified
source eligibility under the configured [source policy](SOURCE-POLICY.md), age,
retry readiness, supported Sonarr version and fresh fingerprints
remain mandatory. Private/unidentified, manual/unowned, paused/stopped or inconsistent
downloads remain protected. Metadata arrival before dispatch cancels the action.

Metadata unavailability is not proof of malware. Request owning Sonarr remove
the current download without blocklisting, then ask Sonarr to search its affected
episode IDs once. Sonarr uses its normal quality/custom-format scoring and may
choose the same release, another release, or nothing. A later proven new attempt
is checked on a later scheduled pass. There is **no three-attempt hard failure**,
no hash/indexer timeout ban and no new attempt-counter database. Repeated metadata
timeouts may therefore lead to repeated searches until the trial expires or the
existing bounded journal reaches capacity and fails closed.

File-policy failures require manual review in Sonarr because Guard cannot
verify the complete blocklist scope. The metadata retry workflow does not
apply to those failures. Existing
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
`retry_removed` requires current confirmation that the original torrent is gone
and no new matching blocklist entry was found. If the post-removal blocklist
result is uncertain, the retry stays on hold for read-only recovery.
A newly matched blocklist record for any affected episode requires manual review. Ordinary file cleanup still requires a match for every affected episode
to confirm blocklisting. Data deletion stays unknown and remains Sonarr's
responsibility.

A positively observed replacement for any affected episode is persisted as
`any_replacement_observed` and marks the retry `retry_superseded`. A later
history read cannot erase that veto. The separate `replacement_observed` result
requires coverage of every affected episode. A newer, positively matched Sonarr
grab also vetoes another search, even if qBittorrent has yet to confirm a
replacement download under that hash. Guard persists this separately as
`replacement_grab_observed` as each episode's history is verified. An outage
reading a later page or episode leaves pack-wide coverage unknown and keeps the
earlier search veto. If neither kind of observation vetoes the search,
record `retry_search_recorded` durably before the second request. After this commit, repeat
Sonarr-side connectivity, Sonarr 4.x compatibility and endpoint checks; reject a
reappearing original hash or newly queued affected episode. After qBittorrent
confirms absence, Guard ignores each stale original row whose queue ID, episode
ID and normalized download hash match the saved pre-removal evidence. Just
before dispatch, read the blocklist again. A new matching entry for any affected
episode or uncertain blocklist evidence blocks the search. A missing indexer,
release title, torrent protocol or nonempty episode list leaves an otherwise
relevant blocklist entry uncertain. Entries explicitly marked Usenet or linked
to known unrelated episodes can be excluded.
Guard also retains any search veto seen after removal intent and before sending
the removal, including a new grab or matching blocklist entry. Those rows stay
in the outcome baseline and cannot establish a result of the removal.
Refresh replacement grab history after the search-intent commit as well: queue
visibility can lag history. A new post-removal-intent grab for ANY affected
episode from the bound client (same hash or different hash) suppresses the entire
extra search with `replacement_already_grabbed`, including a grab in the
refreshed outcome baseline. Grabs before removal intent or from a known different
client do not qualify. Unavailable, malformed or ambiguous relevant history
blocks the search rather than treating missing evidence as no replacement.
For a new relevant grab, missing/non-object `data`, missing/non-string/blank
`downloadClientName` blocks with `replacement_client_unknown`. Only a valid
nonblank different client name may be excluded. Before applying that exclusion,
Guard checks the current bound client ID and name against the removal context.
A renamed or changed downloader blocks the search. Pre-intent grabs remain
excluded before checking their client identity.
A positive integer `seriesId` for a different show rules out an event before
its type is checked. For the target series, a positive integer `episodeId`
outside the affected episodes also rules out the event. An unknown event type
that could concern the target blocks the search. A potentially relevant grab
without valid content IDs blocks with `replacement_history_identity_invalid`.
When post-removal observation finds an ambiguous grab, Guard records the hold
even if a later read omits it. Immediately before sending the separate search,
Guard rereads both Sonarr retry switches. A disabled or unreadable switch blocks
the search with `retry_settings_not_ready` and preserves the removal result.
Validate history event types before any exclusion: accept only supported v4
numeric types1–7 or their exact API names; missing, malformed, unsupported and
`Unknown` (0/`unknown`) values block with `replacement_history_event_invalid`.
Only known non-grab types can be ignored as non-grabs. This also validates event
types of baseline rows; a baseline is not a waiver for malformed schema.
The final queue read explicitly includes items Sonarr could not map to a
series. Each queue row first requires a positive integer series ID. A positively
identified different series is excluded without requiring its episode ID:
Sonarr allows unmapped queue items with null episode IDs. For the target series,
require a positive integer episode ID before excluding original or unrelated
episode rows. Missing/invalid series identity or an unknown episode within the
target series blocks with `replacement_queue_identity_invalid`.
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

Verification covers mocks for both transports, changed metadata, expiry
after commits, outage/version drift, partial results, receipt validation and
restart/no-replay behavior. Unit tests do not establish live integration.
Deploy only after user approval, stopping the worker first and preserving the
already approved trial deadline when issuing a new standalone grant.

Source references for the supported version:

- [Queue removal](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs)
- [Command submission](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Commands/CommandController.cs)
- [Command resource](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Commands/CommandResource.cs)
- [Supported history event types](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/History/EpisodeHistory.cs)
- [Blocklist matching](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Blocklisting/BlocklistService.cs)
