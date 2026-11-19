# Public cleanup workflow

Guard assesses public torrents owned by the configured Sonarr instances.
`guard.py` and `public.py` are dry-run entry points. The scheduled live worker
requires a confirmed Docker scope or a [standalone grant](UNATTENDED-TRIAL.md).
Private archive handling and a web UI are future work.

## Start a scheduled pass

1. Test the configured Sonarr connections to qBittorrent. If either owner in a
   two-instance configuration is unavailable or its downloader test fails,
   Guard waits for the next cycle. No cleanup is sent directly to qBittorrent.
2. Read the Sonarr queues, including unmapped items, and match each eligible
   queue entry to the current qBittorrent torrent. Verify the queue hash and
   aliases, category, exact pinned downloader binding and series/episode IDs.
3. Identify the current grab's indexer from Sonarr's history. Apply the
   [source policy](SOURCE-POLICY.md) for that Sonarr owner. Skip private,
   unidentified or ambiguous sources, unowned downloads and incompatible
   endpoint/client/category combinations.
4. Check qBittorrent's current file list and selection against the
   [file policy](../README.md#file-policy). Keep healthy torrents, including
   those with only harmless unselected extras. Pause or stop status alone
   does not fail a torrent. Apply the separate [metadata-timeout policy](METADATA-RETRY.md)
   to eligible downloads that are still retrieving metadata.

Connectivity uses Sonarr's non-saving downloader test with temporary blank
categories. Sonarr resolves its own saved credentials from the provider ID.
The expected blank-category warning alone is accepted with an otherwise
successful test. Other diagnostics, redirects and outages stop the pass.
Sonarr may update its own connection-health status during the test.

Docker and the provided timers wait ten minutes after a cycle finishes.
The cycle uses a shared three-minute deadline, bounded requests and pagination,
and a worker lock. Assessment, verification and live dispatch each have
time reserved. Private cursors rotate through large queues, including after a
timeout or restart.

## Ownership and source checks

- Require exact client IDs and uniquely bound endpoints. Equivalent default-port
  URLs compare equal. An endpoint change invalidates earlier evidence.
- Validate torrent hashes, including hybrid torrent aliases. An alias used by a
  second queue group or claimed by multiple torrents makes ownership ambiguous.
  If identity cannot be verified, Guard holds the action. qBittorrent properties
  are a fallback when the bulk list lacks infohash fields. Batch state can
  reuse verified identity while the downloader, primary hash, addition time
  and size match, and the one-hour cache is still fresh.
- Read each affected episode's bounded grab history using normalized hashes.
  The selected grabs must agree on the bound downloader and indexer and match
  the current torrent addition time within two minutes. Tied or conflicting
  evidence holds cleanup. A private indexer on a matching queue row vetoes
  cleanup even if grab history says public. A queue's public label alone
  cannot authorize an action.
- Require a complete, structurally valid file list. Malformed IDs, incomplete
  responses, changed ownership or changed file selections cannot establish a
  valid candidate. Several episode rows for one torrent can produce one action.

## Live file-policy cleanup

1. Under the worker lock, repeat assessment for the candidate using both
   Sonarr queues. Check the owning Sonarr's current connection and version.
   Review the visible grab history for the exact queue download ID and hold
   conflicting titles, sources, clients, episodes or malformed evidence.
2. As the last remote check before sending, reread the target torrent and
   its complete manifest from qBittorrent. Require the same addition time,
   hash identity, category and failing manifest. Revalidate the approved
   scope and the fresh assessment immediately before dispatch.
3. Send one request to the owning Sonarr. Select one current queue ID for the
   torrent, even if it has several episode rows.

   ```text
   DELETE /api/v3/queue/{currentQueueId}
   removeFromClient=true
   blocklist=true
   skipRedownload=false
   changeCategory=false
   ```

4. Sonarr asks the downloader to remove the torrent and data, marks the release
   failed and blocklists it. Sonarr applies its own failed-download retry
   settings when deciding whether to search again. Guard assesses whatever is
   queued at the next scheduled pass, including a re-grab or a different public
   release. Each pass uses current evidence. Sonarr owns file-policy retries.

The cycle continues as Sonarr grabs replacements. A healthy grab stays in the
queue. The episode may remain missing when Sonarr has no eligible release.

The live request refuses redirects and has no automatic HTTP retry. If a pass
is interrupted or the response is lost, the next pass checks the current queue
and files. A torrent that is still present can qualify again after fresh
verification. If Sonarr already removed it, that pass simply has no matching
torrent to act on. Sonarr's failure and blocklist history is the place to check
whether its native action completed.

### Torrents with different queue and history hashes

A hybrid torrent can have two verified hashes. Sonarr uses the exact queue
hash to look up grab history during its combined Remove and Blocklist action.
If that lookup is empty and all approved grabs use a single verified alternate
hash, Guard checks the visible history and release metadata for that hash.

Guard asks Sonarr to remove the original queue item first. After qBittorrent
confirms the torrent is absent, Guard rechecks the authorized grab and asks the
owning Sonarr to mark that grab failed. Sonarr writes its blocklist entry and
applies its own retry settings. Removing the queue item first lets Sonarr
evaluate replacements without that download in the queue. The two requests can
complete independently. If the second cannot be verified, the live log shows
`sonarr_remove_accepted_blocklist_unverified`. An interrupted pass cannot
resume a previous request. [Queue removal](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs#L67-L86) · [Mark as Failed by history ID](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/History/HistoryController.cs#L119-L124)

### File-policy blocklist scope

For a matching queue and history hash, this is the same action as Sonarr's queue UI. Guard holds visible history
conflicts and verifies that the torrent under assessment is from an eligible
public source. Sonarr chooses the internal grab used for blocklisting. In
Sonarr 4.0.20.3014, the public history API can omit deleted episodes that
the internal lookup still sees. A new grab can also arrive after the final
read across the two services. [History repository](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/History/HistoryRepository.cs) · [Sonarr's failure selection](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/FailedDownloadService.cs#L53-L60)

### Read the outcome

| Result | Meaning |
| --- | --- |
| `would_fail` | The assessment found a file-policy failure or eligible metadata timeout. In dry-run this is a proposal. |
| `sonarr_remove_blocklist_accepted` | Sonarr accepted Guard's native request. Data deletion, replacement and import need separate confirmation in the relevant application. |
| `held` | A safety or authorization check stopped dispatch. The reason is in the routine action report. |
| `uncertain` | A file-cleanup request may have reached Sonarr. The next pass starts with current queue and torrent evidence. |
| `waiting` | The cycle could not proceed, for example due to maintenance or unavailable authorization. |

## Current preview contract

A dry-run file-policy candidate previews the native remove-and-blocklist request.
A metadata candidate previews removal without blocklisting and a conditional
affected-episode search. Protected, kept or unidentified downloads have no
request preview. A preview sends no cleanup or search request.

With `guard.py --check-safeguards`, eligible dry-run assessments receive a fresh
recheck and include its result in the report and optional log. The recheck
compares ownership and manifest fingerprints and requires a snapshot no more
than ten seconds old. Manifest fingerprints use names, sizes, indices and
priorities. The scheduled dry-run also checks the visible Sonarr grab titles
before logging a file candidate as `would_remove`. A metadata timeout that
passes the dry-run checks is logged as `metadata_candidate`. The live worker
still has to verify the release title and other removal prerequisites.

## Production verification and sender gates

The live worker and production preflight require Sonarr 4.x and validate the
server response and client binding. Sonarr 5.x, missing or malformed versions,
and inconsistent responses hold the operation. `production.py --preflight
INSTANCE TORRENT_HASH` checks the visible grab scope for file cleanup and uses the
read-only outcome verifier for metadata. It neither prepares an operation nor
sends a removal or search.

### Metadata and logs

[Metadata retry](METADATA-RETRY.md) uses fresh checks and keeps evidence in
memory for the current pass. It removes the stalled torrent without blocklisting
and may request an affected-episode search if removal is confirmed and no
replacement is already queued or grabbed. A later pass never resumes an earlier
search request. Dry-run logs proposals, and live mode logs action outcomes.
Both use private rotating files. Check `routine.log` for the request outcome,
then check Sonarr’s history for any blocklist entry or replacement grab.

## Verification before enabling live operation

- In dry-run, verify connectivity, both owners' public/private source rules,
  proposed file and metadata actions and safe handling of healthy or unowned
  torrents.
- Use mocked services to test the exact Sonarr request, changed manifests and
  scopes, a fresh pass after a failed request or re-grab, and log output.
  Test that an interrupted metadata pass cannot replay a search.
- A controlled live check can confirm Sonarr's failure history, blocklist and
  replacement, and the torrent/data removal in the downloader. Approval for a
  live check is separate from a passing source or container test.

## Source basis

- [Queue removal controller](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs)
- [Failed-download service](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/FailedDownloadService.cs)
- [Native retry handler](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/RedownloadFailedDownloadService.cs)
- [Provider test endpoint](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/ProviderControllerBase.cs)
- [qBittorrent connection/category tests](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/Clients/QBittorrent/QBittorrent.cs)
