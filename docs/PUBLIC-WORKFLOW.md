# Public failure workflow: specification and preview only

No live executor exists. This document defines the next implementation milestone;
unit-tested request previews do not establish production mutation behaviour.
Private-source downloads, the private archive helper, Docker deployment and the
web UI remain separate future work. Existing seeding/removal policies stay intact.

Fresh read-only assessment and a private SQLite journal are now implemented.
Dispatch/recovery behaviour is tested using a simulation-only harness; no
production sender or result-verification adapter exists yet. Enable
`--check-safeguards` to exercise rechecks and preview journaling against the APIs.

## Proposed normal path

1. Read and validate both queues, explicit downloader binding, Sonarr grab
   provenance, content identity and public-source classification.
2. Assess a complete qBittorrent manifest under the agreed failure rules. Do not
   infer failure from paused/stopped state, size alone or warning text.
3. Inspect Sonarr retry settings. Both `autoRedownloadFailed` and
   `autoRedownloadFailedFromInteractiveSearch` must be true for the proposed native
   retry path. Require booleans from a successful response, never default unknown
   settings to enabled. Do not change these settings automatically.
4. Immediately before any future mutation, repeat all ownership/binding/source,
   identity/queue-ID, age/state and manifest checks. Cancel if eligibility changes.
5. Persist intent and evidence in a restricted external journal before sending
   any request. Serialize by instance plus torrent hash as well as the worker lock.
6. Send one request through the owning Sonarr instance, using one current queue
   ID for the torrent, even if it represents several episode rows:

   ```text
   DELETE /api/v3/queue/{currentQueueId}
   removeFromClient=true
   blocklist=true
   skipRedownload=false
   changeCategory=false
   ```

7. Let Sonarr's native failed-download handler enqueue the replacement. The guard
   must not also issue an episode/season/series search. Native handling searches
   the affected episode(s), or the season when the failed release represents a
   full season. The guard must never initiate a full-series search.
8. Verify each result independently: the exact torrent hash is absent from the
   bound qBittorrent instance; Sonarr has the corresponding failure/blocklist
   evidence; and replacement progress is observed for affected content. A new
   grab is evidence of a replacement request outcome, not successful import.
9. Reassess every new replacement normally. Re-upload names/hashes may differ.
   No custom repeated-failure limit is currently agreed.

## Partial results and recovery

The Sonarr operation is not an atomic transaction: it requests client/data removal
before marking the tracked download as failed. An HTTP timeout or success code
alone cannot establish all results. Queue disappearance alone is insufficient.

| Observed situation | Required future recovery |
| --- | --- |
| No request sent yet | Fresh checks before any later attempt |
| Request sent, response lost | Mark uncertain; reconcile APIs/history before retrying |
| Torrent removed, failure/blocklist unconfirmed | Partial action; stop and report, do not blindly repeat |
| Failure/blocklist confirmed, retry not yet observed | Wait and inspect native command/history state; do not submit a duplicate search |
| No suitable replacement available | Report unresolved; do not claim replacement success |
| Unexpected category/client/source/identity change | Cancel new mutations and require reassessment |
| Restart during any stage | Reconcile journal and observed evidence before proceeding |

The future journal must distinguish intent, uncertain response, verified removal,
verified failure/blocklist, replacement pending/observed and unresolved/manual
review. It must protect credentials, bound retention and preserve exact content
identity. Do not mark a stage successful because its API request returned 2xx.
File-deletion completion cannot be proven by torrent disappearance alone; define
appropriate client-side verification without adding broad filesystem access.

## Current preview contract

`workflow.py` only reads retry configuration and creates a `request_preview`
dictionary. It never sends the described request. Every preview remains blocked
by `live_executor_not_implemented` and `fresh_recheck_required`, plus any retry
setting problems. A protected/kept/unidentified candidate gets no request preview.
Multiple queue rows yield one preview, and no additional search is planned.

`safety.py` compares ownership and manifest fingerprints from fresh assessment,
checks public eligibility, both retry switches and a ten-second maximum snapshot
age. Manifest fingerprints include names, sizes, indices and priorities, but not
changing download progress; filenames themselves are not journaled. A fresh read
still cannot eliminate the small race with external changes before a future
mutation. Production execution must recheck directly before dispatch.

The external journal uses transactional, fully synchronized SQLite with a unique
mode/instance/hash key. Preview rows never enter dispatch states. Simulation rows
commit `dispatch_recorded` before invoking the fake sender. Recovery from that
stage, a lost response or restart reconciles observations only and never invokes
the sender again. Data removal without confirmed failure/blocklisting requires
manual review; confirmed failure without replacement or data-deletion evidence
stays pending. Complete requires all five positive observations. A missing
response, 2xx status or disappeared queue item is never sufficient by itself.

Journal records omit raw endpoints, file paths, titles and credentials. The
private directory/database requirements, bounded row count and preservation of
unresolved records are intentional. Corrupt journals fail closed instead of
being reset. Production collection of independently verified observations and
an approved live transport remain required before a controlled live test.

`reports.py` renders these results for humans and emits versioned JSON data. This
is the boundary a future read-only web UI can consume. Runtime titles are optional
text stdout only; JSON events and rotating logs omit them.

## Verification before enabling live operation

- Tests must prove fresh rechecks cancel changed candidates and that no API writes
  occur in dry-run, including searches/settings/priority changes.
- Mock each partial-operation outcome and restart point; prove reconciliation
  prevents duplicate removal or replacement requests.
- Check installed-version semantics in a controlled integration test using one
  explicitly approved public torrent, after reviewing the dry-run proposal.
- Confirm failure/blocklist, torrent/data removal and replacement outcome through
  independent evidence. Keep private, manual and healthy downloads protected.
- Obtain explicit approval for live operation only after the workflow is agreed.

## Source basis

The v4 queue operation calls client removal with data deletion and then marks the
tracked download failed. Its native retry handler checks the two configuration
switches and chooses episode or season searches. Verified against the installed
version's source tag; no production DELETE/search was used to test this.

- [Queue controller](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/Queue/QueueController.cs)
- [Failure service](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/FailedDownloadService.cs)
- [Native retry handler](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/RedownloadFailedDownloadService.cs)
