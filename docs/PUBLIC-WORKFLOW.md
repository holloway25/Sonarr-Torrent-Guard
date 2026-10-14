# Public failure workflow: dry-run and disabled single-test implementation

A gated single-test sender and read-only production verifier exist for review.
The release gate is false; unit-tested requests do not establish production
mutation behaviour, and no live test is currently authorized.
Private-source downloads, the private archive helper, Docker deployment and the
web UI remain separate future work. Existing seeding/removal policies stay intact.

Fresh read-only assessment and a private SQLite journal are now implemented.
Dispatch/recovery behaviour is tested using simulations and mocked production
adapters. Enable
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
by `live_sender_disabled` and `fresh_recheck_required`, plus any retry
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
being reset. The separately gated sender and read-only verifier extend these
requirements without enabling the normal CLI to mutate anything.

Journal recovery stores three distinct views: historical positive `confirmed`
flags, merged last-known `observation` values, and `current_observation` with an
availability flag. An outage leaves historical and last-known evidence intact
while marking the current view unavailable. Omitted/unknown fields in later
partial responses preserve previous values. Explicit negative results update the
last-known view; a negative contradicting a historical confirmation requires
manual review without deleting that confirmation. Completion requires all five
positive results in the current snapshot, never just a historical union.
Schema migration preserves existing observations and initializes historical
confirmations from them; it cannot reconstruct evidence already lost before
the migration.

## Production verification and sender gates

`production.py --preflight INSTANCE HASH` rereads an exact candidate, confirms
retry settings and reviewed-version/client binding, and captures baseline IDs.
Its read-only verifier independently checks qBittorrent torrent absence, new
Sonarr failure history, new blocklist records and newer replacement grabs for
the affected episodes. It does not infer results from queue disappearance.
The blocklist API has no download hash; correlation uses a release-title digest,
indexer, series/episodes and newly added record IDs. Failure history additionally
must match the original hash; replacement hashes must differ. Client-name
digests bind matching history records to the configured downloader.

Dispatch time is stored with intent, and matching result events must be at or
after that timestamp as well as absent from the pre-dispatch baselines. Sonarr's
truncated timestamps are interpreted as intervals at their published precision.
An interval overlapping dispatch (including the same whole second) is unknown,
not false or confirmed: the API cannot establish ordering inside that interval.
No blanket one-second tolerance accepts potentially pre-dispatch evidence.
Unknown failure/blocklist evidence after removal remains uncertain; explicit
negative or contradictory evidence still requires review. Missing
timestamps, API outages, malformed identities or clock disagreement prevent
positive confirmation. These checks establish observed results, not proof that
every concurrent manual action was caused by the guard.

Production observations always leave `data_deleted` unknown because no supported
API proves download-side deletion. Consequently the production verifier cannot
claim complete verification without a separately designed independent proof.
No filesystem/share access was added, and no library path can be deleted.

The sender requires a currently disabled code release gate, a separate explicit
non-dry-run invocation, an armed single-test journal and a short-lived approval
for one hash/instance and exact evidence fingerprints. It takes the worker lock,
captures baselines and performs a final fresh check before recording dispatch.
There is no general live CLI mode or approval generator. Request redirects and
retries are refused. Existing prepared/uncertain single-test records only recover
through observations, never automatic dispatch. `--observe INSTANCE HASH` exposes
that read-only recovery route using the stored operation context.

### Repeated hashes and download attempts

Assessment binds the newest grab ID for each affected episode to the current
qBittorrent addition time (within 120 seconds; missing dates, clock skew or a
larger gap fail closed). The newest episode grabs must agree on one classified
source. This prevents older sources for a repeated hash making the current
source ambiguous, without treating an old grab as authority for a manual re-add.
The bounded time correlation is not proof against concurrent manual operations.

An attempt fingerprint binds the instance/hash, addition time and current grab
IDs. Ownership/fresh rechecks include it: a re-grab during validation cancels the
old proposal. Preview and simulation journals use separate records for successive
attempts and preserve the previous action's evidence across restarts. Existing
legacy rows are retained unchanged. Filename changes alone are not new attempts.

The disabled single-test sender deliberately retains its one-action-per-hash
key. A re-grab cannot reuse a consumed approval, bypass a manual-review record or
trigger another live deletion. Routine live attempt scheduling is not implemented
or enabled; it needs a separate reviewed authorization/recovery policy. The next
manual dry-run can assess a new bad attempt, but cannot remove it. A same-hash
re-grab is not reported as a useful verified replacement.

The dispatch-intent commit is followed by a fresh version request. Only after that
request completes are the final candidate snapshot's age and approval expiration
checked again. A slow commit or slow status response cannot carry an expired
approval/stale snapshot into the sender. Version drift, status outages or failed
post-commit expiry checks leave a durable `dispatch_blocked` record, preserving
identity, context, historical evidence and an allowlisted stop reason. This stage
means the request was not sent and is terminal for automatic processing. A crash
before a blocked result is recorded instead leaves dispatch intent requiring
read-only reconciliation; it never permits blind re-sending.

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
