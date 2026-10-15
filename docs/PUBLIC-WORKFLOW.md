# Public failure workflow: dry-run and disabled senders

A gated single-test sender and read-only production verifier exist for review.
Manual sender release gates are false; the separate unattended entry point needs
an explicit expiring routine grant. Unit-tested requests do not establish production
mutation behaviour, and no live test is currently authorized.
Private-source downloads, the private archive helper, Docker deployment and the
web UI remain separate future work. Existing seeding/removal policies stay intact.

Fresh read-only assessment and a private SQLite journal are now implemented.
Dispatch/recovery behaviour is tested using simulations and mocked production
adapters. Enable
`--check-safeguards` to exercise rechecks and preview journaling against the APIs.

## Proposed normal path

The following failure/blocklist/native-retry path applies to **file-policy
failures**. Metadata timeouts instead use the separately disabled review policy
in [metadata retry review](METADATA-RETRY.md): remove without blocklisting, then
one affected-episode search only after confirmed removal. It is not deployed by
changing these documents, and never escalates to blocklisting after three attempts.

1. Require successful Sonarr-side connectivity diagnostics for both owners; wait
   until the next ten-minute cycle during maintenance, without downloader-only
   cleanup. Read and validate both queues, explicit downloader binding, Sonarr grab
   provenance, content identity and public-source classification.
2. Assess a complete qBittorrent manifest under the agreed failure rules. Do not
   infer failure from paused/stopped state, size alone or warning text.
   Separately, the agreed public metadata-timeout rule can fail active
   `metaDL`/`forcedMetaDL` attempts after 30 elapsed minutes since addition, requiring
   zero progress, unknown size and a successfully read empty manifest. It is a
   metadata failure, not a malware verdict; private/unknown sources remain
   protected. Contradictory/missing information skips. Metadata arriving before
   dispatch changes the fingerprint and cancels the timeout action.
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

7. For file-policy failures, let Sonarr's native failed-download handler enqueue the replacement. The guard
   must not also issue an episode/season/series search. Native handling searches
   the affected episode(s), or the season when the failed release represents a
   full season. The guard must never initiate a full-series search.
8. Verify each result independently: the original download incarnation is absent from the
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
| Sonarr or its qBittorrent connection unavailable | Wait ten minutes; recheck via Sonarr; no downloader-only fallback |
| Request sent, response lost | Mark uncertain; reconcile APIs/history only, never blindly resend |
| Torrent removed, failure/blocklist unconfirmed | Partial action; stop and report, do not blindly repeat |
| Failure/blocklist confirmed, retry not yet observed | Wait and inspect native command/history state; do not submit a duplicate search |
| No suitable replacement available | Report replacement pending; this alone does not leave a confirmed cleanup unresolved |
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

Ownership binds both normalized endpoints: the owning Sonarr instance and the
monitored qBittorrent server. Changing Sonarr's host, scheme, effective port or
base path invalidates the reviewed fingerprint and approval even if the new
server returns identical IDs and content. Equivalent default-port spelling does
not change identity. Earlier snapshots lacking this binding must be freshly
assessed; existing journal evidence is not silently rewritten to match.

The external journal uses transactional, fully synchronized SQLite with a unique
mode/instance/hash key for legacy and single-test records. New preview/simulation
keys also include the attempt fingerprint. Preview rows never enter dispatch
states. Simulation rows commit `dispatch_recorded` before invoking the fake sender. Recovery from that
stage, a lost response or restart reconciles observations only and never invokes
the sender again. After observed removal, explicitly negative failure/blocklist
evidence requires manual review; unknown results remain uncertain. Contradictions
of historical positive evidence also require manual review. Confirmed failure
and blocklisting without replacement or data-deletion evidence stays pending.
Complete requires all five positive observations. A missing
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
manual review without deleting that confirmation (for public-attempt cleanup,
only contradictions in cleanup fields affect its stage). Completion requires all five
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
must match the original hash. Replacement hashes differ unless a newer same-hash
incarnation is corroborated by a later qBittorrent addition and new matching Sonarr
grab IDs for all affected episodes, positively after dispatch. Changed addition
time alone leaves original absence unknown. Legacy contexts lacking incarnation
evidence retain hash-absence checks. Client-name
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

For new sends, the coordinator now waits across the next whole UTC second after
the durably stored fractional intent time. This prevents ordinary whole-second
Sonarr results from overlapping that intent when clocks agree. It does not round
intent down or introduce an acceptance tolerance. The wait has a 1.1-second
monotonic bound; a stalled/backward wall clock fails closed. Freshness/approval
are checked after waiting, then the full candidate is reread and version-bound
context recaptured. A transaction unions refreshed pre-send baseline IDs with
the original IDs, preserving identity, original window, intent and observations.
Only an armed coordinator at dispatch-recorded stage may extend these baselines;
recovery never calls that operation. Final connection/version/endpoint, age,
expiry and clock-boundary checks follow this commit immediately before sending.
Events already present during the wait are therefore excluded from outcomes.

The UTC clocks must remain synchronized; changing display timezone does not
solve clock skew. Ambiguous historical results remain unknown under the same
verifier rules. Existing held tests are not reset or automatically relabelled;
their resolution requires separate explicit review, not another removal request.

Production observations always leave `data_deleted` unknown because no supported
API proves download-side deletion. Consequently the production verifier cannot
claim complete verification without a separately designed independent proof.
No filesystem/share access was added, and no library path can be deleted.

The manual sender requires a currently disabled code release gate, a separate explicit
non-dry-run invocation, an armed single-test journal and a short-lived approval
for one hash/instance and exact evidence fingerprints. It takes the worker lock,
captures baselines and performs a final fresh check before recording dispatch.
`production.py` has no live CLI mode or approval generator. The separately granted
`routine.py` worker is described in [unattended trial](UNATTENDED-TRIAL.md).
Request redirects and
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
trigger another live deletion. The separate disabled per-attempt sender and
dry-run timer templates do not enable routine live scheduling or grant approval. The next
manual dry-run can assess a new bad attempt, but cannot remove it. A same-hash
re-grab is not reported as a useful verified replacement.

### Per-attempt sender and maintenance boundary

The `public_attempt` namespace keys operations by mode, instance, hash, attempt
fingerprint and approval digest. Its separate false release gate, armed journal,
non-dry-run invocation and exact expiring approval are all mandatory. Both the
addition time and all current grab IDs must advance beyond earlier resolved
operations; addition must also be after the earlier dispatch intent. Unresolved
legacy or per-attempt production records hold the same attempt, not unrelated
candidates. Definitely unsent cancelled/blocked records can be followed by a new
exact approval after maintenance, preserving both records. Recovery never sends.
Both sender modes perform this related-record check before preparing a new
action; a single-test approval cannot bypass a hold on the same attempt or repeat a
resolved incarnation. Recovery of an already-recorded operation is read-only.

A confirmed successor may be handled despite an older unresolved record only
with a different attempt fingerprint, strictly later downloader addition and
latest affected-episode grab timestamps, and unchanged endpoint/client binding.
Known earlier grab IDs must advance too. Legacy records without grab IDs need
the same strictly later timestamp proof. Hash/name/file matches alone do not
release holds; historical records are never erased or relabelled. Grab timestamps
are now included in fresh ownership evidence. See the trial document for details.

For this namespace only, `cleanup_resolved` requires all three cleanup positives
in one current observation: original absence, failure and blocklisting. A union
of historical partial observations cannot resolve it. Replacement availability
and file deletion are separate outcomes. Only contradictions in the three cleanup
fields hold cleanup for review; later replacement progress cannot undo cleanup
resolution. Historical replacement evidence remains preserved. `data_deleted` remains unknown; this
stage is not `complete` and must not be presented as full end-to-end verification.
Existing single-test/manual-review rows and their evidence are not reset.

The always-dry-run `public.py` CLI performs connectivity checks and candidate
assessment/fresh proposals BEFORE pending recovery, in a bounded, locked cycle
with the existing fair cursor. Recovery is limited to five records per cycle,
five seconds per observation and thirty seconds overall, capped by the remaining
run deadline with two seconds left for persistence. Each adapter temporarily
inherits the observation deadline too, preventing caught timeouts from starting
another long request; previous deadlines are restored afterward. Its separately
validated, durable `recovery_after` cursor rotates across pending keys and
survives restarts, even with no assessment candidates. Deferred/unobserved records
remain held; recovery never discards their evidence. Holds cleared after
assessment are reassessed next cycle. A slow recovery backlog cannot consume the
assessment opportunity or keep restarting at its first record.
`maintenance.py` uses Sonarr's reviewed non-saving provider test with blank
temporary categories, avoiding its category-creation branch. Original provider
ID/connection fields resolve Sonarr's own masked credentials. No settings are
saved, but Sonarr's native provider health status may change as part of testing.
The known blank-category warning alone is accepted, identified by Sonarr's own
`isWarning` field (its generic severity can still say `error` for this warning).
Other warnings/errors, redirects, outages or malformed responses make the cycle
wait. Connectivity is
rechecked by disabled senders before preparation, before intent, and after commit.
All actual public removals/blocklists/native retries still go through Sonarr.

Timer templates under `deploy/` run only the dry-run CLI at ten-minute intervals
after completion; they are not installed/enabled. No long sleeps or catch-up
bursts are used. The two-minute torrent age minimum remains. No automatic record
purge is implemented: the private journal refuses new records at its bound rather
than discarding unresolved evidence. Long-term retention needs separate review.

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

- Tests must prove fresh rechecks cancel changed candidates and no download,
  search, settings or priority mutations occur in dry-run. Sonarr's non-saving
  connection diagnostic POST is the only new diagnostic exception.
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
- [Provider test endpoint](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/Sonarr.Api.V3/ProviderControllerBase.cs)
- [qBittorrent connection/category tests](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/Clients/QBittorrent/QBittorrent.cs)
- [Provider test status updates](https://github.com/Sonarr/Sonarr/blob/v4.0.20.3014/src/NzbDrone.Core/Download/DownloadClientFactory.cs)
