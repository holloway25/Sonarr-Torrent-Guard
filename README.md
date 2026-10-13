# Sonarr Torrent Guard

A standard-library Python public-download checker. The normal command reports
proposals only. A separately gated single-test sender and read-only production
verifier exist for review; the sender is disabled. No live requests have been
approved or enabled. No routine live mode, additional search, resume, extraction,
priority change or filesystem cleanup is implemented.

## Setup

Linux, Python 3.9+ and Australia/Sydney timezone data are required. The download
share is not needed for this milestone. Use `config.example.json` as the schema,
but enter live credentials only in a file outside the checkout. Set its mode to
600 and its parent directory to 700. Indexer names exactly match Sonarr history.

Each instance must have `download_client_binding` with the expected Sonarr client
ID and its exact endpoint. The pinned endpoint must match both the monitored
qBittorrent URL and Sonarr's current host, port, SSL flag and URL base. The pinned
ID selects the client before uniqueness checks, so other clients using the same
category do not interfere; duplicate records for the pinned ID remain invalid.
Default ports are normalized. Missing or changed bindings fail closed. Different proxy
aliases are not assumed to reach the same server; configure a shared verified
endpoint instead. Credentials and bindings stay in the external configuration.

```sh
python3 guard.py --config /path/outside/checkout/connections.json
```

Text reports are the default: counts, readable reasons, per-instance retry
settings and clearly marked proposed actions. Use `--format json` for versioned
JSON-line events suitable for future UI/scheduler integration. Optional
`--show-titles` displays escaped torrent titles only in text stdout, never in
JSON events or log files. Runtime reports must stay outside the repository.

Use `--check-safeguards` to perform a second, targeted read-only assessment for
each failure candidate and record it in a private `action-journal.sqlite3` beside
the external configuration. Both Sonarr queues are reread to preserve duplicate
ownership checks. Endpoint/category/source/content identities and complete file
selections must still match, retry settings must be enabled, and the new snapshot
must be at most ten seconds old. The journal records preview checks only; this
option cannot send removal, blocklist or replacement requests.

Optional `--log-file /path/outside/checkout/guard.log` enables one-MiB rotation
with three backups. Keep runtime files outside Git. No service or schedule is
installed. A future schedule should run every five minutes. A process lock beside
the configuration prevents overlaps and releases on process exit.

The active log and retained numbered backups have mode 600, including newly
created files after rollover under a permissive process umask. Log symlinks are
refused. Ownership/category/client mismatches do not consume the torrent work
allowance. Eligible hashes rotate across both instances using an atomically
saved, mode-600 `batch-state.json` beside the external config. The next run resumes
after the last assessed key, so later candidates get turns even after restarts or
queue reordering. Exceeding the work allowance reports deferred hashes explicitly.

Requests have timeouts, response-size/page limits and a shared three-minute
wall-clock request/assessment deadline enforced by Linux interval signals,
including slowly streamed bodies. API calls run in the main thread. Cross-origin
redirects and HTTPS downgrades are refused; equivalent default-port redirects
are accepted. Failed runs do not imply any live action occurred.
The only POST is qBittorrent authentication; assessment uses GET. TLS certificates
are verified. Explicit public and private source lists protect unknown sources.

## Public policy

Ownership requires the correct Sonarr queue hash, category, configured download
client bound to the actual monitored endpoint, known series/episode and matching
grab-history provenance. Names alone
are insufficient. Multiple episode rows produce one proposal per torrent.
Private sources are protected before file assessment.

| Manifest / selection | Decision |
| --- | --- |
| Any `.exe` or `.scr`, selected or not | Would fail |
| Every file unselected | Would fail |
| Only `.txt`/`.nfo` selected, regardless of size | Would fail |
| Selected media plus unselected `.lnk` or archive extras | Keep |
| Other selected files and no `.exe`/`.scr` | Keep under this narrow rule |

The same conditions apply to paused/stopped public torrents. Stopping alone is
never failure. No torrent is resumed. Existing seeding/removal policies remain
in charge of healthy torrents. Unknown/transitional states, incomplete manifests,
age under two minutes, ambiguous identity and failed API requests skip or abort
assessment. This is policy checking, not malware scanning.

JSON events/logs include instance, hash, indexer, file counts, queue IDs, torrent
state, reason, Sydney timestamp and proposed actions. They omit credentials,
endpoints, titles, filenames and download paths. Schema version 1 has readiness,
assessment and summary events. A `would_fail` report does not mean Sonarr has
failed the release.

Read-only readiness checks inspect both failed-download retry switches. Disabled,
missing or unreadable switches block the proposed replacement workflow; this
program does not change settings. Request previews are data only. The API adapter
never sends DELETE or replacement searches. See
[public workflow](docs/PUBLIC-WORKFLOW.md) for the reviewed request sequence,
verification and recovery requirements before live implementation.

## Verification and privacy

```sh
python3 -m unittest -v test_guard test_safety test_production
python3 tools/privacy_check.py --all
git config core.hooksPath .githooks
```

The optional hook checks staged content; CI checks tracked content and runs tests.
The privacy checker is a guardrail, not proof that all identifying data is absent.
Manually inspect staged content and author name/email before any commit. Use a
privacy-safe Git author identity. Never track local handoff notes, configuration,
logs, state, payloads, personal identities or deployment details.

`safety.py` also implements a simulation-only journal/recovery harness. Tests
commit dispatch intent before a fake sender runs, interrupt/restart processing,
and reconcile independently supplied observations without resending. Completion
requires separate positive evidence of removal, data deletion, failure,
blocklisting and replacement. Unknown/partial results stay unresolved or require
manual review. The disabled single-test sender reuses the durable intent and
reconciliation logic; the production verifier is described below.

Recovery keeps historical positive confirmations separately from last-known
results and the current observation's availability. Outages, absent fields and
unknown values do not erase earlier evidence. Explicit contradictions require
manual review. A union of old/partial positives cannot prove completion: all
required results must be positive in one current observation. Existing journals
are migrated additively, preserving their stored evidence.

The journal requires an owner-private directory and mode-600 database/sidecars.
SQLite transactions use FULL synchronization. Evidence is limited to instance,
hash and ownership/manifest fingerprints; no titles, paths, endpoints or secrets.
Preview and simulation records are separate and cannot enable live mode. It
retains at most 1000 rows and refuses new ones at capacity; it never silently
deletes unresolved evidence. Changed stored evidence requires review. Do not
delete the journal to force a retry. Backups and exports must also stay outside Git.

## Production preflight and disabled single-test sender

```sh
python3 production.py --config /path/outside/checkout/connections.json --preflight INSTANCE TORRENT_HASH
```

Preflight rereads the candidate and retry settings, captures old history/blocklist
IDs, checks the reviewed Sonarr version, and exercises independent read-only
outcome checks. It does not prepare a dispatch journal entry or generate approval.
The verifier matches failure history by original hash and episode identity. New
replacement grabs must have different valid hashes for the affected episodes and
the same bound client. Blocklist API records have no hash: new IDs are correlated
by original release-title digest, indexer, series and episodes. Pre-existing
records never count as new results. After dispatch, event dates must also be at
or after the durably recorded dispatch time; unsynchronized clocks can prevent
confirmation and require review.

`production.py` pins the reviewed Sonarr source version and fails closed on
version/client/endpoint drift. API failures leave affected observations unknown.
The API cannot prove download-side data deletion; `data_deleted` stays unknown,
so API-only reconciliation cannot mark an operation completely verified. No
download or library share is mounted/scanned for this purpose.

The single-test coordinator requires all of: an enabled code release gate
(currently false), an explicit non-dry-run invocation separate from normal CLI,
a single-test-enabled private journal, and a human approval bound to one instance,
hash, ownership/manifest fingerprints, nonce and expiry within five minutes. No
approval file is created by the app. There is no CLI live switch. It takes the
worker lock, captures baselines, rechecks immediately before intent/dispatch,
commits the exact queue operation context and dispatch timestamp, and sends only
the owning Sonarr queue DELETE. Redirects and automatic retries are refused.
It never directly deletes from qBittorrent or submits an extra search.

Existing single-test records, including prepared/uncertain records, only enter
read-only recovery, never a second send. Following any future approved test:

```sh
python3 production.py --config /path/outside/checkout/connections.json --observe INSTANCE TORRENT_HASH
```

This reconciles a recorded single-test operation without approval or dispatch.
Preview/simulation journal namespaces cannot authorize a single test. Production
context stores only exact IDs, public indexer identity, times and digests, not raw
release titles, endpoint addresses or credentials. Live integration and independent
file-deletion confirmation remain required before any activation decision.

## Remaining milestones

- Validate controlled dry-run candidates.
- Add explicit Sonarr v5 compatibility tests. This milestone uses Sonarr v4's v3 API.
- Review the disabled sender and production verifier, then explicitly approve a
  controlled single-torrent integration test separately. Define independent data
  deletion confirmation. No current CLI switch enables live execution.
- Longer term: define private split-RAR selection, share access, safe extraction, atomic
  publication, positive import confirmation and exact helper-file cleanup.
- Package for containers once runtime and storage design are confirmed; add a
  read-only web UI using report events after the public workflow is settled.

Design reference: [qBittorrent checker](https://github.com/sergiobaiao/qbittorrent-checker).
This is an independent implementation; no upstream script or exclusion list is
bundled. Any future source reuse requires licensing review. A project license has
not yet been selected.
