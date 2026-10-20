# Safety-aware journal retention: review candidate

This implementation is for review. `retention.ARCHIVE_RELEASE_ENABLED` is false;
no service/timer or automatic worker call is added. Deployment and application
need explicit approval after review. Do not update an authorized running checkout
casually: changes to safety.py affect the grant's code digest. Housekeeping never
extends permission, changes queue/client settings or sends network requests.

Deploy the archive-aware worker FIRST, and verify its source-bound permission,
before enabling or applying archival. Never move production rows while an older
worker that cannot read archives could later resume. Acquiring its lock alone
does not upgrade that worker. Stop incompatible worker versions and preserve a
private consistent backup during the separately approved deployment.

## Conservative policy

- Keep up to1,000 active action rows; capacity still fails closed.
- Archive only confirmed resolved production records whose last update is at
  least30 days old. Batch size is1–100; default100.
- Eligible stages are `cleanup_resolved` in the public-attempt namespace, and
  `complete` in production namespaces. Validate stored context/identity, a finite
  positive dispatch time no later than the last update, current observation
  availability, and all required current AND historical positive confirmations.
  Cleanup resolution means original absence/failure/blocklist, not file deletion
  or import. Complete requires every observation positive.
- Never archive preview/simulation, prepared, cancelled, blocked, uncertain,
  manual-review, replacement-pending or metadata retry records. A search receipt
  is not full completion. Unavailable/partial/contradictory evidence remains hot.
- Keep at most10,000 archive rows. If the proposed batch would exceed that bound,
  do not move any records; fail closed with `journal_archive_capacity_reached`.
  No oldest-record eviction, purge, expiry or silent unlimited growth.

These are proposed conservative defaults, not a newly approved infinite runtime.
If unresolved or excluded records fill the active journal, it still stops new
actions. An operator must investigate rather than deleting evidence to resume.

## Archive design

The archive is a separate **table in the same private SQLite database**, not an
external file, ZIP or lossy report. A single FULL-synchronous transaction copies
the complete raw row (including original keys, timestamps, evidence, context,
observations, confirmations, stop reason, receipt and any future columns) into
`actions_archive`, then removes its active copy. Failure rolls back the entire
batch. Never overwrite a conflicting archive key. No records are removed from
the archive. Existing database/backups/sidecars must remain private and outside Git.

The additive migration creates the table and owner/hash index only when opening
a read-write journal; it does not move records. An explicit archive application
requires separate housekeeping permission. `Journal.get` checks both stores;
`prepare` finds old keys before insertion, so an archived operation cannot be
recreated. `Journal.related` combines bounded active records and indexed matching
archive records: older attempts continue to enforce cross-mode holds and new-grab
identity rules. This is not a permanent hash ban; a genuinely newer corroborated
attempt can still pass the unchanged rules.

The archive lookup never scans unrelated cold rows. More than1,000 matching
active/archive production records fails closed with `journal_history_limit_reached`
rather than truncating history and losing safety constraints. An inconsistent
duplicate key in both tables or malformed archive evidence also blocks. Recovery
continues to process active pending records only; no archived terminal row can
trigger a deferred search or deletion.

The bound is on record counts, not a disk-space quota. Archiving inside the
database does not necessarily shrink its file. Disk monitoring, disk exhaustion
alerts, backup exports and eventual archive-capacity management remain separate
work. Do not delete or replace a full/corrupt database to force sending.

## Preview and controlled application

The preview command is genuinely read-only. It requires the existing private
database and parent permissions, opens SQLite with `mode=ro`, and makes no schema,
permission or row changes. It supports the current legacy journal without an
archive table. Unsupported or corrupt schema fails closed rather than being
replaced. Output is title/endpoint/credential-free local operational JSON with
counts and eligible record keys; keep any saved output outside the repository.

```sh
python3 retention.py --journal /PRIVATE_CONFIG/action-journal.sqlite3
```

For review/testing, application is a separate explicit operation:

```sh
python3 retention.py --journal /PRIVATE_CONFIG/action-journal.sqlite3 --apply --batch-limit 100
```

`--apply` is currently refused before opening the journal because the release
gate is disabled. After separately approved activation, it acquires the same
nonblocking worker lock before opening a writable journal. If a worker is active,
return `another_run_is_active`; do not race its dispatch/recovery. It has no sender
permission and never calls Sonarr or qBittorrent. The short SQLite transaction
also prevents concurrent changes between copying and removing an active row.

Preview is the default at both the command and archive-method boundary. A
successful preview is not permission to apply. There is no scheduled invocation
and no automatic archival on database open, capacity pressure or grant renewal.

## Verification

Tests cover complete row preservation/restart lookup, same-key non-recreation,
real coordinator no-resend, cross-mode protection, legitimate newer attempts,
unresolved and metadata receipt preservation,30-day evidence/age requirements,
rollback between copy/delete, bounded batches/capacity, archive-key conflicts,
bounded history lookup, read-only legacy preview, disabled application and worker
lock exclusion. All tests use isolated fixture databases, not production mutation.

Batch rollback coverage also fails the SECOND deletion in a two-row batch and
checks both complete active rows and an empty archive after reopening. This must
reject per-row commits, not just commits between copy and delete. Legacy-preview
coverage invokes the actual CLI entry point and a real CLI subprocess against a
database without an archive table, comparing database bytes AND SQLite schema
before/after; testing the read-only helper alone is not sufficient.
