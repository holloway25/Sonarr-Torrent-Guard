# Sonarr Torrent Guard

A standard-library Python public-download checker. This milestone reports
proposals only. No torrent deletion, blocklist, search, resume, extraction,
priority change or file cleanup is implemented.

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
Default
ports are normalized. Missing or changed bindings fail closed. Different proxy
aliases are not assumed to reach the same server; configure a shared verified
endpoint instead. Credentials and bindings stay in the external configuration.

```sh
python3 guard.py --config /path/outside/checkout/connections.json
```

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

Reports include instance, hash, reason, Sydney timestamp and proposed actions.
They omit credentials, endpoints, filenames and download paths. A `would_fail`
report does not mean Sonarr has failed the release.

## Verification and privacy

```sh
python3 -m unittest -v test_guard
python3 tools/privacy_check.py --all
git config core.hooksPath .githooks
```

The optional hook checks staged content; CI checks tracked content and runs tests.
The privacy checker is a guardrail, not proof that all identifying data is absent.
Manually inspect staged content and author name/email before any commit. Use a
privacy-safe Git author identity. Never track local handoff notes, configuration,
logs, state, payloads, personal identities or deployment details.

## Remaining milestones

- Validate controlled dry-run candidates.
- Add explicit Sonarr v5 compatibility tests. This milestone uses Sonarr v4's v3 API.
- Agree and verify live failure/removal and native replacement behaviour before
  implementing it. Every future mutation requires fresh ownership/file checks.
- Define private split-RAR selection, share access, safe extraction, atomic
  publication, positive import confirmation and exact helper-file cleanup.
- Package for containers once runtime and storage design are confirmed.

Design reference: [qBittorrent checker](https://github.com/sergiobaiao/qbittorrent-checker).
This is an independent implementation; no upstream script or exclusion list is
bundled. Any future source reuse requires licensing review. A project license has
not yet been selected.
