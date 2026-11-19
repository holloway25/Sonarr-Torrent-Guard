# Sonarr Torrent Guard

Sonarr Torrent Guard checks torrents that Sonarr has sent to qBittorrent. In live
mode, a verified bad public torrent triggers the owning Sonarr's **Remove and
Blocklist** action. Sonarr handles the removal, blocklist and replacement search.
Guard checks the next grab on a later scheduled pass.

## How a scheduled pass works

1. **Check connections.** Guard asks the configured Sonarr instances to test
   their qBittorrent connection. If a required connection is unavailable, the
   scheduled worker waits for the next pass. Docker and the provided service
   timers wait ten minutes after a cycle finishes.
2. **Identify the torrent and its owner.** The torrent must match a Sonarr queue
   item, the expected category and pinned download client, and the current
   grab history. Guard uses each owner's [indexer policy](docs/SOURCE-POLICY.md).
   It skips configured private indexers, manual or unowned downloads, and
   missing or conflicting ownership or source evidence.
3. **Check the files.** Guard reads the complete file list and selection from
   qBittorrent. It rechecks the owner, source and current files before a live
   removal. A healthy torrent stays in the queue.
4. **Let Sonarr act.** For a verified file failure, Guard sends one native
   Remove and Blocklist request to the owning Sonarr. Sonarr requests removal
   of the torrent and download data, records the blocklist entry and applies
   its own retry settings. A timeout or restart is handled by checking the
   current queue on the next pass. Each replacement or re-grab is assessed
   from its current evidence, including a grab from another public indexer.

File cleanup needs no SQLite action journal, repeat counter or separate search.
The worker does save private batch cursors so large queues get a fair turn.
See the [public workflow](docs/PUBLIC-WORKFLOW.md#live-file-policy-cleanup) for the
exact request, Sonarr's history limits and how to read the result.

## File policy

| File list or selection | Result |
| --- | --- |
| Any `.exe` or `.scr`, selected or unselected | Fail |
| A selected `.lnk`, `.arj`, `.zipx`, `.001`, `.rar`, `.gz`, `.lz`, `.lzh`, `.uue` or `.iso` | Fail |
| Every file is unselected | Fail |
| Only `.txt` or `.nfo` files are selected, regardless of size | Fail |
| Selected media with unselected shortcut or archive extras | Keep if no failure rule matches |
| Other manifests with selected files | Keep if no failure rule matches |

Paused or stopped public torrents can still fail a file rule. The state alone
never causes a failure. Guard leaves incomplete manifests and unknown states
alone, and the default minimum torrent age is two minutes. Guard uses file names
and selection for this policy and reads no payload contents.

### Metadata timeouts

A separate rule applies to a verified public download still in `metaDL` or
`forcedMetaDL` after 30 minutes since addition. It requires zero progress,
unknown size and a successfully read empty file list. This branch asks Sonarr
to remove the download without blocklisting. After confirming removal and
checking for an existing replacement, Guard can request one affected-episode
search. This workflow and its read-only recovery use the private SQLite journal.
If the journal is unavailable, approved live file cleanup can still run.
See [metadata retry](docs/METADATA-RETRY.md).

## Install and run

### Docker or Unraid

Follow [container setup](docs/CONTAINER.md) for a dedicated appdata directory,
private connection settings and first-start checks. The image runs as a non-root
user. It needs access to the Sonarr and qBittorrent APIs and its own appdata
directory. A media library or download mount is unnecessary.

Start with the default `STGUARD_MODE=dry-run`. Review the proposed actions
and private-indexer settings for each Sonarr owner. Set `STGUARD_MODE=live`
when the reviewed configuration is ready. Existing installs may require a
one-time scope confirmation. Changes to that scope require confirmation again.

Use the [reviewed release process](docs/DEPENDENCY-MAINTENANCE.md) to approve a
candidate before it becomes `latest`. A source commit, a published candidate and
an installed container can each be on different versions.

### Standalone

Use Linux and Python 3.9 or newer. Guard uses Python's standard library. Copy
[the configuration example](config.example.json) to a location outside the
checkout, set its permissions to `0600` and its parent directory to `0700`,
and fill in the connection details privately. Set the local timezone for reports.

Set the expected Sonarr download-client ID and qBittorrent endpoint for each
owner. The endpoint must match the monitored qBittorrent URL and the client's
Sonarr settings, including scheme, port and base path. Sonarr owners must use
distinct normalized endpoints and categories. Default ports are normalized.

```sh
python3 guard.py --config /path/outside/checkout/connections.json
python3 public.py --config /path/outside/checkout/connections.json
```

Both commands are dry-run. `guard.py` reports file-policy and metadata
assessments. `public.py` also checks Sonarr-side connectivity and observes pending
journal entries. Its Sonarr diagnostic does not save configuration or change
the torrent queue, but Sonarr may update its own connection-health status.

Use `--format json` with `guard.py` for JSON-line reporting.
`--show-titles` displays escaped titles only in the text output.
`--log-file PATH` writes rotating JSON logs to a private location.
`--check-safeguards` adds a targeted dry-run recheck and stores eligible preview
evidence in a separate `preview-journal.sqlite3` beside the configuration.

The optional dry-run and live service templates are in `deploy/`. Standalone
live operation requires `routine.py --live` and a private scope-bound grant.
See [standalone authorization](docs/UNATTENDED-TRIAL.md).

## Read the results

- `would_fail` is an assessment. Review the proposed Sonarr action in dry-run.
- `sonarr_remove_blocklist_accepted` means Sonarr accepted the live file-cleanup
  request. It does not establish that the torrent data was deleted or that a
  replacement was downloaded or imported.
- `held` means validation stopped the action. Inspect the reported reason.
  `uncertain` means the request may have reached Sonarr. Check Sonarr and the
  current queue to see what happened.
- A missing or unusable action journal produces a separate metadata hold. The
  live worker can still check current files and process eligible file failures.

[Production preflight](docs/PUBLIC-WORKFLOW.md#production-verification-and-sender-gates)
can check one candidate without sending a removal or search:

```sh
python3 production.py --config /path/outside/checkout/connections.json --preflight INSTANCE TORRENT_HASH
```

Keep connection settings, grants, logs, journals and backups outside Git.
Runtime logs omit credentials, raw endpoints, release titles, filenames and
download paths. See [journal retention](docs/JOURNAL-RETENTION.md) for the
read-only retention preview and limits.

## Verify changes

```sh
python3 -m unittest discover -s tools/tests -t . -v
python3 tools/privacy_check.py --all
git config core.hooksPath .githooks
```

CI runs the source tests, privacy checks and offline container tests. The live
file-cleanup tests use fake services to check the exact Sonarr request, a later
public re-grab, protection of private and ambiguous torrents, and operation
without an action journal. An offline pass verifies request construction and
safety checks. A live integration check verifies behavior on an installed setup.

## License and design reference

Licensed under the [GNU General Public License version 3 only](LICENSE)
(`GPL-3.0-only`). Copyright (C) 2026 Sonarr Torrent Guard contributors.
Distributed without warranty. This is an independent implementation with
[qBittorrent checker](https://github.com/sergiobaiao/qbittorrent-checker) as a
design reference.
