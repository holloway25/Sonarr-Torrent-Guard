# Docker / Unraid: dry-run review candidate

GitHub's Container workflow tests source/privacy, builds a digest-pinned official
Python-base image and runs offline non-root/read-only smoke checks. Build context
and COPY use exact source allowlists. No config, grant, API key, login, journal,
logs, handoff, Git checkout, examples or tests are copied into the image. No
credentials are build arguments. GitHub's short-lived registry token is used only
for explicitly requested publication, never passed into the image build.

## Build and publication

Pushes and PRs build/smoke-test without publishing or deploying. Manual Container
workflow dispatch with `publish: true` publishes to GHCR in the repository-derived
namespace, tagged `sha-<full-source-commit>`. No latest tag, self-update or Unraid
deployment is added. Pin the resulting image digest for an approved deployment:
rebuilding can update OS certificate/timezone packages even for the same source.
New GHCR packages default to private; package access/visibility is an operator
decision. Never paste registry/API credentials into issues or build logs.

## Unraid settings

Mount ONE dedicated persistent appdata subdirectory read/write at `/config`.
Never mount a general appdata root, media/download/library share or Docker socket.
No privileged mode, exposed port, host network or web UI is needed. Bridge
networking must reach the configured API endpoints with normal TLS verification.
The image includes timezone data and defaults to `TZ=Australia/Melbourne`.

Default UID/GID is1000:1000. Own appdata with that non-root identity, or select a
different `--user` with matching ownership. The worker restricts its dedicated
mount to0700 and runtime files to0600; do not map a shared general-purpose folder.
The root filesystem may be read-only, capabilities dropped and no-new-privileges
enabled. `/tmp` may be a tmpfs. Image updates must preserve persistent appdata.

Use Unraid environment fields or a private environment file. Generic examples are
in `deploy/container.env.example`; NEVER commit edited deployment values. Runtime
environment variables are visible to Docker/Unraid administrators, as accepted
by the operator; they are not claimed to be hidden from root.

| Variables | Meaning |
| --- | --- |
| `STGUARD_MODE` | Defaults to `dry-run`; `live` is currently refused |
| `STGUARD_CONFIG_SOURCE` | Defaults to `env`; `file` preserves `/config/connections.json` |
| `TZ` | Defaults to `Australia/Melbourne` |
| `STGUARD_QBIT_URL` | Downloader URL, preferably HTTPS, without embedded credentials |
| `STGUARD_QBIT_USERNAME`, `STGUARD_QBIT_PASSWORD` | Runtime login |
| `STGUARD_SONARR_HD_URL`, `STGUARD_SONARR_UHD_URL` | Separate Sonarr addresses |
| `STGUARD_SONARR_HD_API_KEY`, `STGUARD_SONARR_UHD_API_KEY` | Separate API keys |
| `STGUARD_SONARR_HD_CATEGORY`, `STGUARD_SONARR_UHD_CATEGORY` | Exact distinct categories |
| `STGUARD_SONARR_HD_CLIENT_ID`, `STGUARD_SONARR_UHD_CLIENT_ID` | Pinned downloader IDs per owner |
| `STGUARD_SONARR_HD_PUBLIC_INDEXERS`, `STGUARD_SONARR_UHD_PUBLIC_INDEXERS` | JSON arrays of exact approved public names |
| `STGUARD_SONARR_HD_PRIVATE_INDEXERS`, `STGUARD_SONARR_UHD_PRIVATE_INDEXERS` | JSON arrays of protected private names |

Both owners and public/private lists are explicit; unknown sources stay protected.
The binding endpoint is QBIT_URL, maintaining the exact endpoint contract. Config
stays `dry_run: true`. New appdata uses labels Sonarr-HD and Sonarr-UHD. When a
config already exists, environment mode matches normalized Sonarr/downloader
endpoints, category and pinned client ID and preserves its exact existing labels
(including HD/UHD). Credential rotation does not rename owners. Changed or
ambiguous bindings, extra/missing owners, or a journal without its connection
config require an explicit identity migration; startup refuses to guess and does
not replace the config. File mode preserves existing labels and settings.
Both modes check active and archived journal owner identities and recorded live
bindings read-only before scheduling. Mismatched or unreadable evidence blocks
startup, never resets holds. Retain the original config with the entire appdata;
do not edit labels or delete evidence to work around a refusal.
Invalid input does not overwrite a valid config. The generated private runtime file contains credentials: do not
print/export/commit it. Children receive that file, not secret environment values
or credential command-line arguments.

Persistent `/config` contains connection config, entire journal/archive, batch
cursor, locks, optional routine grant, private live log and container heartbeat.
Do not replace this directory when updating an image or reset it to bypass holds.

## Scheduler and health

The Python PID1 scheduler runs one cycle, then waits600 seconds after completion.
No overlapping cycles or catch-up bursts. Dry-run uses existing public assessment
and read-only recovery, including Sonarr's non-saving connection diagnostic; no
removal, blocklisting or searches. Maintenance waits retry on later cycles.
`--once` runs one cycle; `--check-config` validates only, with no API requests.
A lifetime lock prevents another container using the SAME appdata; it cannot
detect independent workers using different copies elsewhere.

The existing three-minute API deadline remains, with an outer210-second child
timeout measured against one monotonic deadline. Active child waits poll at most
every0.25seconds; SIGTERM/SIGINT do NOT wait for that cycle deadline. Stop requests
are checked before launch, immediately after creation and throughout active waits.
Shutdown sends TERM with a2second grace, then KILL with a2second bounded reap.
The worker-controlled waiting budget is at most4.25seconds after a stop request,
not210seconds. The scheduler exits without starting a final heartbeat/appdata
fsync or another cycle. Repeated signals do not reset the shutdown waits.

Configure Docker/Unraid's container stop timeout to at least10seconds, leaving
margin for process exit before the host escalates. Verify actual array-stop
behavior during dry-run staging before enabling live mode. This is a bound on
application waiting, not a guarantee against an uninterruptible kernel/storage
stall or other containers delaying array shutdown. Do not change Unraid's array
unmount/parity safety settings to compensate for an application shutdown fault.
Durable intent/no-replay evidence survives
in appdata; restarting does not renew grants or blindly repeat uncertain actions.

Health means a recent scheduler heartbeat, NOT healthy API connectivity, valid
permission or completed cleanup. Check sanitized cycle logs for waits/errors.
Startup errors never print environment values/raw exceptions. Configure bounded
Docker log rotation on the host too. No automatic journal archival is enabled.

## Live migration is separate

`CONTAINER_LIVE_RELEASE_ENABLED=false`; setting live mode alone cannot activate
it even if a grant is present. The image never issues or renews grants. Existing
seven-day maximum/expiry rules remain; moving to Unraid is NOT indefinite live
authorization. Container worker source is included in the approval code digest.

Before cutover:

1. Review packaging and the exact source/image digest; validate dry-run on Unraid
   using a separate staging appdata directory and real runtime credentials.
2. Agree live permission and expiry; enable the reviewed container gate only
   after approval. Keep retention application separately gated.
3. STOP and disable the LXC live service/timer before ANY container live action.
4. Take a private consistent backup while stopped and transfer the ENTIRE journal,
   archive, cursor and identity evidence, not just credentials/hashes. Never copy
   a database while a writer is active or replace it with an old snapshot.
5. Revalidate labels, bindings, sources, categories, permissions and clock. Issue
   a new explicit code/scope-bound grant for that source; do not silently extend
   an existing expiry. A source/image change invalidates old code authorization.
6. Run ONE live worker, verify logs and the first eligible action. Keep the old
   worker disabled. Rollback must stop the new worker and preserve newer evidence
   before considering old source; never use an old journal to bypass holds.

Publishing the image performs none of those live steps and does not automatically
create an Unraid template. No media volume or download-side deletion is added.

Official references:

- [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [Docker build practices](https://docs.docker.com/build/building/best-practices/)
- [Unraid containers](https://docs.unraid.net/unraid-os/using-unraid-to/run-docker-containers/managing-and-customizing-containers/)
