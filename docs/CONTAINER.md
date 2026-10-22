# Docker / Unraid: dry-run by default, explicitly authorized live operation

GitHub's Container workflow tests source/privacy, builds an official Python-base
image and runs offline non-root/read-only smoke checks. Normal builds use the
reviewed base pin; maintenance resolves a fresh digest in the same compatible
Python/distro family. Build context
and COPY use exact source allowlists, plus the GPLv3 licence text. No config, grant, API key, login, journal,
logs, handoff, Git checkout, examples or tests are copied into the image. No
credentials are build arguments. GitHub's short-lived registry token is used only
for authorized publication, never passed into the image build.

## Build and publication

Pushes and PRs build/smoke-test without publishing or deploying. Every-two-day maintenance
builds and manual Container dispatch with `publish: true` publish tested candidates
to GHCR in the repository-derived namespace, tagged
`sha-<full-source-commit>-run-<run-id>-<attempt>`. This publishes a candidate, not a
release: candidate publication itself does not change `latest`. A separate
automatic release workflow compares its exact publication evidence, copied
application/licence bytes and build instructions with the current release. Only
compatible dependency-only changes may advance `latest` automatically.
Application/build-policy changes stay held. After review passes, manually dispatch
**Promote reviewed image** on `main` with the exact approved digest, its successful
Container publication run ID, and `review_approved: true`. It checks the source
revision and exact digest in that run's immutable publication artifact before
tagging the existing image as `latest`
without rebuilding it. Passing CI alone cannot release changed application code;
that path still requires an operator's explicit review confirmation.

The template uses `:latest`, so a host's existing image updater can pull reviewed
releases. The immutable candidate digest remains available for audit/rollback.
No host connection, host schedule or deployment is performed by these workflows.
Dependabot proposes base-image/build-action updates; a fresh build every two days refreshes
available Debian packages. See [dependency maintenance](DEPENDENCY-MAINTENANCE.md).
Dependency-only updates are released after tests and unchanged-application checks;
application changes still require review. Rebuilding can update packages even
for the same source. Application-code/scope changes still require fresh live
authorization; a release tag does not bypass runtime permission checks.
New GHCR packages default to private; package access/visibility is an operator
decision. Never paste registry/API credentials into issues or build logs.
New builds carry `GPL-3.0-only` licence metadata and `/app/LICENSE`; the workflow
also records the source repository and exact revision as OCI labels, so users can
locate the matching source and licence. The base image and OS packages retain
their own respective licence terms. Visibility changes do not deploy anything.

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
| `STGUARD_MODE` | Defaults to `dry-run`; `live` additionally requires a private valid code/scope-bound grant |
| `STGUARD_CONFIG_SOURCE` | Defaults to `env`; `file` preserves `/config/connections.json` |
| `STGUARD_SOURCE_POLICY` | New template: `private_exclusions`; known source names are public unless listed as private |
| `TZ` | Defaults to `Australia/Melbourne` |
| `STGUARD_QBIT_URL` | Downloader URL, preferably HTTPS, without embedded credentials |
| `STGUARD_QBIT_USERNAME`, `STGUARD_QBIT_PASSWORD` | Runtime login |
| `STGUARD_SONARR_HD_URL`, `STGUARD_SONARR_UHD_URL` | Separate Sonarr addresses |
| `STGUARD_SONARR_HD_API_KEY`, `STGUARD_SONARR_UHD_API_KEY` | Separate API keys |
| `STGUARD_SONARR_HD_CATEGORY`, `STGUARD_SONARR_UHD_CATEGORY` | Exact distinct categories |
| `STGUARD_SONARR_HD_CLIENT_ID`, `STGUARD_SONARR_UHD_CLIENT_ID` | Pinned downloader IDs per owner |
| `STGUARD_SONARR_HD_PRIVATE_INDEXERS`, `STGUARD_SONARR_UHD_PRIVATE_INDEXERS` | JSON arrays of protected private names |

Both owners and private-exception lists are explicit. New templates omit public
lists: an identified Sonarr indexer is public by policy unless listed as private.
Missing/malformed/ambiguous history remains protected; "unlisted" does not mean
"unidentified". Private matching ignores case and surrounding whitespace. Include
each separately named private/freeleech alias. This does not inspect tracker flags.
See [source policy](SOURCE-POLICY.md) before migrating an existing configuration.
Legacy environment templates with public-list variables and no explicit policy
retain allowlist mode. File configurations without a mode also retain allowlists.
Changing a persisted mode requires explicitly selecting the new environment
policy (or deliberately editing a file in file-source mode), and a new reviewed
code/scope grant before live use. Old approvals cannot authorize the broader mode.
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
margin for process exit before the host escalates. Test stopping/restarting the
container while idle and during an active check in dry-run staging; no array
stop is required. This is a bound on
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

`CONTAINER_LIVE_RELEASE_ENABLED=true` releases only the reviewed container entry
point, not permission to send. Setting live mode alone cannot activate it: startup
requires a private valid code/scope-bound grant, including for `--check-config`.
The routine worker reloads/revalidates permission every cycle and before dispatch.
The image never issues or renews grants. Existing trial grants retain their
seven-day limit; ongoing operation requires a separately approved explicit ongoing
grant, not migration of an expired trial. Container worker source is included in
the approval code digest. See [authorization](UNATTENDED-TRIAL.md).

Before cutover:

1. Review packaging and the exact source/image digest; validate dry-run on Unraid
   using a separate staging appdata directory and real runtime credentials.
2. Agree trial expiry or explicit ongoing permission for the reviewed image.
   Keep retention application separately gated.
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

Publishing the image performs none of those live steps. No media volume or
download-side deletion is added.

## Prepared Unraid template

`deploy/unraid.xml` is a version2 template based on Unraid's official starter.
Its permanent name is `sonarr-torrent-guard`, with dedicated appdata of the same
name: initial dry-run verification is a mode, not a disposable staging container.
The same name/appdata can remain in use after the separately approved live cutover;
removing a staging suffix does not enable live actions or issue permission.
It follows the reviewed `latest` release tag, references the
approved darker PNG, uses bridge networking with no published ports and sets
read-only root, non-root UID/GID1000:1000, dropped capabilities, no-new-privileges,
a10second stop timeout and bounded Docker logs. API/password/username fields are
masked in the form but remain visible to host administrators. The form is not a
secret vault; never share/export its populated XML or command output.

The committed template intentionally uses `REPLACE_ME` for registry/project/icon
ownership and credentials; no deployment identity is stored in source. Prepare
a private installation copy outside the repository using the actual registry
namespace and approved icon URL. Confirm registry pull access on the target;
publishing an image does not make a private GHCR package anonymously pullable.
Do not change package visibility or put a registry token in the template.

Before applying the template on Unraid:

1. Choose the dedicated permanent appdata directory shown in the
   template. Inspect it first; do not overwrite existing appdata. Create it owned
   by1000:1000 with0700 permissions (or explicitly choose a matching non-root
   `--user`). Automatic root-owned creation will fail the worker's ownership check.
2. Install the private XML as a user template using the host's supported template
   management, then select it in Docker/Add Container. Leave auto-start off until
   initial validation passes. There is no web UI link or port to configure yet.
3. Fill connection fields privately, including private-indexer exceptions and
   pinned client IDs; keep mode `dry-run`. An empty private list excludes no
   identified indexers; verify all private aliases before enabling live actions.
   Do not substitute example defaults for actual ownership/source verification.
4. Start it and inspect connectivity, proposals and sanitized wait reasons.
   It must send no removal/blocklist/search requests. Stop/restart it while idle
   and active, check prompt exit rather than forced kill, and confirm config and
   journal/cursor evidence survive. Do not disturb unrelated containers or array.
5. Keep the new appdata separate from the current worker's appdata until cutover.
   Continue using this permanent container name after validation. Live cutover still
   requires the stopped-worker consistent backup/full state transfer and explicit
   new authorization described above; never run two live workers.

Official references:

- [Unraid template starter](https://github.com/unraid/unraid-community-apps-starter/blob/main/templates/example-app.xml)

- [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [Docker build practices](https://docs.docker.com/build/building/best-practices/)
- [Unraid containers](https://docs.unraid.net/unraid-os/using-unraid-to/run-docker-containers/managing-and-customizing-containers/)
