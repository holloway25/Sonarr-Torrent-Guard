# Docker / Unraid: dry-run by default, explicitly authorized live operation

GitHub's Container workflow tests source/privacy, builds an official Python-base
image and runs offline non-root/read-only smoke checks. Normal builds use the
reviewed base pin; maintenance resolves a fresh digest in the same compatible
Python/distro family. Build context
and COPY use exact source allowlists, plus the GPLv3 licence text. No config, grant, API key, login,
logs, handoff, Git checkout, examples or tests are copied into the image. No
credentials are build arguments. GitHub's short-lived registry token is used only
for authorized publication, never passed into the image build.

## Build and publication

Main-branch pushes and PRs build/smoke-test without publishing or deploying. Release
tag pushes do not rerun the full suite. Every-three-day maintenance
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
Dependabot proposes base-image/build-action updates; a fresh build every three days refreshes
available Debian packages. See [dependency maintenance](DEPENDENCY-MAINTENANCE.md).
Superseded push/PR tests are cancelled, but publishing and promotion runs are not.
Test builds reuse cached image layers; maintenance and manual publishing builds
still pull the base and rerun package upgrades without reusing cached RUN layers.
Dependency-only updates are released after tests and unchanged-application checks;
application changes still require review. Rebuilding can update packages even
for the same source. The container keeps the configured mode across image updates.
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

Default UID/GID is `1000:1000`. Own appdata with that non-root identity, or select a
different `--user` with matching ownership. The worker restricts its dedicated
mount to `0700` and runtime files to `0600`. Use a dedicated folder.
The root filesystem may be read-only, capabilities dropped and no-new-privileges
enabled. `/tmp` may be a tmpfs. Image updates must preserve persistent appdata.

Use Unraid environment fields or a private environment file. Generic examples are
in `deploy/container.env.example`. Keep deployment values in private files.
Git ignores `*.env` files, and the privacy check rejects actual Guard credential
assignments even in files with other names. It also checks the values and
defaults in Unraid template XML. Runtime
environment variables are visible to Docker/Unraid administrators, as accepted
by the operator; they are not claimed to be hidden from root.

| Variables | Meaning |
| --- | --- |
| `STGUARD_MODE` | Defaults to `dry-run`. Live mode permits verified public file-policy cleanup and qualifying metadata retries. |
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
policy (or deliberately editing a file in file-source mode). Review the source
policy before running in live mode.
The binding endpoint is QBIT_URL, maintaining the exact endpoint contract. Config
stays `dry_run: true`. New appdata uses labels Sonarr-HD and Sonarr-UHD. When a
config already exists, environment mode matches normalized Sonarr/downloader
endpoints, category and pinned client ID and preserves its exact existing labels
(including HD/UHD). Credential rotation does not rename owners. Changed or
ambiguous bindings or extra/missing owners require an explicit identity
migration. Startup preserves the existing configuration on failure. File mode
uses the supplied private configuration.

Invalid input does not overwrite a valid config. The generated private runtime file contains credentials: do not
print/export/commit it. Children receive that file, not secret environment values
or credential command-line arguments.

Persistent `/config` contains the connection config, batch cursors, locks,
approved live scope, rotating `dry-run.log` and `routine.log`, and the
container heartbeat. Preserve the appdata directory when updating the image.

## Scheduler and health

The scheduler runs one cycle, then waits 600 seconds after completion.
Cycles do not overlap or catch up in bursts. Dry-run uses Sonarr's non-saving
connection diagnostic and logs proposed removals or holds. Live mode records
removal and search outcomes. The worker does not consult either log.
Maintenance waits are retried on later cycles.
`--once` runs one cycle. `--check-config` validates the candidate configuration
and live scope without sending API requests or saving the configuration or scope.
A lifetime lock prevents another container using the SAME appdata; it cannot
detect independent workers using different copies elsewhere.

The existing three-minute API deadline remains, with an outer 210-second child
timeout measured against one monotonic deadline. Active child waits poll at most
every 0.25 seconds. SIGTERM and SIGINT start shutdown immediately. Stop requests
are checked before launch, immediately after creation and throughout active waits.
Shutdown sends TERM with a 2-second grace period, then KILL with up to 2 seconds to reap the child.
The worker-controlled waiting budget is at most 4.25 seconds after a stop request. The scheduler exits without starting a final heartbeat/appdata
fsync or another cycle. Repeated signals do not reset the shutdown waits.

Configure Docker/Unraid's container stop timeout to at least 10 seconds, leaving
margin for process exit before the host escalates. Test stopping/restarting the
container while idle and during an active check in dry-run staging; no array
stop is required. This is a bound on
application waiting, not a guarantee against an uninterruptible kernel/storage
stall or other containers delaying array shutdown. Do not change Unraid's array
unmount/parity safety settings to compensate for an application shutdown fault.
Each pass uses the current queues and file manifests. If a previous request was
interrupted, an item still present can qualify again on fresh evidence.

Health means a recent scheduler heartbeat, NOT healthy API connectivity, valid
permission or completed cleanup. Check sanitized cycle logs for waits/errors.
Startup errors never print environment values/raw exceptions. Configure bounded
Docker log rotation on the host too.

## Live mode and cutover

`STGUARD_MODE=live` allows the owning Sonarr's native Remove and Blocklist
action for verified bad public files. Sonarr handles its own replacement.
[Metadata retry](METADATA-RETRY.md) is available separately through the same live
worker. Unset the variable or set it to `dry-run`
for reporting only. Apply a mode change by recreating the
container with the new environment. To stop new live requests immediately,
stop the container. A request already sent can still complete.

Fresh appdata records the configured cleanup scope on the first live start.
Subsequent image updates reuse the approved record while the scope and rule
match. Upgrading from the v3 cleanup rule to v4 requires one scope confirmation
because selected blocked file types now qualify for removal. A worker configured
as live reports `container_live_scope_confirmation_required` until that confirmation
is recorded. Use the procedure below to approve the reviewed scope.

Changing scope, including removing a private indexer exception, holds live
cleanup until you confirm the new settings. A missing, unreadable or changed
scope record cannot authorize a running cycle. Before removal and search, Guard
re-reads both the scope record and the connection file.

To confirm an existing install or a changed scope, stop the normal worker and
use the same dedicated appdata and reviewed image. Choose the command that
matches how the normal container gets its settings.

For file-managed installs, save and review the intended changes in
`connections.json`, then approve that file.

```sh
docker run --rm --network none \
  --mount type=bind,source=APPDATA_PATH,target=/config \
  -e STGUARD_CONFIG_SOURCE=file -e STGUARD_MODE=live \
  REVIEWED_IMAGE --approve-live-scope
```

For environment-managed installs, put the full intended connection and source
settings in a private environment file. Include the same values you will use in
Unraid or Docker, including the changed private-indexer list. Pass that file to
the approval command.

```sh
docker run --rm --network none \
  --mount type=bind,source=APPDATA_PATH,target=/config \
  --env-file PRIVATE_ENV_FILE \
  -e STGUARD_CONFIG_SOURCE=env -e STGUARD_MODE=live \
  REVIEWED_IMAGE --approve-live-scope
```

Both commands write the scope record and exit without calling Sonarr or the
downloader. The environment-managed command also saves the validated settings
to `connections.json`.
Start the normal container in your chosen mode after the command succeeds. Standalone service installations normally use [private grants](UNATTENDED-TRIAL.md).
The internal `routine.py --live --container-mode` entry point explicitly selects
environment-based authorization. It requires `STGUARD_MODE=live` and works on
any host that invokes it. A container runtime is not an authorization boundary.

For a migration from another worker, stop and disable the old worker first.
Preserve the existing configuration, logs, cursors and any historical files.
Verify labels, bindings, source policy, permissions and clock, then run one
worker and check its cycle logs.

## Prepared Unraid template

`deploy/unraid.xml` is a version2 template based on Unraid's official starter.
Its permanent name is `sonarr-torrent-guard`, with dedicated appdata of the same
name: initial dry-run verification is a mode, not a disposable staging container.
The same name/appdata can remain in use after the separately approved live cutover;
removing a staging suffix does not enable live actions or issue permission.
It follows the reviewed `latest` release tag, references the
approved darker PNG, uses bridge networking with no published ports and sets
read-only root, non-root UID/GID `1000:1000`, dropped capabilities, no-new-privileges,
a 10-second stop timeout and bounded Docker logs. API/password/username fields are
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
   by `1000:1000` with `0700` permissions (or explicitly choose a matching non-root
   `--user`). Automatic root-owned creation will fail the worker's ownership check.
2. Install the private XML as a user template using the host's supported template
   management, then select it in Docker/Add Container. Leave auto-start off until
   initial validation passes. There is no web UI link or port to configure yet.
3. Fill connection fields privately, including private-indexer exceptions and
   pinned client IDs; keep mode `dry-run`. An empty private list excludes no
   identified indexers; verify all private aliases before enabling live actions.
   Do not substitute example defaults for actual ownership/source verification.
4. Start it in dry-run and inspect connectivity, file-policy proposals, metadata
   proposals and wait reasons. Confirm that known private and healthy torrents
   are skipped or kept. Stop/restart it while idle
   and active, check prompt exit rather than forced kill, and confirm config and
   logs and cursors survive. Do not disturb unrelated containers or array.
5. Keep the new appdata separate from the current worker's appdata until cutover.
   Continue using this permanent container name after validation. Live cutover still
   requires the stopped-worker consistent backup and full state transfer described
   above. Set the mode to `live` when ready, and never run two live workers.

Official references:

- [Unraid template starter](https://github.com/unraid/unraid-community-apps-starter/blob/main/templates/example-app.xml)

- [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [Docker build practices](https://docs.docker.com/build/building/best-practices/)
- [Unraid containers](https://docs.unraid.net/unraid-os/using-unraid-to/run-docker-containers/managing-and-customizing-containers/)
