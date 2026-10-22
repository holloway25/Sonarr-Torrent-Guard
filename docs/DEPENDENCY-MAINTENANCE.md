# Dependency maintenance and reviewed releases

The image targets the official Python 3.15 slim Debian 13 Trixie base. Normal builds
use the repository's reviewable pin; maintenance builds resolve the current digest
of that same compatible tag and record it in image labels. The application uses
Python's standard library: there are no
third-party pip dependencies to update. OS packages, Python and build actions
still need maintenance.

## Automated checks and candidate builds

- Dependabot checks the Docker base every Monday at 09:10 Melbourne time. It opens
  update PRs; major/minor Python upgrades are excluded from routine updates.
  Base-family/distro changes still need review. Three-day maintenance independently
  resolves the compatible Python tag, so security patch delivery does not wait
  for those bookkeeping PRs to be merged.
- Dependabot checks GitHub Actions every Monday at 09:20 Melbourne time. It opens
  PRs, not automatic merges. PRs run the source and container tests without
  publishing a release or receiving registry credentials.
- GitHub checks the maintenance cadence daily at 23:17 UTC (09:17 AEST /
  10:17 AEDT the following day, Melbourne). A lightweight gate permits an image
  build only when the UTC day count since the Unix epoch is divisible by three: every 72 hours,
  including across month/year boundaries. Off-days skip the build and publish
  jobs; push/PR tests and explicitly requested manual builds are not delayed.
  A due build pulls the current official Python 3.15 Trixie base and renders
  that exact digest into a temporary Dockerfile without editing the checkout.
  Fresh builds with pull and no-cache enabled upgrade available Debian packages
  within the configured distro and install current timezone/CA packages. This
  does not change host packages or the distro/Python version line.
- All normal tests, privacy checks, offline non-root smoke checks and the bounded
  active-cycle shutdown test must pass before a scheduled candidate is published.
  The full regression suite also runs using the built image's Python/system
  libraries, with only read-only source and temporary test files mounted in CI.
  Scheduled jobs may be delayed by GitHub; inactive public repositories can have
  schedules disabled by GitHub. Check Actions for failures or missing runs.

## What updates and what stays pinned

- Compatible Python 3.15 patch releases and Debian Trixie package updates are
  included in maintenance builds, including timezone data and trusted CA certificates.
  There are no third-party pip packages in this application.
- Python's major/minor version and the Debian distribution stay fixed. The
  repository Dockerfile pins an exact base-image digest. Each maintenance build
  resolves a fresh compatible digest and then builds against that exact digest;
  its identity is recorded in the resulting image labels.
- Actions used by image publication and release workflows are pinned to full
  commit hashes. Dependabot proposes action updates as reviewable PRs; it does
  not merge them automatically. The general Checks workflow uses major-version
  action tags; this is separate from dependencies inside the Docker image.
- Published candidate images have unique build tags and immutable digests.
  The host-facing `latest` tag deliberately moves after the release checks pass,
  allowing an independently configured host updater to receive updates. Pinning
  the host to one digest instead would prevent those automatic updates.
- Application-code changes still need review. The three-day schedule changes only
  GitHub maintenance, not any host's polling schedule or runtime settings.

Python-family and Debian-release upgrades are deliberate, review-gated migrations,
not routine dependency refreshes. The pinned Trixie base was verified as Python
3.15.1. CI checks the actual interpreter and OS family, trusted CA loading, runs
the full suite inside the new image and exercises configuration/startup and
bounded shutdown. Automatic release rejects previous Python-family or Bookworm
baselines: the first Trixie image needs explicit reviewed promotion before
three-day Python 3.15/Trixie maintenance can advance `latest`. Existing appdata,
logs, journals and permissions are retained; changing the base is not authority
to migrate or reset runtime state. Application changes bundled with a migration
still require approved code-bound live authorization before deployment.
This source configuration alone does not deploy or change an existing container.

Trixie is Debian's current stable release, with full support through August 2028
and LTS through June 2030; see [Debian's release information](https://www.debian.org/releases/trixie/).
The image contains user-space packages, not a separate kernel or full OS install;
this change does not upgrade the container host's operating system.

## CI minutes and caching

- Source and container checks run for `main` pushes and pull requests, not release
  tag pushes or pushes to the secondary development branch. Newer commits cancel
  older tests for the same branch/PR. Scheduled/manual publishers use unique,
  non-cancelling groups; promotion keeps its existing non-cancelling release lock.
- There are no application pip dependencies to download/cache. Commit-pinned
  Docker Buildx/build actions reuse GitHub-hosted image-layer cache for test builds.
  Only `main` push tests export cache; PRs and publishers do not write that cache.
  No credentials, runtime config, appdata or journals are stored in it.
- Cache is an optimization, not release evidence. Maintenance and explicitly
  published candidates always pull the compatible base and disable layer reuse
  for the build, ensuring package upgrades execute. All source/privacy tests,
  built-image tests and startup/shutdown checks still run before publication.
  Cache export failure is non-fatal and bounded to avoid wasting CI minutes.
- The daily cadence check is lightweight; the full maintenance build runs every
  three days. This reduces future usage but cannot reset an exhausted GitHub
  allowance or guarantee an immediate hosted run. No billing settings are changed.

Each candidate is tagged `sha-<source>-run-<run-id>-<attempt>`, avoiding tag reuse
when the same source is rebuilt with different packages. The run summary reports
the exact digest. A private GitHub job token is used only by the registry-publish
step; application/API credentials are never involved.

## Automatic dependency release; manual application review

PRs are not automatically merged. After a successful published maintenance build
on `main`, **Release tested dependency refresh** runs automatically. It verifies
publication evidence, then compares all copied application files and the licence
against the currently released image's source. It also compares complete Docker
build instructions, ignoring only the compatible base digest. Changes to guard
code, startup settings, permissions, COPY inputs, licence, Python family or distro
are held for manual review. It additionally hashes all application/licence files
inside both actual images before retagging anything.

One narrow bootstrap is authorized: the pre-maintenance released Dockerfile may
lack the package-upgrade step; adding that exact step is allowed while everything
else remains unchanged. Removing the step or adding other commands is not allowed.
Build-order labels reject older/repeated builds. Automatic and manual publishers
share one release lock, so a queued old-code maintenance build cannot roll back a
new manually reviewed application release. Missing evidence blocks release.

If the above checks pass, dependency-only images advance `latest` without a human
approval or a host-side script. A change held for application/build review can
still be released using **Promote reviewed image** on `main` with its digest,
successful publication run ID and explicit `review_approved: true`. That new
reviewed release becomes the baseline for subsequent dependency refreshes.

The publication run stores `publication-<run-id>-<attempt>` containing a JSON
record of its exact digest, source, repository, run and attempt. Promotion checks
successful same-repository run provenance, selects one unexpired artifact from
that attempt, verifies its archive SHA256, and compares its recorded image digest
with the requested digest for manual promotion, or selects that exact digest for
automatic dependency checks, **before any registry login, tagging or push**. A
different build of the same source commit is not interchangeable. Both paths use
the same run/artifact verifier; automation does not remove publication binding.

Missing/expired/ambiguous evidence fails closed; there is no label-only fallback.
Old candidates created before publication evidence was introduced need a new
build and review, not a fabricated backfilled artifact. Artifacts are requested
for 90 days; repository retention limits may shorten availability. Promotion
retags the exact approved image without rebuilding it.

The host's existing updater can then pull `latest`; GitHub never connects to the
host or changes its schedule, appdata or services. Dependency-only image rebuilds
with identical application source/scope retain their code-bound permission.
Application-source or scope changes still require a newly approved grant; image
tags never bypass authorization. Existing resolved/unresolved journal evidence
must be preserved during host updates.

References: [Dependabot configuration](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-version-updates),
[scheduling limits](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule),
[Actions artifacts](https://docs.github.com/en/rest/actions/artifacts).
