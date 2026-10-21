# Dependency maintenance and reviewed releases

The image uses the official Python 3.12 slim Debian Bookworm base. Normal builds
use the repository's reviewable pin; maintenance builds resolve the current digest
of that same compatible tag and record it in image labels. The application uses
Python's standard library: there are no
third-party pip dependencies to update. OS packages, Python and build actions
still need maintenance.

## Automated checks and candidate builds

- Dependabot checks the Docker base on weekdays at 09:10 Melbourne time. It opens
  update PRs; major/minor Python upgrades are excluded from routine updates.
  Base-family/distro changes still need review. Daily maintenance independently
  resolves the compatible Python tag, so security patch delivery does not wait
  for those bookkeeping PRs to be merged.
- Dependabot checks GitHub Actions every Monday at 09:20 Melbourne time. It opens
  PRs, not automatic merges. PRs run the source and container tests without
  publishing a release or receiving registry credentials.
- The Container workflow also runs daily at 23:17 UTC (09:17 AEST / 10:17 AEDT,
  Melbourne). It pulls the current official Python 3.12 Bookworm base and renders
  that exact digest into a temporary Dockerfile without editing the checkout.
  Fresh `--pull --no-cache` builds upgrade available Debian packages
  within the configured distro and install current timezone/CA packages. This
  does not change host packages or the distro/Python version line.
- All normal tests, privacy checks, offline non-root smoke checks and the bounded
  active-cycle shutdown test must pass before a scheduled candidate is published.
  The full regression suite also runs using the built image's Python/system
  libraries, with only read-only source and temporary test files mounted in CI.
  Scheduled jobs may be delayed by GitHub; inactive public repositories can have
  schedules disabled by GitHub. Check Actions for failures or missing runs.

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
