# Dependency maintenance and reviewed releases

The image uses the official Python 3.12 slim Debian Bookworm base, pinned to a
reviewable digest. The application uses Python's standard library: there are no
third-party pip dependencies to update. OS packages, Python and build actions
still need maintenance.

## Automated checks and candidate builds

- Dependabot checks the Docker base on weekdays at 09:10 Melbourne time. It opens
  update PRs; major/minor Python upgrades are excluded from routine updates.
  Base/distro changes still need review. Updating the pin is necessary for newer
  Python builds; rebuilding an unchanged pin alone cannot update Python.
- Dependabot checks GitHub Actions every Monday at 09:20 Melbourne time. It opens
  PRs, not automatic merges. PRs run the source and container tests without
  publishing a release or receiving registry credentials.
- The Container workflow also runs daily at 23:17 UTC (09:17 AEST / 10:17 AEDT,
  Melbourne). Fresh `--pull --no-cache` builds upgrade available Debian packages
  within the configured distro and install current timezone/CA packages. This
  does not change host packages or the distro/Python version line.
- All normal tests, privacy checks, offline non-root smoke checks and the bounded
  active-cycle shutdown test must pass before a scheduled candidate is published.
  Scheduled jobs may be delayed by GitHub; inactive public repositories can have
  schedules disabled by GitHub. Check Actions for failures or missing runs.

Each candidate is tagged `sha-<source>-run-<run-id>-<attempt>`, avoiding tag reuse
when the same source is rebuilt with different packages. The run summary reports
the exact digest. A private GitHub job token is used only by the registry-publish
step; application/API credentials are never involved.

## Review remains required

Dependency PRs are not automatically merged. Candidate publication never changes
`latest`. Review the source changes, build/package logs, tests and exact resulting
image before explicitly dispatching **Promote reviewed image** on `main`.
Provide the digest and publication run ID and confirm `review_approved: true`.

The publication run stores `publication-<run-id>-<attempt>` containing a JSON
record of its exact digest, source, repository, run and attempt. Promotion checks
successful same-repository run provenance, selects one unexpired artifact from
that attempt, verifies its archive SHA256, and compares its recorded image digest
with the requested digest **before any registry login, tagging or push**. A
different build of the same source commit is not interchangeable.

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
