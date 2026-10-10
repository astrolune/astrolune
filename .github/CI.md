<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Automation

All workflows run on pull requests and pushes (security pushes are limited to
`main`), and support manual runs through `workflow_dispatch`. Security checks also
run weekly. Superseded runs on the same branch or pull request are cancelled.

## CI

- Formatting runs once on Linux.
- Clippy checks all targets and features on Linux and Windows, denying warnings.
- Workspace unit, integration, and documentation tests run on both platforms in
  development and release profiles. Each leg records a deterministic
  `SUITE.json` result and uploads it as `suite-<os>-<profile>`.
- `Four-leg suite qualification` downloads all four of those results and refuses
  the matrix unless every declared leg is present exactly once, clean, and
  agreeing with the others on one compiler. A leg that produced no result is an
  error there, never an absence that passes quietly. It runs even when a test
  leg fails, so the verdict names which leg was absent or unclean.
- Rustdoc builds all workspace documentation with warnings denied.
- Release builds compile the workspace on Linux x86-64 and Windows x86-64.
  Smoke checks exercise each binary's help output, daemon configuration, block
  production, restart, and recovery using temporary data and ephemeral ports.
- `Independent-run reproducibility` looks for another successful run of the same
  revision, downloads its retained `QUALIFICATION.json`, and compares the two.
  An absent second run, or an expired artifact, is reported and establishes
  nothing; it is never reported as agreement.
- Actionlint validates GitHub Actions workflows.
- `CI required checks` succeeds only if every preceding CI job succeeds. Configure
  it as a required branch check, together with the separate dependency-policy,
  advisories, and Markdown links checks. Repository settings are not changed by
  these files.

Cargo commands use the pinned toolchain, `--locked`, and dependency caching.
Each job has a timeout. Test matrix failures do not cancel other matrix entries.

## Build artifacts

Successful build jobs retain `astrolune-<target>` artifacts for 14 days. Each
contains a `.tar.gz` with `cli`, `daemon`, and `cargo-contract`, the project license,
README, Cargo lockfile, toolchain declaration, and `BUILD.json` (revision, target,
compiler, profile, and features). `SHA256SUMS` contains the archive checksum.
The tar archive preserves Unix executable permissions when downloaded.

These are unsigned CI builds, including builds from pull requests. A successful
build job does not imply that the other checks passed. Check the complete run
before using an artifact. No workflow publishes GitHub Releases, packages,
containers, or deployments. Production delivery still requires the process in
[`RELEASING.md`](../RELEASING.md).

## Qualification artifacts

`suite-<os>-<profile>` holds one matrix leg's deterministic suite result and
`suite-qualification` the four-leg verdict over all of them; both are retained
for 90 days. `qualification-<target>` holds one run's platform qualification
report, and `reproducibility-<target>` the comparison against another run of the
same revision when one exists. These are retained for 90 days because comparing
two machines means holding one run's evidence until a second machine produces
its own.

`ASTROLUNE_MACHINE` is `<runner name>#<run id>.<attempt>`, so two runs are always
two distinct machine identities to the comparator even when the hosted runner is
the same image. That makes the comparison stronger than a single run and weaker
than two independently administered hosts; the limit is recorded in
[docs/39](../docs/39-toolchain-and-release-qualification.md). No workflow signs,
publishes, or holds any key material, and no workflow performs the release
authority key ceremony described in
[`RELEASING.md`](../RELEASING.md).
