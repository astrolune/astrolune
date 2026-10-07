<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Automation

All workflows run on pull requests and pushes (security pushes are limited to
`main`), and support manual runs through `workflow_dispatch`. Security checks also
run weekly. Superseded runs on the same branch or pull request are cancelled.

## CI

- Formatting runs once on Linux.
- Clippy checks all targets and features on Linux and Windows, denying warnings.
- Workspace unit, integration, and documentation tests run on both platforms in
  development and release profiles.
- Rustdoc builds all workspace documentation with warnings denied.
- Release builds compile the workspace on Linux x86-64 and Windows x86-64.
  Smoke checks exercise each binary's help output, daemon configuration, block
  production, restart, and recovery using temporary data and ephemeral ports.
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
