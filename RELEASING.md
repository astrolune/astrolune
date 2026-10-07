<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Release Process

No production release process is active. This document defines the minimum future baseline; it does not authorize publishing artifacts.

## Preconditions

A release candidate must have an approved scope, updated changelog and compatibility notes, pinned toolchain and dependencies, passing CI on supported platforms, reproducible test vectors, dependency/security review, and documented remaining risks.

Consensus-affecting releases additionally require protocol versioning, activation rules, migration and rollback analysis, cross-version interoperability tests, deterministic fixtures across supported targets, and independent review appropriate to the change.

## Candidate checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
cargo audit
```

Run extended fuzzing, sanitizer/Miri checks where applicable, distributed consensus scenarios, snapshot/recovery tests, and performance calibration outside the short CI gate.

## Artifacts

Future release artifacts must be built from a clean tagged revision, include source and license notices, identify the Rust toolchain and target, publish checksums and a software bill of materials, and use a release-signing process documented before use. This repository does not invent signing identities or keys.

## Publication and rollback

Publishing packages, images, tags, or release notes is an outward-facing action requiring explicit maintainer authorization. A release must state supported platforms, upgrade instructions, protocol compatibility, known issues, security contact, and rollback limits. Finalized protocol state may make rollback impossible; application rollback must never be presented as chain rollback.
