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

`.github/scripts/verify-native-build.py` builds each supported target twice in fresh directories with `SOURCE_DATE_EPOCH=0`, `--remap-path-prefix`, `-Cstrip=debuginfo` and `/Brepro` on MSVC, compares the bytes, and writes `native-reproducibility.json`. `.github/scripts/package-build.py` then checks that report against the exact binaries and compiler, emits the in-archive `BUILD.json` provenance record, builds a deterministic USTAR/gzip archive, and writes `SHA256SUMS` plus a signable `MANIFEST.json`.

`MANIFEST.json` is the `BUILD.json` record plus the archive name and SHA-256 digest, serialized with sorted keys and an LF terminator. It therefore commits to the archive bytes and, through `files`, to every packaged file. Equal inputs produce an equal manifest and an equal signature. `--release` records release intent in both `BUILD.json` and `MANIFEST.json`; it changes the archive digest and authorizes nothing. These scripts still perform no signing, no key handling and no upload.

```sh
python .github/scripts/package-build.py <target> --release
cli release-sign target/ci-artifacts/MANIFEST.json <authority-key> target/ci-artifacts/MANIFEST.json.sig
cli verify-release target/ci-artifacts/MANIFEST.json <authority-public-key> target/ci-artifacts/MANIFEST.json.sig
```

`release-sign` reads a raw 32-byte seed or an encrypted consensus vault, with the password supplied on a private stdin pipe and never in arguments; there is no plaintext export command. The detached signature is 136 bytes: `ALRS0001`, the signing public key, the manifest digest under the domain `astrolune.release.manifest.v1`, and a strict Ed25519 signature. `verify-release` requires the authority public key to be supplied explicitly, compares it with the key embedded in the artifact, and treats disagreement as an authentication failure. The mechanism is documented in [docs/53](docs/53-key-custody-and-release-authority.md).

Release artifacts must be built from a clean tagged revision, include source and license notices, identify the Rust toolchain and target, publish checksums and a software bill of materials, and be accompanied by a signed manifest verified from an independently obtained authority key.

**This repository does not invent signing identities or keys.** No maintainer identity, no real or placeholder authority key, and no key ceremony exists here. Which key is authoritative, how it is generated, held, distributed, countersigned, rotated and revoked, and how verifiers obtain it out of band, must be decided and documented before any release is signed. There is no transparency log, no expiry, no revocation and no threshold policy.

## Publication and rollback

Publishing packages, images, tags, or release notes is an outward-facing action requiring explicit maintainer authorization. Neither the packaging scripts nor the signing commands publish anything. A release must state supported platforms, upgrade instructions, protocol compatibility, known issues, security contact, and rollback limits. Finalized protocol state may make rollback impossible; application rollback must never be presented as chain rollback.
