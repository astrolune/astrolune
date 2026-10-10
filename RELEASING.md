<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Release Process

This document defines AstroLune's release process. No release has been published yet, and the checklist below authorizes nothing by itself: publication requires the explicit maintainer authorization described under publication and rollback.

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

**This repository does not invent signing identities or keys.** No maintainer identity and no real or placeholder authority key exists here, and no ceremony has been performed. What does exist now is the ceremony itself: the ordered procedure below, a canonical identity-document and ceremony-transcript format, a revocation-statement format, and an offline verifier with tests. Deciding which key is authoritative is the maintainer's act of running that ceremony with their own key on their own hardware, not a decision this document can make. There is still no transparency log, no countersignature and no threshold policy.

## Release authority key ceremony

The authority key is generated once, on a machine disconnected from every network for the whole ceremony, with two witnesses present throughout. In order: generate the key; read the derived public key back and have both witnesses confirm it independently; compose the transcript recording the date, the entropy source, the hardware, every custody location, both witnesses, every step performed verbatim, and every pre-signing check with its observed result; compose the identity binding that transcript's digest to the validity window and the scope of targets, revisions and artifact names; sign the transcript and then the identity; verify both offline before the machine is reconnected; have both witnesses read the identity digest aloud and write it down independently; seal one vault copy per separately held container, each password held apart from the copy it opens; and only then distribute.

```sh
cli consensus-vault-create authority.vault
python .github/scripts/release-authority.py transcript --authority-public-key <hex> --date <YYYY-MM-DD> --entropy <source> --hardware <machine> --custody <location> --witness <name and role> --step <action> --verified <check and result> --output release/TRANSCRIPT.json
python .github/scripts/release-authority.py identity --authority-public-key <hex> --transcript release/TRANSCRIPT.json --not-before <instant> --not-after <instant> --serial 1 --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-msvc --output release/AUTHORITY.json
cli release-sign release/TRANSCRIPT.json authority.vault release/TRANSCRIPT.json.sig
cli release-sign release/AUTHORITY.json authority.vault release/AUTHORITY.json.sig
python .github/scripts/release-authority.py verify --authority-public-key <hex> --identity release/AUTHORITY.json --identity-signature release/AUTHORITY.json.sig --transcript release/TRANSCRIPT.json --transcript-signature release/TRANSCRIPT.json.sig --output release/VERIFICATION.json
```

`release/AUTHORITY.json` and its signature travel with the release artifacts. The 64-hex identity digest travels separately, published through at least two channels under different administrative control, so an attacker who controls the host serving the artifacts does not also control the value a verifier compares against. A verifier obtains the digest out of band, recomputes it over the identity document it received, compares, and only then checks a manifest against that identity rather than against a bare hex key, which is what binds a signature to a scope and a validity window instead of only to a holder.

```sh
python .github/scripts/release-authority.py verify --authority-public-key <hex> --identity release/AUTHORITY.json --identity-signature release/AUTHORITY.json.sig --transcript release/TRANSCRIPT.json --transcript-signature release/TRANSCRIPT.json.sig --manifest target/ci-artifacts/MANIFEST.json --manifest-signature target/ci-artifacts/MANIFEST.json.sig --at <instant>
```

Expiry is routine: an identity names a bounded window and is refused outside it without a verifier having to learn anything new. Rotation is a second full ceremony producing the next `serial`, whose `predecessor` is the digest of the identity it replaces and whose `not_before` is later; `--predecessor` checks that continuity but never authenticates the predecessor, because a chain that authenticated its own root would make the out-of-band digest pointless. Revocation is a signed statement naming the identity digest it withdraws, and it must be signed by the key it withdraws, so a verifier authenticates it under exactly the key whose authority it ends. On compromise: stop signing; treat every manifest signature whose distribution overlaps the exposure window as unverified; sign and distribute a revocation with reason `compromise` while the key is still available; run a new ceremony; publish the successor's digest beside the compromised one through both out-of-band channels; and re-sign anything that must remain verifiable, because rotation does not make an old signature valid again.

```sh
python .github/scripts/release-authority.py revoke --authority-public-key <hex> --identity release/AUTHORITY.json --date <YYYY-MM-DD> --reason compromise --output release/REVOCATION.json
```

A key that was lost rather than copied cannot be self-revoked at all; that case is handled only by publishing a successor and letting the predecessor's window expire. A verifier sees only a revocation it is given — there is no transparency log, no revocation list and no online status protocol — which is why the validity window is bounded rather than open-ended. The procedure establishes no hardware isolation, no non-exporting signing device, no threshold or multi-party custody, no attestation that the machine was genuinely offline, no monitoring, and no audit; two witnesses are a procedural control and not a cryptographic one, and nothing in the tooling can verify that the recorded custody locations are genuinely separate. The byte-exact document formats are tabulated in [docs/53](docs/53-key-custody-and-release-authority.md).

## Publication and rollback

Publishing packages, images, tags, or release notes is an outward-facing action requiring explicit maintainer authorization. Neither the packaging scripts nor the signing commands publish anything. A release must state supported platforms, upgrade instructions, protocol compatibility, known issues, security contact, and rollback limits. Finalized protocol state may make rollback impossible; application rollback must never be presented as chain rollback.
