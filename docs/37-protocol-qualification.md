<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 37. Protocol qualification tools

The workspace's focused tests retain canonical transaction, receipt, state,
consensus and cryptographic fixtures. Version compatibility is checked through
strict decoding and exact accepted-input re-encoding. Add a new fixture when
changing a protocol domain, canonical field or activation rule; do not silently
update an expected hash merely to make tests pass.

The shared extension oracle in `tests/integration/tests/support/extensions.rs`
covers VRF envelopes and verification, committee states, role-paired contributions,
complete batches, certified handoffs, state value proofs, certified state and
receipt proofs, stored effects, scoped discovery envelopes, DNS registry calls
and bounded WASM validation/execution. The same oracle runs in a stable-toolchain
mutation test and the `decode_extensions` libFuzzer target. Accepted bytes must
re-encode identically. Accepted WASM modules execute twice with the same explicit
input/context and bounded fuel, and must return identical outputs or errors.

```text
cargo test -p integration --test mutations
cargo test -p integration --test mutations extended_extension_mutations -- --ignored
cargo check --manifest-path crates/codec/fuzz/Cargo.toml
```

The ordinary test performs 3,000 deterministic mutations; the extended test
performs 100,000. Seeds include valid proofs, an effects bundle, a DNS registration,
a discovery envelope, a returning WASM module and a fuel-exhausting loop. Four
additional valid rotation envelopes exercise the new handoff boundaries. Mutations
include byte substitutions, truncations, insertion, deletion and maximum-length
field patterns. The fixed PRNG seed makes failures reproducible across platforms.

All standalone libFuzzer targets compile locally. Running coverage-guided,
sanitizer-enabled campaigns additionally needs a suitable nightly/cargo-fuzz
installation. From `crates/codec`, the new target is selected with
`cargo +nightly fuzz run decode_extensions`. Set campaign time, maximum input
length and RSS/timeout bounds for the selected environment; retain and minimize
any crashing corpus. Existing transaction, genesis, consensus, network and state
fuzz targets remain separate entry points.

On 2026-09-28 the Windows Rust 1.93.1 build passed the 100,000-input deterministic
extension campaign, workspace tests, Clippy with warnings denied, rustdoc, native
and wasm32 SDK checks, and all four explicitly invoked real Rust-to-WASM tool
tests. These are local checks. Long coverage-guided campaigns, Linux qualification
of these changes, independent alternate execution backends and reproducible native
release binaries remain separate ROADMAP work; a mutation smoke test does not
establish those properties.

On 2026-09-29 the expanded 13-seed campaign, including the four new rotation
envelopes, passed 100,000 mutations. The same change passed workspace tests,
Clippy with warnings denied, rustdoc and standalone fuzz-target compilation.

The subsequent Rust 1.98.1 upgrade repeated those checks and adds reproducible
native builds, deterministic archives and the legacy vault fixture; see
[toolchain and release qualification](39-toolchain-and-release-qualification.md).

On 2026-10-02 the shared oracle expanded to 64 seeds by adding 48 frozen protocol
objects. The one-million-input deterministic campaign passed with 299,431 accepted
decoder paths. [Document 41](41-protocol-compatibility.md) describes the corpus,
independent Python checks and exact qualification scope.

The historical-evidence extension adds three seeds, for 67 total. Its repeated
one-million-input campaign passed with 295,800 accepted decoder paths; see
[historical PoTB evidence](42-historical-potb-evidence.md).

Admission intent, request, approval and certificate add four seeds, for 71 total.
The repeated one-million-input campaign passed with 299,954 accepted decoder paths;
see [quorum admission authorization](43-quorum-admission.md).

On 2026-10-03 the explicit PoTB configuration/state/batch/handoff formats added
seven structured seeds, for 78 total. The repeated one-million-input campaign
passed with 292,867 accepted decoder paths. Eight separately frozen PoTB objects
also passed authenticated Rust replay and independent Python framing, namespace,
history and weight checks; [policy profile](44-potb-state-transitions.md).
The old 50 protocol fixtures remained unchanged. These counts are deterministic
mutation results, not coverage-guided fuzz coverage.

On 2026-10-04 the live PoTB network added admission/evidence gossip and stored
PoTB effects, for 81 structured seeds. The one-million-input campaign passed
with 293,326 accepted decoder paths. The original 50 legacy and eight PoTB policy
fixtures remain unchanged; [activation and verification scope](45-live-potb-network.md).
