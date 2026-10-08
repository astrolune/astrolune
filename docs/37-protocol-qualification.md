<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

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

A second shared oracle in `tests/integration/tests/support/contracts.rs` reaches the
WebAssembly contract host directly instead of incidentally, through the extension
oracle's magic-byte arm. Every candidate is first offered under a foreign runtime
identity, which must never validate. An accepted module must re-expose the exact
submitted bytes and commit to the recomputable `wasm_code_hash` of those bytes, then
execute identically twice on the shared engine and once more on a freshly built
engine. `WasmCall` is `Copy` and `WasmOutput` is `Eq`, so the identical finalized
context is replayed rather than rebuilt. A forged code commitment, code substituted
under a retained commitment and a substituted runtime version must each be rejected
rather than trusted. The call input, the compute, memory, I/O and bandwidth grants,
the contract-local state and the access declaration are all derived from the
candidate's own commitment bytes, so each mutated input explores a different point
inside the accepted bounds while staying reproducible; the out-of-range counterpart
of every one of those bounds is then asserted to reject before the module runs.

The structured contract corpus in
`tests/integration/tests/support/contract_modules.rs` holds 9 accepted modules and
3 malformed regressions, 12 in total: a minimal returning module, an unbounded loop
retired by the fuel grant alone, input length/copy/output, a declared state write and
read-back, a declared state deletion, two 32-byte-topic events, the authenticated
caller and finalized height, a nonzero status that stages no writes or events, and
memory growth retired by the store limiter. The three regressions place an
instruction after a function's `end`; deriving them asserts the exact code-section
tail 10, 6, 1, 4, 0, 65, 0, 11 of the minimal module, so the derivation cannot
silently stop producing them. The same shared derivation and assertion now produce
the extension corpus's three malformed WASM regressions, which are unchanged.

```text
cargo test -p integration --test contracts
cargo test --release -p integration --test contracts extended_contract_mutations -- --ignored
cargo test --release -p integration --test contracts million_contract_mutations -- --ignored
```

The ordinary contract test performs 3,000 deterministic mutations,
`extended_contract_mutations` performs 100,000 and `million_contract_mutations`
performs 1,000,000. All three are deterministic mutation campaigns over the same
fixed PRNG seed; none of them is a coverage-guided result.

All standalone libFuzzer targets compile locally. Sanitizer-enabled campaigns
need a suitable nightly/cargo-fuzz installation. From `crates/codec`, the
extension target is selected with
`cargo +nightly fuzz run decode_extensions` and the contract target with
`cargo +nightly fuzz run execute_contract`. Set campaign time, maximum input
length and RSS/timeout bounds for the selected environment; retain and minimize
any crashing corpus. Existing transaction, genesis, consensus, network and state
fuzz targets remain separate entry points. The fuzz package is excluded from the
workspace and carries its own lockfile, so CI compile-checks it separately with
`cargo check --locked --manifest-path crates/codec/fuzz/Cargo.toml --all-targets`;
without that step the targets could rot unnoticed.

Windows has a separate coverage-only runner:

```powershell
./tools/fuzz-windows.ps1 -Seconds 300 -Seed 20261005
./tools/fuzz-windows.ps1 -Seconds 300 -Seed 20261005 -Target decode_extensions,execute_contract
```

It builds offline with the pinned stable compiler and writes a new directory under
`target` with the compiler/flag/seed record and a final report. `-Target` selects
which instrumented binaries to build and run and defaults to `decode_extensions`,
so earlier invocations behave exactly as before. Each selected target gets its own
subdirectory holding its own exported corpus, failure artifacts, seed export log,
fuzzer log and binary hash: `decode_extensions` consumes the same 99 structured
extension seeds plus three malformed WASM regressions (102 total), and
`execute_contract` consumes the 12 structured contract modules. Every target must
separately pass matching counter/PC counts, new coverage and normal completion; a
compilation, panic or coverage mismatch on any one of them fails qualification.
Input length, per-input time and process memory are bounded. Rust panics preserve
their exact input before aborting, including without ASan's death callback.

This profile uses LLVM edge counters and comparison feedback with optimization
disabled: optimized Rust 1.99.0 MSVC instrumentation produced mismatched PC tables
locally. It does not enable AddressSanitizer or instrument the Rust standard
library. The tiny COFF section-boundary C file is isolated to the opt-in fuzz
package; production crates remain safe Rust. LLVM describes the instrumentation
in [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html).

On 2026-10-05 the maintainer reported that the uploaded revision passed all GitHub
checks. No remote operation or independent inspection of those checks was
performed in this work session; subsequent local edits need their own CI run.

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

On 2026-10-05 the governance extension adds 18 frozen objects and raises the
shared corpus to 99 seeds. Its one-million-input deterministic campaign passed
with 279,302 accepted decoder paths. This remains a mutation campaign, not a
coverage-guided result; [governance qualification](48-parameter-governance.md).

On 2026-10-07 a dedicated contract fuzz surface was added: the oracle in
`tests/integration/tests/support/contracts.rs`, the `execute_contract` libFuzzer
target, the 12-module structured contract corpus and the `contract_mutation_smoke`,
`extended_contract_mutations` and `million_contract_mutations` campaigns. On
Windows with Rust 1.99.0 the smoke campaign reported 99 accepted contract paths
over 3,000 mutations, the extended campaign 4,071 over 100,000 and the
one-million-input campaign 40,488 over 1,000,000; no mutation produced a panic.
The deliberately unchanged 99-seed extension corpus reproduced 28,069 accepted
decoder paths over 100,000 mutations and exactly 279,302 over 1,000,000, the same
figure recorded on 2026-10-05.

Coverage feedback was then observed locally for both targets with the runner's
instrumentation flags, 90-second budgets and seed 20261007. `decode_extensions`
loaded 99,409 inline 8-bit counters and 99,409 PCs, executed 917,335 inputs in
91 seconds, added 9,717 new units and grew its corpus from 102 to 2,851 files.
`execute_contract` loaded 90,299 inline 8-bit counters and 90,299 PCs, executed
2,336,611 inputs in 91 seconds, added 12,130 new units and grew its corpus from
12 to 3,198 files. Neither produced a crash artifact, and both satisfied the
runner's gate of equal counter/PC counts, new coverage and normal completion.

Those two libFuzzer stages were invoked directly with the runner's exact flag set,
because `tools/fuzz-windows.ps1` itself could not be driven to completion in that
session: Windows PowerShell 5.1 with `$ErrorActionPreference = 'Stop'` turns
cargo's native standard error under `*>` redirection into a terminating
NativeCommandError, the same failure reproduces with the runner's earlier
single-target command, and PowerShell 7 is not installed on that machine. The
multi-target parameterisation, the per-target gate and the report fields were
therefore reviewed and syntax-checked but not executed end to end locally.

These are local checks on one Windows machine. Ninety seconds of coverage feedback
is not a long campaign; AddressSanitizer is still not enabled, the Rust standard
library is still uninstrumented, and Linux and macOS coverage-guided qualification
of these targets remains separate ROADMAP work. The contract oracle gates
candidates at 64 KiB to keep each round bounded, so modules between that bound and
the runtime's 1 MiB `MAX_MODULE_SIZE` are never validated or executed by these
campaigns. CI now compile-checks the workspace-excluded fuzz package, which
prevents the targets rotting silently but runs no campaign. `actionlint` was
unavailable locally, so the added CI job was only checked by parsing the workflow
and matching the existing job style.
