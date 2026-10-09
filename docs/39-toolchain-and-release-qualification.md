<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 39. Toolchain and release qualification

The native workspace and restricted Rust contract profile pin Rust 1.99.0.
`rust-toolchain.toml` installs Clippy, rustfmt, rust-analyzer and the
`wasm32-unknown-unknown` target. On Windows, `tools/enter-dev.ps1` puts the
rustup proxies ahead of older standalone Rust installations in the current shell.

The 2026-09-29/30 dependency upgrade keeps the canonical wire formats and existing
wallet-v1 format. The failing CI logs used `AeadInPlace` methods removed by
chacha20poly1305 0.11; vaults now use `AeadInOut` with checked fixed-size nonce/tag
conversion. A committed vault produced with Argon2 0.5.3 and
chacha20poly1305 0.10.1 checks backward compatibility. The seed is a public RFC
8032 test vector, not operator material. Source packages have an explicitly new
compiler-profile commitment; [old bundle handling](34-contract-source-packages.md).

All direct Cargo dependencies were checked against the crates.io stable releases;
both workspace and standalone fuzz lock resolutions were refreshed. Upstream
transitive requirements remain authoritative: forcing unrelated major versions
through a dependency's API does not establish compatibility. The 2026-09-30 OSV
query over the workspace lockfile's 132 registry packages was manual and left no
committed artifact. `.github/scripts/audit-dependencies.py` now performs that
lookup reproducibly under an explicit request cap and timeout, covers the
workspace-excluded fuzz lockfile as well, and distinguishes a live query from
verification against its pinned snapshot; CI runs it from
`.github/workflows/security.yml`. Measured counts, policy results and the
per-dependency trust surface are recorded in
[dependency and security review](51-dependency-and-security-review.md). A database
check is not an independent implementation audit.

## Native artifacts

```text
python -B .github/scripts/verify-native-build.py x86_64-pc-windows-msvc --binaries-output target/verified-native
python -B .github/scripts/package-build.py x86_64-pc-windows-msvc --binaries target/verified-native --revision <full-commit-hash>
python -B -m unittest discover -s .github/scripts -p 'test_*.py' -v
```

The verifier resolves absolute Cargo/rustc paths for `rust-toolchain.toml` through
rustup, sets the exact `RUSTC` for child builds and removes ambient compiler
wrappers. A standalone compiler earlier in PATH cannot replace the pinned one.
The verifier builds the complete release workspace twice in separate fresh
directories, disables incremental compilation, remaps workspace/build paths,
strips debug information and enables the MSVC deterministic-link option. It
compares SHA-256 hashes of `cli`, `daemon`, `cargo-contract` and `dns`. An optional
output directory receives binaries only after all comparisons match.
`target/native-reproducibility.json` records compiler identity and binary hashes.
Linux uses the same command with `x86_64-unknown-linux-gnu`.

The archive builder includes those four binaries, documentation and banner,
license, README, lockfile and compiler manifest. Files have a sorted order,
fixed modes, zero ownership and an explicit timestamp (`SOURCE_DATE_EPOCH`,
default zero). The gzip header contains no host filename or current time.
`BUILD.json` records build identity and every payload's SHA-256; `SHA256SUMS`
commits the complete archive. Regression tests change filesystem timestamps and
permissions, check exact equality, inspect all hashes and reject incomplete
builds. The packager reads `target/native-reproducibility.json` (or `--build-report`),
checks the target and all four binary hashes against the exact packaged payloads,
and takes compiler identity from that report. A changed binary or stale/mismatched
report fails before archive publication. These scripts perform no upload or signing.

CI's Linux/Windows build matrix now runs this two-build gate and packages its
verified output. Release-profile tests also invoke all four real Rust-to-WASM
SDK/package checks instead of leaving them permanently ignored.

## Local evidence

On Windows with Rust 1.98.1 the upgrade passed workspace tests in debug and
release, strict Clippy and rustdoc, formatting, all four explicit Rust-to-WASM
tests, standalone fuzz-target compilation, the 100,000-input extension mutation
campaign, the legacy vault fixture and archive reproducibility tests. Two fresh
native builds produced equal hashes for all four executables. Both repositories'
workflow files passed actionlint 1.7.12.

The companion web workspace uses Node 26.10.0, npm 12.1.0, Turbo 2.11.5 and
Next.js 16.3.7. TypeScript 7.0.2 supplies the native CLI; the supported TypeScript
6.0.2 API package remains available to Next.js/MDX/ESLint. Direct dependency
checks report no outdated packages, and npm audit reports no known vulnerabilities.
Content checks, nine RPC tests, type checking, lint, all three production builds
and 28 desktop/mobile browser scenarios passed. Browser tests used a newly
provisioned four-validator TLS devnet plus observer and a real finalized payment.

No hosted CI runs were started. Linux execution and reproducibility on independent
machines remain to be observed; equal builds on one Windows host establish only
the measured scope. [Live rotating consensus](40-live-vrf-network.md) was subsequently
implemented. Active PoTB, governance, physical retention and alternate runtime
qualification retain their own ROADMAP entries.

## 2026-10-02 stable refresh

A new check of the official stable Rust manifest and both package registries found
Rust 1.99.0, `wat` 1.260.0, npm 12.2.0, Turbo 2.11.6, Next.js 16.3.8 and Node types
26.6.4. Those versions are now pinned; Node itself remains 26.10.0. Both Cargo
locks and the web lockfile were refreshed. The 132-package OSV query and npm audit
returned no known vulnerabilities on this date. Both were manual; the Cargo side is
now reproduced by the committed script described above, while the npm audit has no
committed automation.

Rust 1.99 added strict Clippy diagnostics for empty-value assertions. Telemetry
and test assertions now pass those gates. The atomic `try_update` rename remains
unstable under `atomic_try_update`, so saturating counters keep using the stable
`fetch_update` API. Contract builds resolve the pinned compiler once by its absolute
rustup path and reuse it for ABI, SDK and both artifact builds. A regression test
puts a fake rustc first in PATH and supplies an invalid ambient toolchain while
requiring identical executable WASM output.

The refreshed compiler passed the full debug/release workspace suites, strict
Clippy/rustdoc, all four real WASM build tests, standalone fuzz-target compilation
and the 71-seed million-input deterministic campaign. The 50 existing protocol
fixtures remained byte-identical. Web type/lint checks, nine RPC tests and all three
production builds passed on the refreshed dependencies.

Two fresh native Rust 1.99.0 builds with explicit compiler paths produced identical
SHA-256 hashes for all four executables. Archive regression tests also reject a
report naming a different target, compiler, build count or binary payload.

All 28 desktop/mobile browser scenarios also passed against a new four-validator
TLS devnet, an observer and a real finalized payment. The local test build sets
`NEXT_PUBLIC_*_URL` origins before compilation, as required by Next.js; runtime-only
URL overrides do not rewrite prerendered cross-app links.

## 2026-10-08 first observed hosted run

Earlier platform claims in this document rest on local Windows checks. On
2026-10-08 the `CI` workflow ran on GitHub-hosted runners for the first time, so
some of that evidence is now observed rather than configured.

Passed: formatting; strict Clippy on `ubuntu-latest` and `windows-latest`; and the
workspace suite on `ubuntu-latest` in both the debug and release profiles, which is
the first observed Linux suite result. The `windows-latest` debug suite also passed.

Failed, with causes recorded here rather than summarised away. The documentation job
rejected a public doc comment in `crates/crypto/src/blake2s.rs` that linked an item
outside its module scope, under `rustdoc::broken-intra-doc-links`. The fuzz
compile-check and both release-build jobs failed on one shared cause: the
workspace-excluded fuzz package's lockfile was ignored by `.gitignore`, so
`cargo check --locked` could not resolve it and the advisory review's
both-lockfile test raised `missing lockfile`. That lockfile is now committed,
because the advisory scope recorded in
[document 51](51-dependency-and-security-review.md) is only reproducible when it is.

The `windows-latest` release suite failed one test,
`tls_rotating_profile_serves_verifiable_handoffs_and_recovers_all_roles`, where a
restarted late-joining observer reported no retained state at height 2. The same
test passed on the three other matrix legs and passes locally in release. Retention
eviction is excluded, since the window is 64 blocks, and log replay rebuilds the
index. The trigger was not reproduced in that run, so the assertion was left intact
and made diagnostic instead of relaxed.

## Second hosted run, 2026-10-09

The second run narrowed the matrix to two failures, both since reproduced locally
and root-caused. Formatting, strict Clippy on both platforms, documentation, the
fuzz compile-check, both release builds and workflow validation passed, and both
release test legs passed with 1 188 and 1 189 tests. Only the two debug legs failed,
one test each.

`ubuntu-latest` debug failed
`tls_potb_profile_serves_verifiable_handoffs_and_recovers_all_roles` on the same
assertion as the previous run's Windows failure, which identified the cause the
earlier single sighting could not. The payment the test waits for lands in block
one, so `await_payment` returns as soon as a restarted late-joining observer has
block one, while that observer may still sit below height 2. The historical query
at height 2 then legitimately found nothing. Two separate defects combined: the
test used a finalized payment as the precondition for a historical query, which it
is not, and the RPC collapsed "this height is not finalized here yet" and "this
finalized height left the retained index" into the same null result, so no caller
could tell catch-up from absent history. Both are fixed. `state_proof_at` now
reports a height above the served head as `Unavailable` and reserves null for an
evicted finalized height, and both profile tests wait on the answering node's own
finalized head. A regression test drives an observer that cannot leave its genesis
anchor and asserts the distinction directly.

`windows-latest` debug failed
`malformed_forked_incomplete_or_wrong_height_handoffs_never_advance_authority` with
`WSAEWOULDBLOCK` while reading a request length. The test peer deliberately makes
its listener non-blocking so an accept deadline can be enforced, and on Windows an
accepted socket inherits that mode while `set_read_timeout` does not clear it. The
hazard was already known here: `DeadlineSocket::new` carries the same fix and
[document 20](20-authenticated-transport.md) documents it. The sweep for the pattern
found four affected sites and one of them was production code, not a test: the
daemon metrics listener is non-blocking and its accepted stream was read a byte at
a time, so on Windows a Prometheus request whose next byte had not arrived was
dropped, silently, because the caller discards the error. Its own unit test missed
this by binding a blocking listener. All four now clear the mode explicitly.

Neither failure is platform-specific in cause: the state-proof race was observed on
Windows release first and Linux debug second, and the socket-mode defect is dormant
on Linux only because `accept` there does not inherit the flag.

Two hosted runs with failures are not cross-platform qualification. The causes are
fixed, but a clean run across all four legs has not been observed yet, so that
roadmap item stays open. Linux reproducibility is still unobserved because the
release-build jobs did not reach their archive step in the first run, and
independent-machine reproducibility needs a second machine rather than a
second run on the same hosted image.
