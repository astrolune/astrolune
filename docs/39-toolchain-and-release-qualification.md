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

Two hosted runs with failures are not cross-platform qualification. This run does
establish Linux reproducibility: the `ubuntu-latest` release-build job passed in
full, and that job runs the two-build byte comparison, the smoke checks, the
archive and the qualification report in one sequence, so a pass means the two
fresh Linux builds produced equal hashes for all four executables. An earlier
statement here that Linux reproducibility remained unobserved described the first
run, where the release-build jobs failed before their archive step, and was left
standing after the second run contradicted it. What the second run does not
establish is a clean four-leg suite, which the two debug failures denied, or
reproducibility across two machines, which one run cannot supply at all.

## Clean four-leg run

The repository owner reports that the `CI` workflow is now green on every job on
GitHub-hosted runners, including all four `tests` legs, after the two root-caused
debug failures above were fixed. The evidence that makes that an observation
rather than a report is the run's own artifacts, and the exact figures are
recorded here as soon as they are supplied.

**To be supplied, and invented by nothing in this repository**: the GitHub Actions
run identifier `<run-id>`, its UTC date `<date>`, and the per-leg counts the four
`suite-<os>-<profile>` artifacts of that run record. For any run that includes the
comparison job described below, all of those figures already sit in one
`astrolune.suite-qualification/1` verdict in that run's `suite-qualification`
artifact — the four legs' `passed`, `failed`, `ignored`, `measured`,
`filtered_out` and `suites`, their shared `rustc` identity, the `dev` and
`release` count drift, and the advisory platform and profile differences — so the
figures are read from one machine-written document rather than retyped from four
job logs. A run that predates that job has the four leg artifacts but no verdict,
and its figures must be read from them directly.

Until `<run-id>` and `<date>` replace those placeholders, this section records a
report and not an observation, and the cross-platform suite qualification roadmap
item stays open on that basis alone. A clean four-leg run, once recorded, still
establishes only that the pinned toolchain's workspace suite passes on two
GitHub-hosted runner images in two profiles on one revision. It is not an
independent audit, not a result on any platform outside that matrix, not a
statement about any revision but that one, and not evidence about hardware,
timing or load that a shared hosted runner cannot control.

## Four-leg suite comparison

`.github/scripts/suite-report.py` records each leg, and
`.github/scripts/compare-suites.py` decides whether the four together qualify the
revision. The CI job `Four-leg suite qualification` downloads every `suite-*`
artifact of the run and invokes it, and `CI required checks` requires that job,
so the verdict is a branch gate rather than a figure a reader has to total by
hand.

```text
python -B .github/scripts/compare-suites.py --artifact-root target/suite-legs --output target/suite-legs/SUITE-QUALIFICATION.json
python -B .github/scripts/compare-suites.py suite-ubuntu-latest-dev/SUITE.json suite-ubuntu-latest-release/SUITE.json suite-windows-latest-dev/SUITE.json suite-windows-latest-release/SUITE.json
```

The expected leg set is the four pairs of `ubuntu-latest`/`windows-latest` and
`dev`/`release`, written into the script rather than read from the files it is
given, because a set derived from the input can never notice that one of its
members never arrived. A comparison that cannot name every expected leg exactly
once is an error and emits no verdict at all: an absent leg, a leg supplied
twice, and a leg the matrix never declares are each refused by name. Every leg
must additionally carry the `rustc -Vv` host triple its own platform implies,
so a result dropped into the wrong artifact directory cannot be counted as the
leg its directory name claims.

A suite result carries no digest over its own fields, so the comparer re-derives
what it can: a leg whose `outcome` does not follow from its own `failed` count
and `exit_status`, or that counts failures it does not name, has been edited and
is refused rather than counted. Qualification then requires every leg's
`outcome` to be `ok`, its `exit_status` to be zero, its `failed` count to be
zero and its `failed_tests` to be empty, and requires all four legs to report
one `rustc` version, since all four install the same pinned toolchain and a
second compiler identity means one leg qualified something else.

Cross-leg count differences are split by whether the matrix explains them. The
two legs of one profile run the same commands over the same workspace, so their
`passed` and `suites` counts may differ only by platform-gated tests; the bound
is 5% of the larger leg, and a larger gap, or a leg reporting zero, is a
refusal. Differences the matrix does cause are advisory and reported rather than
refused: `host` differs by platform by construction, and the release legs run a
fifth `cargo test` invocation that filters `cargo-contract` down to its four
ignored tests, so `ignored`, `measured` and `filtered_out` legitimately move with
the profile. This mirrors the `host` and `rustc` advisory split in
`compare-qualification.py`.

The verdict is `astrolune.suite-qualification/1`, written with sorted keys and an
LF terminator, and it records the per-leg counts, the totals, the drift each
profile allowed and observed, the advisory differences, and every refusal in
sorted order rather than only the first. It establishes nothing about a revision:
a suite result carries no commit hash, so the verdict binds four legs of one run,
not four legs of one revision, and the run itself is what names the revision.
It is not a coverage measurement, not a timing measurement — the leg records
deliberately exclude timings so two runs of one revision on one platform stay
byte-identical — and not evidence that the tests are adequate.

## Independent-run reproducibility comparison

`.github/scripts/compare-qualification.py` was committed and unit-tested but
reachable from no workflow, so the `qualification-<target>` artifact's 90-day
retention held evidence nothing ever read. The CI job
`Independent-run reproducibility (<target>)` now closes that: it downloads this
run's `QUALIFICATION.json`, asks the Actions API for the most recent other
successful `CI` run of the same `head_sha`, downloads that run's retained report
for the same target, and compares the two. `CI required checks` requires the job,
so a disagreement blocks rather than sits in an artifact.

What the comparator requires is that the two reports name one target, carry
digests their own fields reproduce, agree on every field in `COMPARABLE`, and
come from distinct `machine` identities. `ci.yml` sets `ASTROLUNE_MACHINE` to
`${{ runner.name }}#${{ github.run_id }}.${{ github.run_attempt }}`, and the run
identifier differs between any two runs, so two runs of one revision satisfy the
distinctness requirement by construction. That is worth stating plainly rather
than presenting as a stronger result than it is. On GitHub-hosted runners each
job receives a freshly provisioned ephemeral virtual machine, so two runs are in
practice two machines; `runner.name` is a pool label such as `GitHub Actions 2`
and is not a hardware identity, so the check cannot tell a second machine from a
second run on the same one. Two hosted runners of one image are therefore two
machines in exactly the sense the comparator checks: stronger than one run,
because the build ran twice on separately provisioned hosts with independently
populated caches, and weaker than two independently administered hosts, because
both are the same image, the same operating-system patch level, the same
filesystem layout and the same administrator. Byte identity across two
differently administered machines, across two base images, or across any host
outside GitHub's hosted pool is **not** established, and the
`independent_builds` count inside one report remains two builds on one machine.

The comparison is opportunistic by design. A revision whose CI has run once has
no second report, and a revision whose earlier run is older than the 90-day
retention has no retained artifact; the job reports either case in its log and
exits zero, because evidence that is unavailable is not evidence of agreement.
Pull-request runs are excluded from the candidates, and the two reports' own
`revision` fields are compared before the comparator is invoked, because on a
pull-request run `GITHUB_SHA` is a merge commit that moves with the base branch:
two correct builds of one head commit under two different merge commits would
otherwise be reported as a reproducibility failure. A reader therefore cannot
infer from a green job that two machines were compared, only that no two
available reports disagreed. The job performs no signing, holds no key, and
publishes nothing.
