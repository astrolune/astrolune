<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 51. Dependency and security review

This document records a measured review of the third-party dependency surface and
replaces the unreproducible manual advisory query previously cited by
[toolchain and release qualification](39-toolchain-and-release-qualification.md).
The committed tooling is `.github/scripts/audit-dependencies.py` for advisories
and `.github/scripts/check-license-coverage.py` for licence and duplicate
policy; their regression tests are `.github/scripts/test_audit_dependencies.py`
and `.github/scripts/test_check_license_coverage.py`, and the pinned data is
`.github/scripts/advisory-snapshot.json` and
`.github/scripts/deny-coverage-baseline.json`. Policy lives in `deny.toml` and
`.github/workflows/security.yml`.

All numbers below are measured, not asserted. Every measurement in this document
comes from one host: Windows 11 on `x86_64-pc-windows-msvc`, `cargo 1.99.0
(5f94df478 2026-08-27)`, `rustc 1.99.0 (b940084d7 2026-09-28)`, `cargo-deny
0.18.6` and Python 3.11.9, on 2026-10-07 and 2026-10-08 as dated per claim.
Nothing here establishes behaviour on Linux, on hosted CI runners, or on any
independent machine, and nothing here is an implementation audit of any
dependency.

## Bounded advisory lookup

`audit-dependencies.py` parses each lockfile with `tomllib`, selects only packages
whose `source` begins `registry+`, and queries the OSV `querybatch` endpoint for
the `crates.io` ecosystem. Path and workspace members are excluded because they
have no registry advisories. The lookup is bounded by three explicit mechanisms:

- `--batch-size` (default 64) fixes how many packages one request carries;
- `--max-requests` (default 16) caps total requests and refuses to start when the
  package count would exceed it;
- `--timeout` (default 30 seconds) bounds each individual request.

Every failure path raises instead of degrading. A transport error, a timeout, a
non-200 status, a result count that does not match the batch, or a paged result
aborts the run with `no result is established`; an exceeded request cap aborts
before any query is sent. The script additionally issues one canary query for
`time 0.1.44`, a package known to carry advisories, and aborts with `not
trustworthy` when that query returns nothing. An unreachable, intercepted or
empty-responding database therefore cannot produce a clean report.

Offline operation is explicit rather than implied. `--offline` verifies the
committed snapshot instead of querying, and refuses to run when the snapshot is
absent or when its `packages_digest` does not equal the digest of the current
locked package set. The report always states which happened: `determination` is
either `queried live` or `verified against pinned snapshot`, and `database` is
either `OSV` or `pinned OSV snapshot`. A snapshot can only be written from a live
query and requires an explicit `--queried-on` date.

The report at `target/dependency-advisories.json` is written with sorted keys and
a fixed newline, contains no host paths and no generated timestamps, and names
every bound it ran under. Two offline runs over an unchanged lockfile produce
identical bytes; a regression test asserts this.

This section establishes that a database query is reproducible and that its
failure modes are loud. It does not establish that OSV is complete, that the
`crates.io` ecosystem mapping covers every advisory class, or that a package
absent from OSV is sound. A snapshot verification establishes only what was true
on its recorded `queried_on` date, not what is true now.

## Measured lockfile scope

On 2026-10-07 the two lockfiles measure as follows. `Cargo.lock` carries 132
registry packages, confirming the count claimed in
[toolchain and release qualification](39-toolchain-and-release-qualification.md).

| Lockfile | Total | Registry | Local | Package digest |
|---|---|---|---|---|
| `Cargo.lock` | 158 | 132 | 26 | `8c0c6b174952ce12da14643df6695cdfc0469a6a91a02d929171c465ac9f24d3` |
| `crates/codec/fuzz/Cargo.lock` | 114 | 96 | 18 | `42eab7826e6ff25e497fcfde801b7c3b739177b1ea00ca32390a4e6811a16022` |
| union | — | 135 | — | `daa9e204c51c02b0b77adfaef20f9fe0a1c90433e2da03a371da3f9ee7fb6974` |

The fuzz lockfile is a workspace-excluded package and is explicitly in scope. It
contributes exactly three packages the workspace lockfile does not contain:
`arbitrary 1.4.2`, `jobserver 0.1.35` and `libfuzzer-sys 0.4.13`. Its remaining 93
packages are already present at identical versions, so the union is 135 unique
name and version pairs rather than 228.

The live run on 2026-10-07 used 4 requests against a cap of 16, being one canary
query and three batches of 64, and returned no advisories for any of the 135
packages. The result is pinned in `advisory-snapshot.json` with `queried_on`
`2026-10-07`.

This section establishes the exact set of packages checked and that both
lockfiles are covered. It does not establish that the resolved graph built for
any particular target and feature combination equals the lockfile; lockfile
membership is the scope, and it is a superset of what any single build compiles.

## Policy state and the gap it does not cover

`cargo deny 0.18.6` reports `advisories ok, bans ok, licenses ok, sources ok`
and exits zero on 2026-10-07 and again on 2026-10-08 after the changes below.
`cargo audit 0.22.2` loads 1293 RustSec advisories and reports no findings,
scanning 158 crate dependencies in `Cargo.lock` and 114 in
`crates/codec/fuzz/Cargo.lock`; both exit zero.

A measured coverage gap qualifies the `cargo deny` result, and on 2026-10-08 its
cause was determined. The gap reproduces exactly: probing with an empty `allow`
list produces 121 `error[rejected]` diagnostics over 121 distinct crates,
`cargo deny check -s` independently reports `licenses ok: 0 errors, 2 warnings,
121 notes`, and `cargo deny list --format tsv` emits a header plus 121 crate
rows, while `Cargo.lock` holds 158 `[[package]]` entries and `cargo metadata
--all-features --locked` resolves all 158. Licence and ban policy therefore
evaluated 121 of 158 packages: all 26 workspace members and 95 of the 132
registry packages.

The cause is that cargo-deny resolves what cargo would compile, not what the
lockfile records, and the 37 omitted packages divide three ways with nothing left
over. `cargo tree --locked --workspace --all-features --target all -e
normal,build,dev` resolves 128 packages and `-e normal,build` resolves 122.

- **30 packages that no target and feature combination compiles.** They are the
  transitive closure of twelve packages whose every non-dev edge is an optional
  dependency of a third-party crate: `bit-vec 0.9.1`, `foldhash 0.1.5`,
  `indexmap 2.14.2`, `num-bigint 0.4.8`, `password-hash 0.6.1`, `phc 0.6.1`,
  `serde 1.0.229`, `string-interner 0.19.0`, `time-macros 0.2.32`,
  `toml_writer 1.1.2+spec-1.1.0`, `wasmparser 0.261.0` and `x509-parser 0.18.1`.
  `all-features` activates the features of workspace members only and never a
  third-party crate's own optional features, so `rcgen` never enables
  `x509-parser` and with it `der-parser`, `asn1-rs`, `oid-registry`,
  `rusticata-macros`, `nom 7.1.3`, `minimal-lexical`, `data-encoding`,
  `lazy_static`, `displaydoc`, `synstructure` and the `num-*` chain.
  `Cargo.lock` lists them because a lockfile records the feature-independent
  union of the resolve.
- **1 package gated behind a cfg that is false everywhere.** `serde_derive
  1.0.229` is reachable only through `serde_core`'s `[target.'cfg(any())']`
  edge. `cargo tree --target all` keeps it because that flag disables cfg
  evaluation; cargo-deny evaluates the cfg and correctly drops it. It is the
  only difference between the cargo-deny graph and the 122 packages
  `cargo tree -e normal,build` resolves.
- **6 packages reachable only through a workspace member's dev-dependency.**
  `wat 1.261.0`, `wast 261.0.0`, `wasm-encoder 0.261.0`, `leb128fmt 0.1.0`,
  `unicode-width 0.2.2` and `memchr 2.8.3`. `wat` is declared under
  `[dev-dependencies]` by seven members. These are compiled by `cargo test` and
  are the only genuinely unexamined code in the 37.

cargo-deny 0.18.6 cannot be configured to reach that last group. A throwaway
four-package workspace, one member with one normal dependency, one optional
dependency and `memchr` as a dev-dependency, evaluates the member, the normal
dependency and the optional dependency, proving `all-features` works, and never
evaluates `memchr`, under `[graph] exclude-dev` unset, `false` and `true`, under
the `--exclude-dev` flag, under `--workspace`, and under resolver 1, 2 and 3.
The `--exclude-dev` help text states it "excludes all dev-dependencies, not just
ones for non-workspace crates", so workspace dev-dependencies ought to be in the
graph by default; measurably they are not. The alternative explanations were
tested and rejected. Explicit `targets` narrows rather than widens coverage:
`-t x86_64-pc-windows-msvc` evaluates 100 crates, `-t
x86_64-unknown-linux-gnu` 101 and both triples together 101, so the empty
`targets = []` is the widest setting available and is kept. `--exclude-dev`
leaves the count at 121 and `--exclude-unpublished` lowers it to 110. Feeding
cargo-deny a self-generated `cargo metadata --all-features --locked` through
`--metadata-path` leaves it at 121 with either default or all features, so the
pruning is in cargo-deny's graph builder and not in how it invokes cargo.

Licence coverage is now 158 of 158 by committed tooling, with the cargo-deny
gap bounded exactly rather than merely disclosed.
`.github/scripts/check-license-coverage.py` parses the SPDX expression of every
package `cargo metadata --all-features --locked` resolves, including the legacy
`MIT/Apache-2.0` slash form that eleven packages still use, and evaluates it
against the `licenses.allow` list in `deny.toml`. On 2026-10-08 it reports
`locked_packages` 158, `cargo_deny_graph_packages` 121, `uncovered_packages` 37,
no rejected licence and no failure. That it reaches past the graph is measured,
not asserted: removing `MIT` from the allow list makes it reject 33 of the 158,
of which `data-encoding 2.11.1`, `memchr 2.8.3`, `nom 7.1.3` and `synstructure
0.13.2` are packages cargo-deny never sees. The bound lives in
`.github/scripts/deny-coverage-baseline.json`, which names all 37 with the
licence its manifest declares and the reason measured for each. The checker
fails if the uncovered set gains a member, loses one, or if a recorded licence
stops matching the manifest, and it refuses to run at all when the baseline is
absent. Its regression tests are
`.github/scripts/test_check_license_coverage.py`, which also assert, with no
toolchain present, that the committed allow list satisfies every licence the
baseline records.

`cargo deny check bans` reports two duplicated crates: `getrandom` at `0.2.17`
and `0.4.3`, and `syn` at `2.0.119` and `3.0.6`. `getrandom 0.2.17` is a
transitive requirement of `ring 0.17.14` while first-party code uses `0.4.3`;
`syn 2.0.119` is required by the `curve25519-dalek-derive` and `zeroize_derive`
proc-macros while `thiserror-impl 2.0.21` uses `3.0.6`. Neither is fixable from
this repository. Across all 158 packages there are four duplicates rather than
two: `hashbrown` at `0.15.5` and `0.17.1` and `wasmparser` at `0.228.0` and
`0.261.0` also appear, both inside the 37. The coverage baseline records all
four and the checker fails on a fifth, which is the ban half of the bound.
Adding them to `bans.skip` instead would only raise `unmatched skip` warnings,
because cargo-deny cannot see the versions they refer to.

Four policy changes were made on 2026-10-07, each verified to keep `cargo deny
check` green:

- `bans.multiple-versions` moves from `warn` to `deny` with explicit `skip`
  entries carrying a `reason` for `getrandom@0.2.17` and `syn@2.0.119`, so the two
  upstream-forced duplicates are documented and any new duplicate fails CI;
- `advisories.unmaintained` is set explicitly to `all` and `advisories.ignore` to
  an empty list, pinning the broadest reporting rather than inheriting a default
  that may narrow;
- `MPL-2.0` is removed from `licenses.allow`, being the only non-permissive entry
  and reported by `cargo deny` as never encountered, so file-level copyleft is no
  longer pre-granted;
- `cargo audit --file crates/codec/fuzz/Cargo.lock` is added to
  `.github/workflows/security.yml`, which previously audited only the workspace
  lockfile.

The 2026-10-08 change adds no policy rule. `deny.toml` gains only comments
recording the measured graph size, why `targets` stays empty and where the bound
lives, so the file's behaviour is unchanged and `cargo deny check` still reports
`licenses ok: 0 errors, 2 warnings, 121 notes`.

Adding `advisories.unsound` or `advisories.notice` is not possible. Configuration
version 2 removed both keys, and `cargo deny` rejects them with
`error[deprecated]: this key has been removed`. Both classes are unconditional
errors that cannot be configured. The two remaining `license-not-encountered`
warnings, `BSD-2-Clause` and `Zlib`, are not equivalent, which corrects an
earlier claim here that both were unused. Measured over all 158 packages,
`BSD-2-Clause` is offered by nothing, while `Zlib` is the sole licence of
`foldhash 0.1.5`, one of the 37; cargo-deny calls it unencountered only because
`foldhash` is outside its graph, and removing `Zlib` from `licenses.allow` would
make the full-lockfile check reject that package.

The `registry-advisories` job in `.github/workflows/security.yml` runs the live
query, the offline snapshot verification and the regression tests, and uploads
the report. A `license-coverage` job added on 2026-10-08 installs `cargo-deny
0.18.6` pinned, records `cargo deny list --format tsv` as `target/deny-graph.tsv`,
runs the coverage checker against it and uploads both the graph listing and
`target/dependency-license-coverage.json`. Both use `actions/checkout@v7.0.1`,
`actions/setup-python@v7` and `actions/upload-artifact@v7` under the file's
existing `permissions: contents: read` and `concurrency` block.

This section establishes a green policy run, the cause of the 121-of-158 gap and
an exact bound on it. It does not establish that cargo-deny will ever cover the
six compiled dev-dependencies; that remains an upstream limitation, and the
committed checker is the compensating control rather than a fix to the tool. The
licence read is the `license` expression each `Cargo.toml` declares as
`cargo metadata` reports it. No licence text was compared against its SPDX
identifier, cargo-deny's `confidence-threshold` text scoring is not
reimplemented, and a package declaring no expression at all would be refused
rather than scored; none of the 158 does. The three reasons recorded per package
are measurements from this host on 2026-10-08, derived with `cargo tree` and the
resolve graph by hand; the committed checker enforces the uncovered set, its
licences and the duplicate set, not the reasons, and nothing prevents a future
feature change from compiling one of the 31 packages that no build reaches
today, which is what the growing-set guard exists to catch. Because
`audit-dependencies.py` and `cargo audit` both read lockfiles directly, advisory
coverage of all 135 packages was never affected by this gap and is unchanged. No
committed automation covers the companion npm workspace, whose `npm audit` result
in [toolchain and release qualification](39-toolchain-and-release-qualification.md)
remains a manual claim. `actionlint 1.7.12` could not be run for either the
2026-10-07 or the 2026-10-08 workflow edits: Go is unavailable on this host and
the GitHub release download timed out, so `security.yml` and `ci.yml` were
validated only by YAML parse and structural comparison against the existing
jobs.

## Cryptographic and parsing surface

The workspace declares no `[workspace.dependencies]` table; third-party versions
are declared per crate. The table below gives the declared pin, the resolved
lockfile version and what each dependency is trusted for. Entries marked caret
are not exact pins.

| Dependency | Declared pin | Resolved | Trusted for |
|---|---|---|---|
| `ed25519-dalek` | `=3.0.0` | `3.0.0` | strict Ed25519 verification and signing in `crates/crypto/src/ed25519_provider.rs` |
| `curve25519-dalek` | transitive | `5.0.0` | Edwards group arithmetic under Ed25519 and the VRF |
| `subtle` | transitive | `2.6.1` | constant-time comparison inside the dalek crates |
| `blake2` | `=0.11.0` | `0.11.0` | BLAKE2s-256 for every protocol commitment and hash |
| `vrf-rfc9381` | `=0.0.7` | `0.0.7` | RFC 9381 ECVRF proof generation and verification for committee selection |
| `argon2` | `=0.6.0` | `0.6.0` | wallet vault password derivation in `crates/keystore/src/vault.rs` |
| `chacha20poly1305` | `=0.11.0` | `0.11.0` | wallet vault authenticated encryption |
| `getrandom` | `=0.4.3` | `0.4.3` and `0.2.17` | operating-system entropy for vault keys and nonces |
| `zeroize` | `=1.9.0` and caret `1.9.0` | `1.9.0` | scrubbing secret key and password memory |
| `rustls` | caret `0.23.45` | `0.23.45` | mutual TLS 1.3 transport, explicitly on the `ring` provider |
| `ring` | transitive | `0.17.14` | TLS primitives selected by `rustls::crypto::ring::default_provider()` |
| `rustls-webpki` | transitive | `0.103.15` | peer certificate path and name validation |
| `rcgen` | caret `0.14.10` | `0.14.10` | transport certificate generation behind the `provisioning` feature |
| `x509-parser` | transitive | `0.18.1` | certificate parsing reached through `rcgen` |
| `wasmi` | `=2.0.0` | `2.0.0` | deterministic WebAssembly execution sandbox |
| `wasmparser` | transitive | `0.228.0` and `0.261.0` | WebAssembly module validation inside the sandbox and the test assembler |
| `wat` | `=1.261.0` | `1.261.0` | test fixture assembly only; declared under `[dev-dependencies]` in every crate |
| `toml` | `=1.1.6` | `1.1.6+spec-1.1.0` | configuration and contract manifest parsing |

`vrf-rfc9381 =0.0.7` is the clearest dependency risk in this surface. A `0.0.x`
version carries no stability commitment, implies a small or single maintainer, and
sits directly on the consensus path: committee selection depends on its proof
verification. It is exactly pinned and reported clean by both advisory databases,
but neither fact substitutes for review of its implementation.

Pin consistency is incomplete. `zeroize` is declared with a caret at five sites;
this change converts `crates/keystore/Cargo.toml` and `apps/cli/Cargo.toml` to
`=1.9.0` and leaves `apps/daemon/Cargo.toml`, `crates/crypto/Cargo.toml` and
`crates/p2p/Cargo.toml` caret-declared, those files being outside this change.
`crates/p2p/Cargo.toml` also declares `rustls = "0.23.45"`, `rcgen = "0.14.10"`
and `time = "0.3.55"` with carets, and `crates/codec/fuzz/Cargo.toml` declares
`cc = "1"` and `libfuzzer-sys = "0.4.13"` with carets, `cc = "1"` being the
loosest declaration in either lockfile. `cargo check --locked --workspace
--all-features` passed immediately after the two pin changes, and `cargo check
--locked -p keystore --all-features` passes; `cargo tree` resolves `zeroize
v1.9.0` for both `keystore` and `cli`, and offline snapshot verification still
matches the recorded `Cargo.lock` digest, so the exact pins changed no resolution.
A later workspace-wide run on the same day failed with six unrelated name
resolution errors in `crates/consensus/src/governance.rs`, a file untouched by
this change and under concurrent edit; that failure is not attributable to the
pins and was not resolved here.

Licence data from `cargo deny list` counts the licences each crate offers rather
than the one selected: `MIT` 115, `Apache-2.0` 87, `ISC` 4, `BSD-3-Clause` 3,
`Apache-2.0 WITH LLVM-exception` 2, and one each of `BSD-1-Clause`,
`LGPL-2.1-or-later` and `Unicode-3.0`. The `LGPL-2.1-or-later` offer belongs to
`r-efi 6.0.0` and the `BSD-1-Clause` offer to `fiat-crypto 0.3.0`; both also offer
allowed permissive terms, which is why `cargo deny check licenses` passes without
either appearing in `licenses.allow`.

This section establishes which versions are in use and what each is relied upon
for. It establishes nothing about correctness. No cryptographic dependency here
has been independently reviewed by or for this project, no constant-time or
side-channel property has been measured, and no provider substitution or
supply-chain provenance check exists: `deny.toml` restricts sources to the
`crates.io` registry index but nothing verifies published artefacts against
upstream source repositories. External cryptographic review and independent
provider review remain open, as does the alternate-provider work tracked in
[cryptographic foundations](09-cryptographic-foundations.md).
