<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Contributing to AstroLune

AstroLune is a Rust blockchain node. Small, reviewable changes with explicit invariants are preferred over broad implementation claims.

## Setup

1. Install [rustup](https://rustup.rs/).
2. Clone the repository and enter its root. The pinned toolchain in `rust-toolchain.toml` installs Rust, Clippy, and rustfmt.
3. Install a C compiler for the `ring` TLS backend (MSVC C++ Build Tools on Windows with the MSVC Rust target, or GCC/Clang with the GNU target). The Rust distribution's bundled GNU linker alone is insufficient for compiling C dependencies.
4. Run the baseline checks:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Before changing code

- Read [`ARCHITECTURE.md`](ARCHITECTURE.md) and the relevant file under [`docs/`](docs/README.md).
- Distinguish protocol rules from local policy and optimization.
- State whether serialization, consensus, state, resource accounting, wallet authorization, or network compatibility changes.
- Search for existing shared types and traits before adding another abstraction.

## Code standards

- Use Rust 2024 and follow the surrounding naming and comment density.
- Keep modules focused and dependency direction narrow.
- Use explicit bounded inputs, checked integer arithmetic, and typed errors.
- Do not introduce floating-point values into protocol-adjacent interfaces.
- Avoid panics on untrusted input.
- Add English rustdoc for public interfaces and explain invariants rather than restating syntax.
- Add the project copyright and SPDX header to new source, documentation, configuration, and workflow files.

### Unsafe Rust

Workspace crates forbid unsafe Rust. A narrowly scoped exception requires a dedicated crate, measured need, documented safety invariants, a safe API, portable reference implementation, focused tests, and explicit security review. Do not relax the workspace lint to make an exception convenient.

### Dependencies

Prefer the standard library for small foundational interfaces. A new dependency must have a clear need, compatible license, maintained source, bounded attack surface, and deterministic behavior where protocol-visible. Do not use wildcard versions or unpinned Git dependencies.

## Consensus determinism checklist

For any protocol or execution change, verify that results do not depend on:

- wall-clock time, thread scheduling, worker count, or race order;
- unordered map/set iteration;
- local CPU, network, memory, or disk measurements;
- cache, prediction, prefetch, SIMD, AOT, or JIT availability;
- locale, filesystem, environment variables, or ambient network state;
- target-dependent overflow, floating point, or serialization;
- error-message text rather than stable error categories.

Optimized and portable/reference paths must produce identical canonical fixtures.

## Tests

Add tests for implemented behavior, including malformed and boundary inputs. Prefer pure unit tests for invariants, workspace integration tests for component boundaries, and fixtures for canonical bytes. Protocol changes should eventually include property tests, fuzz seeds, and cross-platform determinism vectors.

Run before submitting:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Report checks that could not be run. Never bypass hooks or remove assertions merely to make CI green.

Benchmarks are not part of the gate above, and no measured duration can fail
anything: the harness carries no timing threshold. Run one with
`cargo bench --locked -p <crate>`, or shorten an exploratory run with
`ASTROLUNE_BENCH_ROUNDS=5 ASTROLUNE_BENCH_TARGET_US=500`. CI does run every suite
on both platforms as a required check, which verifies that each declared
benchmark still executes and that none has silently stopped running; it is not a
performance gate, and the figures from a shared runner are not comparable. Note
that `--all-targets` also compiles and lints benchmarks, so a stale benchmark
breaks clippy. A measurement is not a correctness check: see
[local performance measurement](docs/56-performance-measurement.md) for the
method and its limits.

## Documentation

Update documentation in the same change as an interface or architecture modification. Keep implementation status factual, using the grades defined in [`ARCHITECTURE.md`](ARCHITECTURE.md): `planned`, `interface baseline`, `implemented`, `tested`, `benchmarked`, `audited`, and `production-ready`. A grade records how far an area has been carried; do not raise one ahead of the code and tests.

## Pull requests

- Keep one coherent purpose per pull request.
- Explain the problem, invariants, compatibility impact, security impact, and verification.
- Avoid unrelated formatting or renaming.
- Expect additional review for consensus, cryptography, runtime, storage recovery, P2P, key management, and wallet authorization.
- Do not include secrets, generated build output, or private test data.

The project currently has no promise of merge timelines. Governance is described in [`GOVERNANCE.md`](GOVERNANCE.md).
