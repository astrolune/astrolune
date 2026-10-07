<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

## Summary

Describe the problem and the implemented change.

## Protocol impact

- [ ] No consensus-visible behavior changes.
- [ ] Consensus-visible behavior is documented and covered by deterministic tests.
- [ ] Serialization compatibility was considered.
- [ ] Security assumptions and failure modes were considered.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`

List additional checks and any checks that could not be run.
