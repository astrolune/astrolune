<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 12. Genesis and Initial Accounts

## Implemented behavior

`Genesis::decode` validates bounded canonical input. `Genesis::commitment` validates the configuration and computes the standard domain-separated BLAKE2s-256 hash. `Genesis::materialize` builds a private `InMemoryState` containing initial account balances, validator weights, and a commitment to all genesis parameters. It does not change an existing database or start a chain.

The operator command reads at most the genesis byte limit plus one byte, validates the input, and prints the chain ID, genesis hash, initial state root, and entry counts:

```sh
cargo run -p cli -- genesis genesis.bin
```

It writes no files. Verify the genesis hash against an independently trusted chain configuration before starting the daemon. Validator public-key registration and consensus signing remain separate work. [Native signed payments](13-native-payments.md) now implement committed balance/nonce transitions and fixed reference fees.

## Daemon activation and recovery

```sh
cargo run -p daemon -- --genesis genesis.bin --data-dir node-data --dry-run
cargo run -p daemon -- --genesis genesis.bin --data-dir node-data --blocks 3
cargo run -p daemon -- --genesis genesis.bin --data-dir node-data --blocks 0
```

The daemon reads bounded binary genesis input before creating data files or listeners. `--dry-run` validates input without writing data or opening listeners. Chain ID and initial block capacity come from genesis. The demonstration committee uses the first `committee_size` validators in canonical order with their full `u128` weights; this is not a PoTB sampler and does not implement rotation or authenticated finality.

`FullNodeService::open_with_genesis` atomically installs the materialized state in an empty archive. It stores a trusted height-zero anchor whose identifier is the genesis commitment and whose state root is the materialized root. This anchor has no block body or finality certificate. The first produced block is height one, with the genesis commitment as its parent. `--blocks N` counts additional produced blocks, excluding the genesis anchor; `--blocks 0` initializes or recovers it without listeners.

Every restart requires the same genesis file contents. The service verifies the committed genesis identity before production; at height zero it also checks the anchor ID and complete initial state root. It never reapplies allocations to a running chain. Missing or mismatched genesis, incompatible producer configuration, and nonempty legacy archives fail closed. An empty legacy archive can be initialized. Existing genesis-free demonstration chains keep their prior behavior. No archive encoding changes are required: genesis uses the existing snapshot-anchor record.

These checks bind local recovery to the operator's chosen genesis. Archive checksums do not authenticate later execution or consensus against maliciously rewritten local data. The native payment executor writes only sender/recipient accounts, preserving genesis and validator keys. General contract/system-operation authorization remains pending.

## Canonical genesis version 1

All integers are fixed-width little-endian. Fields occur in this order:

| Field | Encoding |
|---|---|
| Version | `u16`, exactly 1 |
| Chain ID | nonzero `u32` |
| Capacity | four nonzero `u64`: compute, memory, IO, bandwidth |
| Committee size, rotation count | two `u64` |
| Runtime version | nonzero `u32` |
| Validator count | `u64`, at most 4,096 |
| Validators | 32-byte ID followed by `u128` weight, 48 bytes each |
| Allocation count | `u64`, at most 65,536 |
| Allocations | 32-byte address followed by `u64` balance, 40 bytes each |

The maximum complete encoding is 2,818,122 bytes. These genesis counts retain their existing fixed-width encoding; they do not use the transaction codec's compact lengths. Both lists and the end of input are checked before allocating owned entries. Trailing bytes, truncations, oversized counts, and unsupported versions are rejected.

IDs and addresses must be nonzero and strictly increasing by raw bytes. Validator weights must be nonzero and their sum must fit `u128`. Committee size is at least one and no larger than the validator set. Rotation is at least one and no larger than the committee. Empty allocations and explicit zero balances are valid. A nonzero runtime identifier alone does not establish that an execution backend supports that runtime.

`H("astrolune.genesis.v1", canonical_genesis_bytes)` uses the [standard domain framing](09-cryptographic-foundations.md#domain-framing). `GenesisCommitment::genesis_hash` now returns `Result<Hash256, GenesisError>` and validates before invoking its provider. `Genesis::commitment` always uses the protocol hash suite.

## Initial state layout

Keys consist of the exact ASCII namespace below followed by the indicated raw identity bytes, without a separator or length beyond the namespace's own trailing slash.

| Key | Value |
|---|---|
| `astrolune/genesis/v1` | 32-byte canonical genesis hash |
| `astrolune/validator/v1/` + validator ID | initial `u128` weight, little-endian |
| `astrolune/account/v1/` + address | `u64` nonce then `u64` balance, little-endian |

Every allocation creates an account with nonce zero. The metadata commitment ensures that changing chain ID, capacity, committee policy, or runtime version changes the initial state root even when all allocations remain identical. Keys are canonically ordered and committed using the existing [state Merkle format](10-state-and-recovery.md#state-commitment-version-1). Snapshots use that format unchanged.

`types::AccountState` is shared with transaction admission; `transaction::AccountState` remains a compatible re-export. `state::account_key` derives the key and `state::read_account` reads from an independently authenticated snapshot. Absent accounts return `None`; malformed or extended values fail with `StateError::Corrupt`. Accounts contain balances and nonces, not signing keys. Admission still requires the public key whose derived address matches the sender.

These namespaces define the reference initial layout. Enforcement of system-key write restrictions belongs to future authenticated execution integration; the general state database is a low-level key/value store.

## Compatibility and verification

Valid version-1 genesis bytes remain unchanged. Previously accepted invalid configurations and unknown versions are now rejected by decoding and hashing. The materialized state layout is new; it is not retroactively installed in existing demonstration archives.

Tests cover every truncation, hostile counts, aggregate-weight overflow, configuration validation, byte-mutation round trips, maximum-size materialization, independent byte/hash/root vectors, membership and absence proofs, immutable snapshots, corrupt accounts, file recovery, signed admission using recovered accounts, and CLI success/failure behavior. Activation tests cover daemon restarts, unchanged balances, exact archive equivalence with uninterrupted production, genesis/configuration mismatches, legacy-chain rejection, dry runs, and retry after failed publication. Quorum arithmetic is tested up to `u128::MAX`. The standalone codec fuzz package includes `decode_genesis`; long fuzz campaigns remain outstanding.

For the fixture in `crates/genesis/tests/canonical.rs`, the independently calculated genesis hash is `98ddf60aafa73a4717c1b94fbc4df02f1c2ff9ba909f236ee3924c70895c0bf6`, and the initial state root is `0b818b0904e6b79282d518498a87120b61e622fd672fc9e78853d8190c4770ef`.
