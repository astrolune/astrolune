<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 10. State Commitments and Recovery

## Implemented reference behavior

`InMemoryState` and `FileBackedState` share bounded, ordered state transitions, BLAKE2s Merkle roots, immutable snapshots, and membership and absence proofs. `InMemoryStorage` stages finalized batches before verifying their state roots, then publishes state, block, certificate bytes, and checkpoint together. It retains immutable historical state views for snapshot export and preserves the latest checkpoint when pruning.

The producer executes proposals against an isolated copy. Preparing or rejecting a proposal does not change canonical state, height, or pending transactions. Before committing, the producer re-executes the reference transition and checks outputs, resource totals, capacity, and commitments. Successful storage commit publishes the producer's state and removes included transactions. `FullNodeService` propagates commit failures and retains the pending proposal for retry.

These are reference implementations. `InMemoryStorage` does not survive restart, and the daemon still demonstrates admission, execution, and finality. `FileBackedStorage` now persists retained blocks, certificates, checkpoints, and historical state together; see [chain archives](11-chain-archives.md). Finality authentication, finalized account/fee transitions, and production-scale state indexing remain open. `FileBackedState` persists state entries only, without block history or certificates.

## State commitment version 1

Let `H(D, M)` be the length-framed BLAKE2s domain hash from [cryptographic foundations](09-cryptographic-foundations.md#domain-framing). Entries are ordered lexicographically by the complete key bytes. All lengths and counts below are unsigned 64-bit little-endian integers.

```text
leaf(K, V) = H("astrolune.state.leaf.v1", len(K) || K || len(V) || V)
node(L, R) = H("astrolune.state.node.v1", L || R)
root(N, T) = H("astrolune.state.v1", N || T)
```

Each level combines adjacent left/right nodes. A last unpaired node is promoted unchanged. The top hash is wrapped with the original entry count. An empty tree uses count zero and a 32-byte zero top hash; its root is:

```text
292b37da034d0be78d8a0747a314188cdadcae8d268a3dfd433972228b7f3d36
```

`StateProof` binds a zero-based leaf index, total entry count, and siblings from leaf to root. Verification derives orientation and unpaired levels from the index and count, requires exactly the necessary siblings, and checks the supplied key and value against the trusted root. `None` from `prove` is not an authenticated absence proof.

`StateDiff::commitment()` is `H("astrolune.state.diff.v1", canonical_diff_bytes)`. Operation order, repeated writes, deletions, and field lengths are preserved. This replaces the demonstration executor's XOR output commitment. A final state root depends on final entries, whereas a diff commitment also binds the sequence of operations.

## Authenticated absence and proof transport

`StateSnapshot::prove_absence(key)` returns `Some(StateAbsenceProof)` for an absent key and `None` for an existing key. Keys longer than 256 bytes are rejected. The in-memory and file-backed backends, including immutable snapshots retained across commits, expose the same API.

Each neighboring `StateWitness` contains its complete key, value, and membership path. `verify(trusted_root, requested_key)` requires strict key ordering and authenticates every supplied neighbor against the same root. Interior gaps require consecutive leaf indices and equal leaf counts. A missing predecessor requires index zero; a missing successor requires the final leaf. Two missing neighbors authenticate only the canonical empty-state root. Authentic but nonadjacent entries cannot establish absence, and a proof for an older snapshot must be checked against that snapshot's root.

The caller must independently authenticate a root produced by the canonical ordered-state implementation. A proof does not establish finality or validate ordering of the entire committed tree. Because version-1 leaves bind complete values, absence proofs disclose neighboring values and may contain up to two megabytes of value data. Proof generation recomputes a membership path for each neighbor; incremental indexing remains future work. Measured on one host, that makes generation linear in the account count while verification stays logarithmic: at 4,096 accounts a membership proof costs about 1.85 ms to generate against 2.5 us to verify, a factor of roughly 733, and absence proofs cost about twice membership on both sides. The figures establish no bound and describe one machine; [measurement limits](56-performance-measurement.md).

The standalone absence-proof format leaves existing roots, snapshots, and chain archives unchanged:

```text
"ASTABSEN"                 8-byte magic
version = 1                u16 little-endian
lower witness, then upper witness:
    present                u8, exactly 0 or 1
    if present:
        key_length         u64 little-endian
        key                key_length bytes
        value_length       u64 little-endian
        value              value_length bytes
        index              u64 little-endian
        leaf_count         u64 little-endian
        sibling_count      u8
        siblings           sibling_count * 32 bytes, leaf to root
```

`to_bytes` and `from_bytes` enforce the state key/value/count bounds, a valid leaf index, at most 20 siblings, and a maximum packet size of 2,099,022 bytes. Decoding checks the complete framing before allocating owned keys and values; unsupported versions, reserved presence flags, truncation, and trailing bytes are rejected. Decoding alone is not authentication: callers must invoke `verify` with the requested key and trusted root. The requested key and root are external inputs, so one gap proof can authenticate multiple absent keys strictly within that gap.

Tests cover generated tree shapes, boundary gaps, prefixes and empty keys, skipped neighbors, mixed roots, stale snapshots, file recovery, exact format fixtures, length bounds, every truncation and single-byte mutation of a proof. The `decode_state_absence` fuzz target checks canonical re-encoding and rejection under an invalid root. Long fuzz campaigns remain a release gate.

## Bounds and atomic transitions

The reference backend accepts at most 1,048,576 entries, keys of at most 256 bytes, values of at most 1,048,576 bytes, and snapshots of at most 67,108,864 bytes including framing. Every intermediate operation in a staged batch must fit these bounds. These are explicit reference-format limits, not adaptive block-capacity recommendations.

`prepare(parent, diffs)` applies diffs in transaction order to a private copy. Writes to the same key retain their original order. Wrong parents, exceeded bounds, or mismatched proposed roots leave the original state unchanged. `commit_verified` publishes only a matching root. Snapshots share immutable entry maps and remain valid across commits and pruning of the owning backend.

This implementation copies the map for each prepared transition and recomputes the tree. Historical snapshots can retain substantial memory until pruned. An incremental persistent tree is future work.

## Canonical snapshot bytes

```text
"ASTSTATE"                  8-byte magic
version = 1                 u16 little-endian
entry_count                 u64 little-endian
state_root                  32 bytes
repeated entry_count times:
    key_length              u64 little-endian
    key                     key_length bytes
    value_length            u64 little-endian
    value                   value_length bytes
```

Keys must be strictly increasing. Duplicate keys, unsupported versions, trailing bytes, truncated fields, oversized lengths, and incorrect roots are rejected. The entire structure is checked before allocating owned entries. `InMemoryState::from_snapshot(bytes, expected_root)` also checks an independently supplied root.

`NodeStorage::import_snapshot(expected_checkpoint, source)` requires the caller to authenticate that checkpoint through finality before importing. A self-consistent snapshot is not evidence of finality. The first transport chunk is exactly:

```text
"ASTCHAIN" || u16_le(1) || u64_le(height) || block_hash || state_root
```

Remaining chunks contain canonical state snapshot bytes, with 65,536 bytes per chunk except the nonempty last chunk. Empty, reordered, oversized, surplus, or truncated data is rejected. Publication happens only after the checkpoint matches and the state root verifies. Successful import replaces local history with the trusted checkpoint; blocks and certificates must be fetched and authenticated separately. Existing checkpoints cannot be rolled back or replaced at the same height by this API.

## File publication and recovery

`FileBackedState::open(path)` holds an operating-system exclusive lock on `path.lock` for its entire lifetime. The parent directory must already exist and be controlled by the operator. The paths `path.lock` and `path.pending` are reserved for the database. Symlink data-file aliases are rejected; arbitrary hostile changes to the database directory are outside this backend's threat model. A second writer fails with `StateError::Locked`. The sidecar lock file is kept after closing so its identity remains stable; process exit releases the actual OS lock.

Commit prepares and verifies all entries before writing a complete snapshot to `path.pending`, synchronizes the file with `sync_all`, closes it, and renames it over the published file. Memory changes only after successful rename. Failure before publication preserves both the current in-memory state and the published file. Recovery validates the published file and ignores incomplete staging bytes; the next writer replaces interrupted staging data.

On Unix, the parent directory is also synchronized. Failure after rename returns `DurabilityUnknown`, retains the published state in memory, and blocks further writes until reopen. Windows directory durability during power loss remains filesystem-dependent; synchronized files and atomic replacement do not establish a universal hardware power-loss guarantee.

The stored root detects accidental corruption. An adversary who can rewrite the whole file can also replace its root; a node must compare recovered state with its independently authenticated chain checkpoint.

## Compatibility and verification

Old XOR state roots, zero empty-state roots, XOR diff commitments, and unversioned flat state files are incompatible. Legacy files fail closed and are not silently overwritten. Preserve any old data separately; initialize fresh reference state or perform an explicit verified migration. This change does not migrate wallets, historical blocks, or chain databases.

Tests include independent BLAKE2s fixtures, generated odd/even Merkle trees, altered proofs, every truncation and byte-position mutation of a sample snapshot, malformed lengths, duplicate keys, ordered writes, backend equivalence across restarts, write/rename failures, cross-process lock exclusion, abrupt process exit, authenticated multi-chunk exchange, failed-import rollback, pruning, and rejected-proposal retry. The decoder fuzz package includes `decode_state_snapshot` with an exact re-encoding invariant. Long fuzz campaigns, cross-platform qualification, and independent review remain release gates.
