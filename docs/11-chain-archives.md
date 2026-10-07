<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 11. Durable Chain Archives

## Scope and use

This document describes the legacy archive and local demonstration mode. New certified network directories use the [append-only chain log](22-append-only-chain-storage.md); existing archives remain supported without automatic migration.

`storage::FileBackedStorage` implements `NodeStorage` with an atomic, single-writer file archive. It preserves retained block bodies, opaque finality certificate bytes, checkpoints, and state snapshots across restarts. `BlockProducer::commit_block` already accepts this backend through its generic storage boundary.

```rust,no_run
use storage::{FileBackedStorage, NodeStorage};

let mut storage = FileBackedStorage::open("chain.bin")?;
let recovered = storage.recover()?;
// Authenticate the recovered checkpoint against trusted chain configuration/finality.
// Pass verified CommitBatch values to storage.commit(&batch).
# Ok::<(), storage::StorageError>(())
```

Both memory and file backends reject transaction bodies whose signed canonical IDs do not match the header's transaction root. They also check structural transaction/certificate bounds, parent linkage, consecutive heights, and the resulting state root. The caller must authenticate finality and execution, including receipts and account semantics. The archive checksum detects corruption; it does not authenticate a file rewritten by an adversary.

`FullNodeService::new` retains the memory backend for fixtures. `FullNodeService::open(config, path)` verifies the file archive, restores execution state and the parent hash, and resumes at the next checked height. `BlockProducer::from_checkpoint` rejects state-root mismatches, populated state without a checkpoint, and exhausted heights. The caller still authenticates the checkpoint and chain identity; archive version 2 contains no chain configuration identifier in its header.

The daemon creates its data directory and opens `chain.bin` there. Each `--blocks N` invocation produces N additional blocks. `--blocks 0` initializes or recovers without opening listeners; `--dry-run` validates options and optional genesis input without writing files or opening listeners. Unknown, missing, duplicate, overflowing, or malformed arguments fail before opening storage. Both listener sockets bind before block production starts. An occupied listener or locked/corrupt archive stops startup rather than silently continuing.

`--genesis PATH` activates [genesis account state](12-genesis-and-accounts.md) through `FullNodeService::open_with_genesis`. `FileBackedStorage::initialize_genesis` atomically installs a trusted height-zero snapshot anchor only in an empty archive. Its identifier is the genesis commitment, with no block body or certificate; production starts at height one. Restarts check genesis identity stored in committed state. Genesis-free opening rejects genesis-initialized archives, and supplying genesis never converts a nonempty legacy chain.

RPC chain status is initialized from recovery and updated only after successful durable commits. Genesis-backed daemon account queries read committed account state, and transaction submission reaches signed native payment admission in the node mempool. Genesis-free chains keep these operations unavailable. The RPC service boundary requires `Send` so a bound server can move to its worker thread.

This is demonstration block/state recovery. Certificates remain placeholders. Genesis-backed native payment balances and nonces recover from committed state. Consensus keys, signing journals, pending transactions, and adaptive-capacity observations are not recovered. The latter observation window is bounded and starts empty after restart; it does not change the producer's configured header capacity. The daemon uses the supplied genesis chain ID or defaults to 7 and does not implement network synchronization. Its listener workers currently terminate with the process. Archives stop accepting writes at the reference bounds below; automatic pruning is not enabled.

Process tests cover repeated daemon runs, recovery-only startup, argument errors, dry runs, writer exclusion, corrupt archives, and listener failures. Differential tests compare 20 service restarts with uninterrupted block production, including nonempty execution state and identical retained block bodies.

## Archive version 2

All integers below use unsigned fixed-width little-endian encoding. A `blob` consists of a `u64` byte length followed by exactly that many bytes.

```text
"ASTSTORE"                         8-byte magic
version = 2                        u16
checkpoint_count                   u64
for each checkpoint in height order:
    height                         u64
    block_hash                     32 bytes
    state_root                     32 bytes
    state_snapshot                 blob (ASTSTATE version 1)
    has_block                      u8: exactly 0 or 1
    if has_block == 1:
        block_header               200 canonical bytes
        transaction_count          u64
        each signed transaction    blob (current canonical transaction codec)
        finality_certificate       blob
checksum                           32 bytes
```

The checksum is `H("astrolune.storage.archive.v1", all_preceding_bytes)` using the [shared domain framing](09-cryptographic-foundations.md#domain-framing). Recovery rejects unknown versions, bad checksums, malformed lengths, non-canonical inner values, trailing bytes, invalid roots, gaps in retained heights, and broken parent linkage.

Only the first retained checkpoint may lack a block and certificate. This represents an authenticated imported snapshot anchor or an operator-trusted genesis anchor. Subsequent records must contain blocks extending that anchor. Pruning preserves the latest checkpoint and removes a prefix of history; the first retained block may therefore have a parent outside the archive.

Reference bounds are 256 MiB per archive, 4,096 retained checkpoints, 65,536 transactions per block, 4 MiB per encoded transaction, and 1 MiB per certificate. Inner transaction codec and state snapshot limits also apply. Oversized writes fail before publication. These are reference storage bounds, not negotiated protocol capacity rules.

## Atomicity and recovery

The parent directory must already exist and be controlled by the operator. The backend canonicalizes its parent path, rejects symlink data/lock aliases, and holds an OS exclusive lock on `path.lock`. The lock sidecar remains on disk; process exit releases its lock. Concurrent opens fail with `StorageError::Locked`.

Commit, snapshot import, and pruning stage a complete private history, encode it, write `path.pending`, synchronize the file, and atomically rename it over the published archive. Memory changes only after rename. Errors before publication preserve the old memory and disk state. Recovery ignores pending bytes and verifies the published archive; it does not substitute pending data for a corrupt published file.

On Unix, the parent directory is synchronized after rename. Failure at that point returns `DurabilityUnknown`, retains the newly published in-memory view, and blocks further operations until close/reopen. A caller must stop its pipeline and recover, not retry blindly. Windows power-loss durability remains filesystem-dependent.

Snapshot import persists the authenticated checkpoint and state without inventing block bodies or certificates. It discards prior history and rejects rollback or replacement at the same height. Later commits extend the imported checkpoint. Pruning and historical snapshot exports retain the same behavior after reopening.

The reference backend clones retained block metadata and rewrites all retained snapshots for every update. Decoded allocations and temporary copies can substantially exceed encoded size. Operators must prune within bounds. Incremental indexing, compaction, high-throughput storage, Linux qualification of the new recovery suite, and prolonged crash/fuzz campaigns remain work for a production backend.

## Compatibility and verification

Block IDs now use `H("astrolune.block.v1", canonical_header_bytes)`, replacing XOR folding. Receipt commitments use `H("astrolune.receipt.v1", canonical_receipt_bytes)`, matching the node's existing receipt leaves. Header/receipt wire bytes are unchanged; old block IDs, parent links, and standalone XOR receipt commitments are incompatible. The [versioned transaction envelope](14-versioned-transactions.md) requires archive version 2. Version-1 archives are rejected, including empty archives; recovery does not rewrite them. Unknown archive formats fail closed; no automatic migration is performed.

Tests cover independent hash vectors, every header/receipt byte, former XOR cancellation attacks, height exhaustion, all archive truncations and byte mutations, malformed structures with recomputed checksums, repeated reopen, retained historical exports, pruning, failed commit/import/rename rollback, second-process exclusion, and abrupt exit after publication.
