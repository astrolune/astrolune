<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 22. Append-only chain storage

## Implemented behavior

New certified validator and observer directories use `storage::ChainStorage` backed by `AppendOnlyStorage`. A finalized block appends its body, certificate and ordered state deltas. Previous block bodies are neither rewritten nor retained in memory. The node keeps the latest state and a height-to-file-offset index, reads requested history from disk, and propagates read failures. The daemon stops on a local history read failure before its next consensus step.

The new log has no 4096-checkpoint or 256 MiB total-history limit. A regression test commits 4097 blocks, verifies the unchanged genesis prefix, reopens the log and reads both ends of history. This is a persistence improvement, not a production throughput or capacity claim.

The network independently verifies recovered finality certificates against trusted genesis membership and checks complete ancestry. Storage checks transaction commitments, sequential height/parent linkage, and replayed state roots. Live imports still authenticate certificates and re-execute payments before publication. Checksums detect damaged bytes; they do not authorize finality.

## Publication and recovery

The data directory contains:

| File | Purpose |
| --- | --- |
| `chain.bin` | Immutable log header followed by append-only records |
| `chain.bin.head` | Durable published end offset and chained record digest |
| `chain.bin.lock` | Persistent sidecar held under an exclusive OS writer lock |
| `chain.bin.pending` | Temporary head publication; never authoritative during recovery |

A commit validates the entire batch, prepares the next state, appends and synchronizes one record, writes and synchronizes the temporary head, then atomically replaces the published head. Only afterward does the node publish the new in-memory checkpoint and consume pending payments. On Unix, the containing directory is synchronized after head replacement. Windows power-loss guarantees depend on the filesystem and storage stack; abrupt process-exit tests do not qualify power-loss behavior.

Recovery checks the header and head, streams exactly the published prefix, verifies chained checksums, replays every state transition and rebuilds the height index. Only after complete verification can it truncate bytes beyond the published end. A complete but unpublished record is discarded just like a partial tail. A missing head, head beyond EOF, unknown format, invalid checksum, invalid ordering or invalid state root fails startup without repairing the committed prefix.

A failure before head replacement attempts to truncate and synchronize the old end. If rollback cannot establish durability, or directory synchronization fails after replacement, further operations return `DurabilityUnknown` until reopening. A published head is never rolled back by the writer. Failure-injection tests cover both sides of this publication boundary.

## Format version 1

Integers are fixed-width little-endian. A `blob` is `length:u64 || bytes`. `H` is the project's length-framed domain-separated BLAKE2s-256 function, not raw string concatenation of a domain and payload.

```text
chain header:
    "ASTLOG01" || H("astrolune.storage.log.v1", "ASTLOG01")

each record:
    payload_length:u64 || payload || digest:32
    digest = H("astrolune.storage.log.v1",
               previous_digest:32 || payload_length:u64 || payload)

published head (80 bytes):
    "ASTLOG01" || end_offset:u64 || last_digest:32 || checksum:32
    checksum = H("astrolune.storage.head.v1", preceding 48 bytes)
```

The initial previous digest is the header digest. Payload tag 0 is an anchor: `height:u64 || block_hash:32 || state_root:32 || snapshot:blob`. An anchor is allowed only as the first record. Genesis uses height zero; a separately authenticated snapshot can initialize an empty library store at another height, but the certified network still requires full history from genesis.

Payload tag 1 is a batch: canonical 200-byte block header, transaction count `u64`, canonical transaction blobs, certificate blob, diff count `u64`, then each diff's operation count `u64` and ordered operations. Put is `1:u8 || key:blob || value:blob`; delete is `2:u8 || key:blob`. Duplicate keys and diff ordering are preserved. Payload tag 2 has the same batch fields followed by a bounded effects blob containing ordered receipts and a genesis membership witness; [document 35](35-certified-receipts.md) specifies it. Unknown tags, trailing bytes, excessive counts, and oversized fields are rejected.

## Compatibility and operation

Existing `ASTSTORE` version-2 files remain readable through `FileBackedStorage`. Receipt-producing commits upgrade the archive to version 3; see [receipt format compatibility](35-certified-receipts.md). They retain their 4096-checkpoint / 256 MiB limits and startup explicitly reports the legacy backend. There is no automatic migration, new consensus format or peer protocol change. Legacy validators and log-backed observers can exchange the same certified blocks; mixed-backend payment and restart tests cover this.

For a new network directory, ordinary `cli devnet ...` and validator/observer launch commands select the log automatically. Existing validator identities must retain their signing journals and protected locks. Reaching an old storage limit is not a reason to recreate a validator identity or delete signing state. In-place archive migration remains future work; an additional observer in a fresh directory can obtain history over authenticated synchronization.

Stop the node before backing up or restoring the directory. Keep `chain.bin` and `chain.bin.head` from the same backup together with the node's signing journal, consensus cache, role marker and trusted configuration as applicable. Do not delete `.head` or the lock sidecar to attempt repair. A missing/corrupt published file requires a consistent backup or a separately provisioned observer recovery; startup does not guess the lost checkpoint. Checksums cannot detect a coherent rollback of all local files, so external anti-rollback protection remains required for validator key custody.

## Remaining bounds and qualification

| Area | Current bound or limitation |
| --- | --- |
| One log payload | 72 MiB, checked before recovery allocation |
| State engine | Latest state remains in memory; 64 MiB encoded snapshot and 1,048,576 entries |
| Deltas | 1,048,576 diffs and total operations per batch; existing key/value bounds apply |
| Transaction/certificate | Existing archive structural bounds; network applies its stricter wire limits |
| Height index | Memory grows with retained block count |
| Recovery | Linear replay and certificate verification from genesis |
| Historical snapshots | Replayed on demand; latest snapshot reads current committed state |
| Pruning / replacing history | Explicitly unsupported by the log; snapshot import requires an empty store |
| Signing journal | [Protected journals roll over](23-signing-journal-rollover.md) after 100,000 decisions at fixed size; raw version-1 journals retain their bound |

Tests cover differential replay against the reference store, ordered duplicate writes/deletes, historical snapshots, all byte truncations/mutations of a committed fixture, every unpublished tail cut, corrupt/missing heads, live read corruption, writer exclusion, abrupt child-process exit, uncertain publication, legacy compatibility, and actual TLS daemon shutdown after a corrupted history read. Production state indexing, bounded startup, retention/compaction, rollback-resistant key custody, sustained load and power-loss testing remain open.
