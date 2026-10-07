<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 4. Transactions, Parallel Execution, and State

## 4.1 Canonical transaction

A transaction contains a version, chain ID, sender, nonce, expiry, lane, declared state access list, per-resource limits and prices, payload, and signature. Encoding is versioned, length-bounded, canonical, and domain-separated.

Validation follows a fixed order: shape and bounds, chain and expiry, sender and nonce, declared resources and balance, signature, lane-specific payload, then execution eligibility. Invalid pre-admission transactions do not enter execution.

### Current codec baseline

The current `types::Transaction` uses the [version-1 envelope](14-versioned-transactions.md): magic, version, chain ID, sender, nonce, inclusive expiry height, explicit lane, access list, resource limits, signed resource prices, payload, and signature. Unknown versions and lane tags are rejected.

All integers use fixed-width little-endian bytes. A sequence length below 128 uses one byte. Larger lengths use exactly `0x80` followed by a little-endian `u32`; markers `0x81` through `0xff` and five-byte encodings of lengths below 128 are rejected as non-canonical. Booleans accept only `0` and `1`, including receipt success flags.

The decoder limits access lists to 1,048,576 entries, each state key to 256 bytes, and payloads to 1,048,576 bytes. It validates the full transaction, including signature length and absence of trailing bytes, before allocating owned keys or payload. These are structural codec limits, not production block-capacity recommendations or signature verification.

The versioned envelope changes transaction bytes and commitments; unversioned transactions are not accepted. Alternate length encodings and receipt flags are rejected. Golden vectors, exhaustive prefix and flag checks, transaction mutation checks, and truncation tests are in `crates/codec`; fuzz targets for transactions, state keys, and receipts assert that every accepted input re-encodes to identical bytes.

The current cryptographic suite, signing bytes, transaction IDs, and `SignedValidator` behavior are specified in [cryptographic foundations](09-cryptographic-foundations.md). The demonstration validator remains separate from cryptographic admission.

## 4.2 Adaptive Execution Leasing

A transaction reserves the state keys it declares for the duration of its wave. Read leases are shareable; write leases are exclusive. Keys are normalized, sorted, and deduplicated before scheduling.

A transaction that accesses an undeclared key does not silently extend its lease. The initial policy is deterministic failure. A later protocol may define deterministic rescheduling, but all validators must make the same choice and charge the attempted work.

Access lists may be supplied by the sender, derived from a contract manifest, or conservatively expanded by static analysis. Predictions may improve placement but cannot reduce the enforced lease.

## 4.3 State access scheduler

The scheduler constructs a conflict graph from leases and partitions transactions into ordered execution waves. Transactions in one wave have no declared write/read or write/write conflict. Wave construction uses original block position as the stable tie-breaker.

The implemented `GreedyScheduler` visits transactions in block order and chooses the earliest wave strictly after every earlier conflicting transaction. Transactions from the same sender also remain ordered for nonce and balance effects. The current access list has no mode field, so all declared keys are conservatively treated as writes.

Choosing the first conflict-free wave alone is insufficient: for access sets `{A}`, `{A,B}`, `{B}`, placing the third transaction back in the first wave reverses its dependency on the second. The scheduler therefore preserves directed conflict order. `StateLease::new` sorts and deduplicates requests with write access taking precedence; write leases permit reads, and read-only leases may be shared.

Generated conflict graphs are checked for complete transaction coverage, conflict-free waves, dependency order, and equivalence to serial writes. The plan is not yet connected to a parallel runtime; `SerialScheduler` remains available. More sophisticated schedulers may replace the reference only if the chosen plan is itself committed or if they provably produce the same outputs and replay behavior.

## 4.4 Predictive execution

A predictor uses recent finalized access patterns, contract code metadata, and call selectors to estimate conflicts and locality. It can select workers, prefetch keys, or recommend waves. Prediction data is local and may differ between nodes.

Correctness never depends on a prediction. Observed accesses are compared with leases, and canonical fallback execution handles misses.

## 4.5 Optimistic execution

Potentially conflicting transactions may run concurrently against one immutable snapshot. Each output records its read set, write set, read versions, receipt, and state diff. Validation proceeds in committed transaction order. A stale read or incompatible write causes deterministic replay against the latest validated overlay.

Replay limits prevent adversarial conflict patterns from consuming unbounded work. After the limit, the remaining transactions execute sequentially.

## 4.6 Transaction locality

Within ordering freedom explicitly granted to the producer, transactions with nearby accounts, contracts, code, and state keys should be grouped to improve caches and sequential I/O. Consensus commits the final order, so every validator executes the same semantic sequence.

Fee priority, fairness, anti-MEV policy, locality score, and lane guarantees need one deterministic ordering specification. Locality cannot reorder transactions after consensus.

## 4.7 Immutable snapshots and diffs

Every block executes from an immutable parent snapshot. Parallel workers read through snapshots and write only to private diffs. Successful transaction diffs are merged in committed order into a block overlay. Failed transactions preserve their defined fee and nonce effects but discard contract writes.

The final commit stage applies a canonical key order in batched sequential writes, calculates the state root, synchronizes durable data, and atomically publishes the new root. A mismatch with proposal commitments aborts the block without partially publishing state.

## 4.8 Hot/cold state and caches

Hot/cold placement is local database policy:

- hot state uses memory-resident indexes and decoded cache entries;
- warm state uses mapped or block-cached persistent data;
- cold state uses compact immutable segments and slower indexes.

A multi-level cache may include worker-local, process-shared, and persistent tiers. Cache keys include state root or version to prevent stale reads. Eviction never changes logical state.

## 4.9 Prefetch and zero-copy access

The scheduler submits declared and predicted keys before a wave starts. Prefetch is cancellable and bounded. State values should remain encoded or borrowed through verification when possible, with decoding delayed until required.

Database implementations must make lifetimes explicit. Compaction cannot invalidate data still borrowed by an execution snapshot.

## 4.10 Efficient state database

The state database must support immutable snapshots, content or version integrity, batched reads, write batches, sequential commit, crash recovery, checksums, pruning policy, and snapshot export/import. A concrete production engine is not selected. The implemented reference backends now provide bounded Merkle state, membership and absence proofs, verified snapshots, and atomic publication; see [state and recovery](10-state-and-recovery.md) for exact formats, failure behavior, compatibility, and remaining work.

State sharding is deferred. If required later, it begins as internal partitions under one execution domain and one state commitment. Cross-shard asynchronous semantics are not introduced by storage layout alone.
