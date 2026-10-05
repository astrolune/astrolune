<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 8. Implementation Status and Roadmap

## 8.1 Current baseline

As of 2026-10-05, this repository contains a Rust 2024 workspace with:

- canonical shared types and bounded decoder primitives;
- standard BLAKE2s-256 and strict Ed25519 backends, canonical transaction commitments, and state-aware signed admission;
- normalized access leases and dependency-preserving greedy execution-wave planning;
- compileable interfaces for cryptography, genesis, transactions, PoTB committees, BFT votes, state, runtime, execution, persistence, synchronization, P2P, RPC, configuration, keystore, telemetry, and node coordination;
- a tested in-memory mempool reference policy, genesis validation, configuration secret redaction, quorum arithmetic, decoder boundary helpers, and workspace integration invariants;
- authenticated double-vote evidence, bounded durable validator evidence outboxes, offline evidence CLI verification, experimental deterministic scoring and an explicit PoTB producer profile with canonical inclusion, active age weights, quorum admission and authenticated recovery, with daemon activation and RPC/CLI/DNS verification;
- bounded finalized-block history RPC for read-only explorers, alongside status and account reads;
- an allocation-free Rust contract SDK with tested wasm32 host bindings and bounded offline source-package reconstruction;
- an on-chain DNS registry with owner-authorized leases and a certified-proof resolver;
- operator CLI with genesis verification, validator/devnet provisioning and a native-payment wallet, a network-capable daemon, and pinned Rust contract build/source verification tools;
- CI, dependency-policy automation, contribution templates, project governance documents, and engineering specifications;
- a block production pipeline (`BlockProducer`) that coordinates mempool selection, deterministic execution, and storage commitment;
- a local demonstration service (`FullNodeService`) that simulates finality while coordinating execution and storage;
- a daemon with both local demonstration and certified fixed-committee network modes, bounded peer exchange, payment gossip, protected signing recovery, and RPC status tied to durable commits.

The repository now runs a **certified reference network** for native payments and fixed-committee BFT across independent daemon processes. A [reference CLI wallet](24-wallet-and-rpc-client.md) supports offline signing and real RPC submission. [Live genesis-v2 VRF rotation](40-live-vrf-network.md), standby participation and verified client catch-up are implemented. [Live PoTB activation](45-live-potb-network.md) is implemented. [Bounded historical state indexing](47-historical-state-index.md) and [quorum capacity/fee governance](48-parameter-governance.md) are implemented. [Explicit bounded history export and pinned recovery](49-pinned-history-retention.md) are implemented; automatic retention remains open. Certified state and receipt queries, authenticated finality waiting, on-chain DNS and bounded source-package tooling are implemented. Verified VRF selection, the WASM runtime and signed contract activation are implemented; see [VRF](28-vrf-and-weighted-selection.md), [runtime](29-parallel-payments-and-wasm.md) and [contracts](30-signed-contracts.md). See [network setup and current limits](19-reference-network.md).

## 8.2 Component status

| Area | State |
|---|---|
| Canonical codec | primitive, version-1 transaction, block-header, and receipt codecs implemented; strict lengths/flags, version/lane rejection, and transaction preflight validation tested; version-1 consensus vote/certificate and bounded reference-network envelopes implemented/tested; production compatibility qualification remains open |
| Shared protocol types | interface baseline |
| Genesis | bounded version-1 decoding, validated BLAKE2s commitment, account/validator state materialization, CLI verification, atomic daemon activation and restart identity checks implemented; exact genesis-key registry and explicit protected signer provisioning implemented |
| Cryptography and VRF | standard BLAKE2s-256 and strict Ed25519 implemented/tested; registered validator-key verification; strict registered-key RFC 9381 VRF verification/generation and RFC/malleability/context tests implemented |
| PoTB and BFT | checked committee commitments, registered Ed25519 vote authentication, bounded round-specific quorum collection, and independently verified version-1 certificates implemented/tested; protected local prevote/precommit locks, verified valid-round proofs, and timeout transitions implemented/tested; signed proposals and explicit reference round-robin designation implemented/tested; reference monotonic timers and fixed-committee daemon networking implemented/tested; verified VRF selection, complete contribution collection, certified handoff and rotating execution/history replay APIs and explicit PoTB daemon/client activation implemented; formal distributed liveness remains open |
| Keystore | single-key Ed25519 signer, bounded decision journal with protected watermark rollover, chain/genesis/key binding, monotonic watermark, atomic version-2 vote/lock records, process locking, restart and uncertain-write recovery implemented/tested; daemon open-only journal recovery and explicit CLI provisioning implemented/tested; encrypted wallet vaults and OS-generated keys implemented/tested; consensus key custody and anti-rollback anchors remain open |
| Transactions | canonical signing/ID commitments and state-aware signed validator implemented/tested; native signed payment transitions and fixed reference fees implemented/tested; version-1 envelope, inclusive expiry, signed lane/prices, and expiry eviction implemented/tested |
| Mempool | bounded in-memory reference admission and deterministic selection implemented/tested |
| State and storage | bounded Merkle state, membership and absence proofs, immutable snapshots, atomic transitions, file-backed state and whole-chain archive recovery, and authenticated snapshot exchange implemented/tested; daemon block/state restart recovery implemented/tested; native payment account transitions implemented/tested; append-only block/delta logs with disk history reads, atomic head publication and replay recovery are implemented/tested for new network directories; bounded recent transaction indexing and certified receipt recovery are implemented/tested; bounded historical state indexing is implemented; explicit pinned physical retention is implemented; automatic retention remains open |
| Runtime and execution | signed serial/parallel payments and ABI-v2 contract waves, bounded integer WebAssembly interpreter, staged writes/events and atomic publication; worker-count/error equivalence tested; explicit rotating-producer VRF system lane reserves resources and commits atomically; genesis-v2 daemon activation is implemented; quorum capacity/fee governance is implemented; alternate backends remain open |
| Sync, P2P, RPC, and node | node demonstration pipeline with staged proposal execution, atomic commit, retry preservation, and canonical transaction/receipt leaves; genesis-backed native payment admission/execution and daemon RPC implemented/tested; genesis-free admission and finality remain demonstrations; explicit producer certified proposal/commit APIs and a reference round-robin participant coordinate signed proposals, evidence, timeout events, and recovery; certified validator and non-voting observer networking over mutual TLS 1.3, transaction gossip, available-value persistence, full-history certificate authentication, sequential catch-up, scoped private-network discovery, bounded reusable sessions and authenticated observer export implemented/tested |
| Configuration | pure validation and debug redaction baseline |
| Telemetry | bounded fixed-cardinality operational counters and optional loopback Prometheus endpoint implemented/tested; measurements never enter consensus |
| Contracts | pinned Rust builds and artifact tools; signed deployment/calls under genesis profile 2, fee/nonce transitions and certified restart/catch-up tested; allocation-free SDK host bindings implemented/tested; bounded offline source packages and exact artifact reconstruction implemented/tested |
| DNS | bounded on-chain registry, ownership/lease transitions, confusable-name reservations, transaction preparation and certified-proof TCP resolver implemented/tested |
| CLI and daemon | CLI genesis verification; local daemon with file-backed block/state recovery, genesis activation, strict arguments, startup failure propagation, and durable RPC head; signed native payments and committed account/submission RPC implemented/tested; opt-in certified fixed-committee network, devnet provisioning, and standalone TLS identity provisioning implemented/tested; default local mode retains demonstration finality |

## 8.3 Removed architecture

The current design removes:

- C and C++ as first-party implementation languages;
- the C ABI as the primary module boundary;
- ALVM and its custom instruction set;
- Trocto, Regol, and Kreep contract languages;
- a general-purpose off-chain user storage/share service;
- claims that VRF is intentionally absent;
- historical implementation claims not represented by this Rust repository.

Validator-local persistence remains required and is named `storage`; it is not a user content service.

## 8.4 Planned milestones

### M1 — canonical foundations

Canonical encodings, domain tags, hashing, addresses, signatures, checked resource arithmetic, golden vectors, property tests, and fuzz targets.

The codec now rejects alternate length prefixes and non-canonical receipt flags, and validates transaction structure before allocating owned fields. Regression coverage includes golden bytes, every supported sequence length, every receipt flag, truncations, and transaction byte mutations. The standalone fuzz package includes the accepted-input re-encoding invariant for transactions, state keys, and receipts. The [version-1 transaction envelope](14-versioned-transactions.md) adds signed expiry, explicit lane, and prices; transaction encoder output changes and old archives fail closed. See [the current codec baseline](04-state-and-transactions.md#current-codec-baseline).

Standard hashing and signing backends, signed transaction IDs, address derivation, and checked resource pricing are implemented with conformance tests. These replace incompatible placeholder cryptographic outputs; see [suite and compatibility details](09-cryptographic-foundations.md). The daemon now supports explicitly selected authenticated fixed-committee networking; local mode retains demonstration certificates.

### M2 — state and transactions

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, diffs, sequential atomic commit, crash recovery, pruning, receipts, and snapshot exchange.

Implemented reference state commitments, membership and absence proofs, bounded versioned snapshots, atomic file-backed state publication, writer locks, recovery, verified snapshot exchange, and proposal rollback are described in [state and recovery](10-state-and-recovery.md). [Whole-chain archives](11-chain-archives.md) now persist blocks, certificates, checkpoints, and historical state atomically. Local daemon block/state restart integration is implemented with process and differential recovery tests. [Genesis activation](12-genesis-and-accounts.md) creates committed account balances/nonces and validator weights, installs a durable height-zero anchor, and validates genesis identity on restart. Recovered accounts are tested against signed admission. [Native payments](13-native-payments.md) implement sequential account transitions, fixed reference fees, atomic revalidation/publication, and daemon account/submission RPC with process restart tests. Versioned transaction policy is enforced at admission, proposal execution, and commit; expiry eviction follows successful durable publication. Durable consensus signing decisions now recover independently through the signing journal. Daemon signer integration and full-history certificate verification are implemented in the reference-network profile. [Append-only chain storage](22-append-only-chain-storage.md) removes whole-history rewrites and the archive checkpoint cap for new network directories, with legacy compatibility and fault/replay coverage. General execution/fee policy, production state indexing and retention remain open.

### M3 — deterministic runtime

Pinned Rust contract toolchain, target selection, validator, interpreter, host ABI, resource metering, SDK, reproducible artifacts, source verification, and differential execution.

### M4 — parallel execution

Deterministic waves, Adaptive Execution Leasing, lanes, optimistic access validation, replay bounds, locality, fusion, prefetch, caches, pools, and signature batches.

Bounded execution-parent caching and borrowed-key wave planning are implemented
with uncached/serial differential tests and deterministic read-count checks;
[scope and limits](29-parallel-payments-and-wasm.md#execution-parent-cache-and-planner-allocation).
Fusion, prefetch, worker/object pools and signature batching remain open.

### M5 — consensus

PoTB transitions and evidence, audited VRF provider, unbiased weighted sampler, partial committee rotation, producer selection, prevote/precommit state machine, certificates, durable anti-equivocation, formal models, and adversarial simulations.

The [authenticated finality layer](15-authenticated-finality.md) verifies registered keys, chain/height/committee-bound vote digests, and weighted precommit certificates. The collector retains one round, rejects duplicate nil votes, distinguishes authenticated equivocation, and never combines weights across rounds or phases. Certified producer commits authenticate finality before existing execution/storage checks, with failed-write retry and restart verification tests. The [durable signing journal](16-durable-signing.md) now reserves a chain/genesis/key-bound decision before returning an Ed25519 signature, blocks stale coordinates, and recovers after process exit. Typed vote signing maps wire phases to protected journal coordinates. Protected journals now support [bounded rollover](23-signing-journal-rollover.md), preserving their immutable prefix and inode lock while continuing past 100,000 decisions. The [local BFT guard](17-local-bft-voting.md) now verifies prevote proofs, preserves locks through nil votes/timeouts and restarts, and reserves locks atomically with signatures. Read-only producer validation and a payment/vote/certificate/archive integration test exercise execution before signing and publication after finality. [Signed proposals and a reference participant](18-signed-proposals-and-participants.md) now authenticate designation, persist proposal reservations, coordinate execution/voting/commit, and recover across round changes and failed storage writes. The [reference network driver](19-reference-network.md) integrates daemon voting, timers, signer provisioning, durable available values, and certified synchronization. Mutually authenticated TLS 1.3 and independent transport provisioning are implemented; see [transport security](20-authenticated-transport.md). Verified weighted VRF selection, [authenticated handoff and rotating execution/recovery APIs](38-authenticated-committee-handoff.md) are implemented; genesis-v2 daemon activation is implemented; production qualification remains open.

### M6 — P2P and node

Authenticated encrypted transport, peer discovery, rate limits, compact blocks, finalized sync, bounded queues, pipelining, speculation, external RPC, telemetry, and finalized adaptive-capacity observations.

[Non-voting full nodes](21-observer-nodes.md) now verify and serve certified history, re-execute imported blocks, relay payments, and recover without consensus keys. Observer provisioning and actual TLS/RPC process tests are implemented.

### M7 — ecosystem

Wallet integration and DNS registry/resolver.

[Native-payment CLI signing and a bounded RPC client](24-wallet-and-rpc-client.md)
are implemented/tested, including devnet funding, signature inspection, submission
failure handling and real finalized account queries. Encrypted wallet custody,
certified state/receipt queries, authenticated finality waiting and on-chain DNS are implemented/tested; see [receipt behavior](35-certified-receipts.md).

### M8 — production gates

Distributed calibration, interoperability suite, long fuzz campaigns, reproducible releases, dependency audit, independent cryptography/consensus/runtime/security reviews, key ceremonies, and incident/operator runbooks.

Supported fixed/rotating wire histories retain 50 frozen compatibility fixtures. The explicit PoTB producer profile adds eight separate fixtures with authenticated replay and independent Python checks. The shared deterministic mutation corpus now uses 81 seeds and passes one million inputs; [scope](41-protocol-compatibility.md) and [live PoTB qualification](45-live-potb-network.md).

The concise checklist is maintained in [`../ROADMAP.md`](../ROADMAP.md).

## 8.5 Required continuous gates

Every protocol change must pass formatting, Clippy with warnings denied, unit/integration/doc tests, canonical serialization compatibility, cross-platform deterministic fixtures, and documentation-link checks. Relevant changes additionally require property testing, fuzzing, recovery tests, and optimized/reference differential checks.

Unsafe Rust remains forbidden except in the dedicated wasm32 FFI module; [documented binding review](../crates/contract-abi/SAFETY.md). CI currently covers Linux and Windows quality checks; dependency policy and advisory workflows are configured separately.

## 8.6 Open decisions

Before production implementation, resolve:

1. Adversarial contribution/evidence availability and formal safety/liveness. Capacity/fee governance uses more than two thirds of incumbent weight with next-epoch activation; [implementation](48-parameter-governance.md). The [live PoTB profile](45-live-potb-network.md), candidate provisioning and incumbent-quorum admission CLI are implemented. [Bounded delivery simulations](46-rotating-network-simulations.md) cover both rotating profiles; broader Byzantine/churn schedules remain open.
2. Alternative availability policies beyond the implemented complete-roster private-network profile.
3. Rotating weighted BFT lock, unlock, timeout, and handoff rules.
4. Versioned activation of future protocol changes; current encoding/hash compatibility is fixed by the [literal corpus](41-protocol-compatibility.md).
5. Cross-platform contract artifact qualification; bounded offline source reconstruction, ABI-v2 WebAssembly, its host SDK and Rust 1.99.0 builds are implemented.
6. Production state indexing and concrete durable chain database engine; the reference Merkle commitment is specified.
7. Transaction ordering, anti-MEV policy and lane borrowing; versioned fee governance is implemented.
8. Adaptive-capacity observation, manipulation resistance, and activation.
9. P2P transport, discovery, topology, identities, and denial-of-service bounds.
10. Deployment-specific DNS lease pricing; deterministic naming, ownership and lease rules are implemented.
11. Supported platforms, compatibility lifecycle, release signing, and maintainer authority.

## 8.7 Non-negotiable correctness properties

- Finalized transaction order is unique at each height.
- A finality certificate represents voting power strictly greater than two thirds.
- Committee selection is publicly verifiable and proportional to finalized PoTB weight under the specified sampler.
- Parallel, sequential, speculative, fused, cached, AOT, JIT, SIMD, and portable paths agree.
- Adaptive capacity cannot be changed by one node's local measurements.
- Canonical state is published only after finality and execution commitments validate.
- Sync and snapshot imports remain staged until verified.
- Configuration and logs do not expose secret key material.
- Ecosystem services cannot access validator signing authority.
