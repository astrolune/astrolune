<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 2. Rust Architecture, Networking, and Capacity

## 2.1 Language and safety rules

All first-party AstroLune components use Rust 2024. Workspace crates forbid unsafe Rust. A future narrowly scoped exception is allowed only in a dedicated audited crate for a measured requirement such as SIMD, zero-copy operating-system I/O, or cryptographic FFI. It must expose a safe interface, document invariants, retain a portable fallback, and receive explicit review.

Rust ownership prevents many memory bugs but does not create consensus determinism automatically. Deterministic encodings, ordered collections, bounded allocation, checked arithmetic, and explicit failure behavior remain protocol requirements.

## 2.2 Workspace boundaries

### Foundation and protocol

| Package | Responsibility | Current status |
|---|---|---|
| `codec` | canonical bounded encoding primitives | primitive, transaction, header, receipt, vote/certificate and network-envelope codecs implemented and tested |
| `types` | shared hashes, addresses, resources, transactions, blocks, receipts | interface baseline; the length-framed domain hash helper is implemented and tested |
| `crypto` | hashing, signature, and VRF provider boundary | BLAKE2s-256, strict Ed25519, RFC 9381 ECVRF and bounded parallel strict verification implemented and tested |
| `genesis` | chain parameters and initial validator/allocation validation | bounded version-1 decoding, validated commitment, state materialization and restart identity checks implemented and tested |
| `transaction` | staged transaction validation and lane assignment | canonical commitments, state-aware signed admission and native payment transitions implemented and tested |
| `consensus` | PoTB weights, committee rotation, votes, and BFT finality | PoTB transitions, authenticated votes/certificates, protected local voting, signed proposals, verified weighted VRF selection and certified handoff implemented and tested |
| `keystore` | purpose-separated signer and anti-equivocation boundary | Ed25519 signer, protected decision journal with watermark rollover, encrypted vaults and an independent rollback anchor implemented and tested |

### State, execution, and node

| Package | Responsibility | Current status |
|---|---|---|
| `state` | leases, immutable snapshots, diffs, database API | bounded Merkle state, immutable snapshots, membership/absence proofs and atomic transitions implemented and tested |
| `runtime` | canonical contract modules, interpreter and ahead-of-time backends | integer WebAssembly ABI v2 interpreter and a bounded ahead-of-time artifact cache implemented and tested, qualified field for field including charged compute; no backend emits native machine code, and a just-in-time backend is impossible while `unsafe_code` is forbidden |
| `execution` | waves, lanes, scheduling, optimistic execution | signed serial/parallel payments, ABI-v2 contract waves, lease-preserving wave planning and worker-count equivalence implemented and tested |
| `mempool` | bounded local admission and deterministic selection policy | bounded in-memory admission and deterministic selection implemented and tested |
| `storage` | validator-local finalized chain/state persistence | append-only block/delta log, whole-chain archives, atomic publication and replay recovery implemented and tested |
| `sync` | finalized blocks and snapshot synchronization | header, block and snapshot-manifest verification implemented and tested; the catch-up state machine itself lives in `node` |
| `p2p` | binary frames and compact blocks | bounded binary envelopes, peer exchange and optional compact blocks implemented and tested |
| `rpc` | external wallet and application API | status, account, submission, block-history, receipt and proof endpoints implemented and tested; public-network hardening open |
| `config` | validated configuration and secret references | pure validation and debug redaction implemented and tested |
| `telemetry` | local-only metrics sink | bounded fixed-cardinality counters and an optional loopback Prometheus endpoint implemented and tested |
| `node` | subsystem pipeline and adaptive-capacity coordination | certified validator and observer networking, staged proposal execution, atomic commit and recovery implemented and tested |

### Products, SDK, and tests

| Package | Responsibility |
|---|---|
| `contract-sdk` | deterministic Rust contract host API |
| `testkit` | deterministic fixtures and the bounded benchmark harness |
| `integration` | workspace-level conformance tests |
| `daemon` | node daemon entry point |
| `cli` | operator and developer CLI |
| `cargo-contract` | pinned contract builds, artifact verification and source packages |
| `dns` | authenticated in-network names |

Dependency direction flows from products and orchestration toward narrow primitives. Consensus does not depend on a database engine, socket runtime, RPC transport, telemetry sink, or native compiler. P2P moves canonical messages and does not execute blocks.

## 2.3 Specialized binary P2P protocol

Consensus traffic uses a versioned bounded binary protocol rather than JSON-RPC, gRPC, or an application RPC framework. External APIs remain separate and cannot inject pre-decoded trusted values into consensus.

A frame contains fixed magic/version fields, chain identity, message kind, flags, canonical payload length, payload, and integrity/authentication data. Decoders MUST reject unknown mandatory flags, non-minimal lengths, oversized frames, truncation, trailing bytes, and incompatible chain identity before allocating according to attacker input.

Message families include handshake, transaction announcement/request, compact block, missing transactions, proposal, prevote, precommit, finality certificate, peer exchange, and bounded synchronization. Validated frame payloads remain borrowed from receive buffers until their lifetime requires ownership.

## 2.4 Efficient block propagation

A producer announces a compact block with its full header, ordered short transaction identifiers, and prefilled transactions expected to be missing. A peer reconstructs from its mempool and requests only missing or ambiguous transactions.

Short identifiers are keyed by block-specific entropy. Reconstruction verifies the complete ordered transaction root. Collision, ambiguity, or timeout falls back to explicit hashes or a bounded full block.

## 2.5 Adaptive block capacity

Capacity covers compute, memory, state I/O, and bandwidth. It changes slowly using a finalized observation window.

Local CPU, network, disk, and memory measurements cannot directly modify block validity. They may inform signed observations, but the protocol accepts only quantized finalized inputs with specified sample count, robust aggregation, outlier handling, movement bounds, absolute floors/ceilings, activation delay, and conservative missing-data behavior.

Adaptive sizing stays inactive until manipulation resistance and the exclusion of slower honest validators are analyzed.

## 2.6 Node pipeline

```text
network ingress
  -> bounded frame and canonical decoding
  -> transaction validation and signature batches
  -> bounded mempool and locality indexing
  -> compact proposal reconstruction
  -> PoTB committee proposal, prevote, and precommit
  -> immutable parent-state snapshot
  -> deterministic parallel execution and conflict replay
  -> receipt, resource, and state commitment checks
  -> atomic validator-local finalized commit
  -> external RPC and ecosystem notifications
```

Every queue has item and byte limits. Consensus messages use reserved priority so transaction traffic cannot starve finality. Synchronization imports into staging and publishes only verified finalized data.

## 2.7 Batch and zero-copy processing

Ingress groups compatible signature and hash checks into batches. Workers may verify in parallel and an audited provider may use SIMD. Results return to original order before admission.

Network buffers flow through framing, canonical validation, hashing, and decoding as borrowed slices. Copies occur only at encryption/decompression, alignment, lifetime, ownership, or persistence boundaries. A state backend may expose guarded borrowed data only when compaction cannot invalidate a live snapshot.

## 2.8 Runtime and execution separation

`runtime` validates and executes canonical Rust contract modules through the portable interpreter or the ahead-of-time backend, which translates each module before any call budget exists and reuses the retained artifact. `execution` schedules transactions, enforces access leases, validates observed conflicts, and creates ordered state diffs. Retained artifacts are local cache entries, not consensus data, and the backend a node selects cannot change a charged resource or a canonical result.

## 2.9 Storage meaning

`storage` persists validator blockchain data: finalized blocks, certificates, state objects, checkpoints, and snapshots. It is not the intentionally removed general-purpose user storage/share service and creates no storage economy.

## 2.10 API, configuration, keys, and observability

External RPC, administration, DNS use separately bounded listeners. Configuration contains references to secrets rather than secret values. Consensus, network, service, and wallet keys have distinct purposes. Telemetry is best-effort local output and cannot feed consensus decisions.
