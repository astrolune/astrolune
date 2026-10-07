<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 0. Project Overview

## 0.1 Purpose

AstroLune is a high-throughput blockchain built in Rust. Its primary consensus model is Proof of Trusted Behavior (PoTB): finalized network behavior produces validator weight, and weighted verifiable randomness selects committee participation. A fast BFT protocol finalizes transaction order while a separate deterministic execution pipeline computes state transitions.

Performance is a first-class requirement, but no optimization may weaken determinism, verification, isolation, bounded resource use, or protocol safety.

## 0.2 Required capabilities

### Consensus and networking

- PoTB-derived voting and selection weight.
- Weighted VRF committee selection.
- Partial committee rotation, initially targeting approximately 10% per block.
- Prevote/precommit BFT finality with a quorum strictly greater than two thirds.
- Consensus/execution decoupling.
- Leader and producer pipelining for the next height.
- Overlapped propagation, voting, execution, and commit stages.
- A bounded binary P2P protocol for consensus traffic.
- Compact-block reconstruction and missing-transaction recovery.
- Adaptive block capacity derived deterministically from finalized observations.

### Transaction execution

- Parallel execution of independent transactions.
- Deterministic scheduling and deterministic conflict recovery.
- Adaptive Execution Leasing through declared state access lists.
- State access scheduling into conflict-free waves.
- Predictive conflict estimation as a non-consensus optimization.
- Multiple execution lanes for payment, contract, and system workloads.
- Optimistic parallel execution with observed-access validation.
- Transaction fusion for compatible operations without changing individual receipts.
- Transaction locality for cache-efficient ordering within consensus constraints.
- Speculative execution of likely next-block contents.

### State and runtime

- Hot/cold state placement as a local database policy.
- Batched reads, caches, sequential writes, and optimized indexes.
- Immutable state snapshots for parallel reads without global locks.
- State diffs followed by a separate deferred commit stage.
- Multi-level caches and state prefetching.
- Optional future state sharding inside one execution domain; not part of the baseline.
- Batch transaction processing and parallel signature verification.
- SIMD acceleration where an audited library and deterministic fallback exist.
- Execution-plan and compiled-contract caches.
- Memory and object pools on measured hot paths.
- Zero-copy borrowed network frames and minimized transaction/state copying.
- Deterministic AOT compilation and optional local JIT compilation.
- Native artifact caching keyed by code, compiler, target, and metering versions.
- Metering by compute, memory, state I/O, and bandwidth classes.

## 0.3 Determinism envelope

Canonical inputs MUST produce identical block, receipt, event, resource-use, and state commitments on every conforming node. Consensus-visible code therefore MUST NOT depend on:

- floating-point results;
- wall-clock time or thread scheduling;
- hash-map iteration order;
- local CPU, memory, disk, or network measurements;
- cache hits, prediction success, SIMD availability, JIT availability, or worker count;
- ambient filesystem, network, process, or operating-system state.

Optimizations may alter latency, never accepted results. Every optimized path needs a deterministic verifier or fallback.

## 0.4 Scope

The first engineering phase provides compileable Rust interfaces and a coherent repository layout. It does not implement consensus cryptography, a production state database, a VM, networking, or services.

AstroLune includes DNS for authenticated in-network names. It explicitly excludes a general-purpose distributed storage or file-sharing product. Validator state persistence remains necessary node infrastructure and is not the removed storage service.

## 0.5 Names

The product name is **AstroLune**. Rust crates and binaries use lowercase package names such as `consensus` and `daemon`. Protocol domain tags use versioned lowercase identifiers such as `astrolune.vote.v1`.
