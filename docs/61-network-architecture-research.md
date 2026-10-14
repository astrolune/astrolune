<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 61. High-Performance Network Architectures and the AstroLune Development Plan

Research dates: October 14–15, 2026, Europe/Moscow. Source revision:
`cfd94fd640051855bf6a1c3e6c445b815e817b99`.

**Status: research document, not a normative protocol change.**
This stage provides a comparative analysis, local measurements, decisions on which
mechanisms to adopt, and experiment designs. It introduces no changes to Rust code
or network rules. Original candidates are described in
[document 62](62-original-architecture-proposals.md).

## Implications for the project

State and execution costs come first, followed by data propagation and finality.
AstroLune already has parallel execution, access lists, prefetching, compact
transport, an AOT cache, and bounded overlap between processing stages. New names
for these existing mechanisms would not create a technical advantage.

The practical sequence is: reproducible benchmark environment → incremental state
and removal of unnecessary dependencies → execution without global wave barriers →
original experimental mechanisms → distributed comparison. There is no reason to
change PoTB for branding or remove checks to increase TPS.

PoTB is a short, distinctive name worth retaining. Under the current
[specification](01-consensus-potb.md), it determines validator weight; VRF selection
and BFT with prevote/precommit follow. The system's name should not obscure this
separation. New execution mechanisms do not need to be named Proof-of-something.

## Distinctive architectures in other networks

Here, “distinctive” describes a characteristic architecture, not proof of global
priority. Whitepaper versions, deployed implementations, and activation plans
differ. Promotional TPS figures are not used to rank networks.

| Network / direction | Architectural idea | What it accelerates and what limits it | Decision for AstroLune |
|---|---|---|---|
| Solana: Sealevel | Explicit read/write access; concurrent execution of independent transactions | Removes false read–read dependencies; writes to the same account remain dependent | Adopt more precise access classification; access lists already exist |
| Solana: Turbine, Alpenglow | Erasure-coded propagation; Alpenglow separates Votor and Rotor | Reduces leader load and voting latency; changes the failure model and availability requirements | Investigate transport separately; do not transplant voting thresholds into PoTB |
| TON | Dynamic shardchain splitting/merging and asynchronous messages between shards | Distributes state and computation; a cross-contract operation may require several messages | Adopt locality and bounded queues; defer full sharding |
| TON: Catchain 2.0 / Simplex | Leader slots, notarization/finalization, and skip handling | Shortens agreement; correctness depends on precise rules and configuration | Use as input to separate BFT research, not as a drop-in replacement |
| Aptos | Block-STM: speculative execution, state versions, dependency detection, and retries | Does not require precise access lists in advance; conflicts cause extra work | Adopt targeted conflict handling if profiling justifies the complexity |
| Sui | Objects with explicit ownership/sharing; Mysticeti DAG consensus | The object model exposes independence; shared objects remain contention points | Adopt application data-design principles; no full state-model migration is needed |
| Monad | Parallel execution, consensus/execution overlap, and specialized MonadDb | Overlaps computation and I/O; delayed execution requires its own reserve-balance rules | Adopt local overlap and state engineering; defer the delayed-root protocol |
| NEAR | Nightshade and stateless validation with witnesses | Distributes load across shards and reduces state requirements for validators; witnesses consume bandwidth | Revisit after scaling a single validator and measuring the network |
| Avalanche | Snowman: repeated subsampled polling and a probabilistic safety model | Reduces communication in the common case; uses a different finality model | Do not substitute it for PoTB certificates with a >2/3 quorum |
| Ethereum | Separation of execution and data availability, blobs / the DAS direction | Scales data availability for rollups; does not directly accelerate L1 execution | Separate DA and execution metrics; do not adopt the full stack now |
| Eclipse / AlDBaran | Specialized state commitments, separating the hot path from historical proofs | Reduces state-update cost; proof formats and persistence need separate verification | A high-priority reference for the state backend; updates/s are not network TPS |

Primary sources for the table:

- [Solana: Sealevel](https://solana.com/news/sealevel---parallel-processing-thousands-of-smart-contracts).
- [Anza: Alpenglow, Votor, and Rotor](https://www.anza.xyz/blog/alpenglow-a-new-consensus-for-solana).
- [TON: sharding](https://docs.ton.org/foundations/shards),
  [Simplex](https://docs.ton.org/foundations/whitepapers/simplex),
  [configuration](https://docs.ton.org/foundations/config).
- [Aptos: execution](https://aptos.dev/network/blockchain/execution),
  [Block-STM research](https://arxiv.org/abs/2203.06871).
- [Sui: consensus](https://www.docs.sui.io/develop/sui-architecture/consensus),
  [current transaction lifecycle](https://docs.sui.io/develop/transactions/transaction-lifecycle).
- [Monad: parallel execution](https://docs.monad.xyz/monad-arch/execution/parallel-execution),
  [asynchronous execution](https://docs.monad.xyz/monad-arch/consensus/asynchronous-execution),
  [MonadDb](https://docs.monad.xyz/monad-arch/execution/monaddb).
- [NEAR: Nightshade 2.0 and stateless validation](https://www.near.org/blog/nightshade-2-launches-on-near-mainnet-introducing-stateless-validation).
- [Avalanche: consensus protocols](https://build.avax.network/docs/nodes/architecture/consensus).
- [Ethereum: danksharding](https://ethereum.org/roadmap/danksharding/).
- [AlDBaran: the authors' research](https://arxiv.org/abs/2508.10493).

### Corrections to common summaries

1. The 2019 Sealevel article explains the principle; it is not a reference for
   current TPS or the complete implementation of a deployed Solana client. Anza's
   Alpenglow latency estimates are based on simulation without computation
   overhead. The materials reviewed here are not treated as confirmation that
   Alpenglow has been activated on mainnet.
2. TON cannot be described solely through legacy Catchain: official materials
   include Simplex and parameter 30. The specific masterchain/shardchain mode
   depends on configuration; code or a parameter's existence does not establish
   activation everywhere.
3. Current Sui documentation explicitly states that Mysticeti sequences all
   transactions. The historical consensus-bypass path for owned objects must not
   be presented as an unconditional description of the current path.
4. Snowman is the current reference for Avalanche's Primary Network; the old
   description of X-Chain as a DAG does not reflect its linearization.

## What the code actually implements

| Area | Verified implementation | Implication |
|---|---|---|
| Scheduling | [scheduler.rs](../crates/execution/src/scheduler.rs): earliest wave after prior access to a key/sender; all access-list keys are treated as Write | Potential false dependencies on shared code and read-only data |
| Execution | [parallel_payment.rs](../crates/execution/src/parallel_payment.rs): bounded worker pool per attempt, barriers between waves, singleton-wave fusion, serial replay after speculative failure | More workers alone do not resolve dependencies; a long transaction can delay a narrow wave |
| Contracts | [contract.rs](../crates/execution/src/contract.rs): calls read the code key, deployment writes it; `ArtifactCache` is already used | Access can be refined where semantics establish it; no need to reinvent the AOT cache |
| State | [memory.rs](../crates/state/src/memory.rs), [snapshot.rs](../crates/state/src/snapshot.rs), [commitment.rs](../crates/state/src/commitment.rs): map copying, size scanning, and full Merkle rehashing | Cost depends on the entire state, not just changed keys |
| Commitments | Sorted leaves; proofs include the index and leaf count | Insertions/deletions shift positions; replacing the structure with a Patricia trie would change roots and proofs |
| Transport | [Document 54](54-compact-blocks-and-execution-pipeline.md): optional compact exchange with full 32-byte IDs and bounded fallback | Already implemented, but not Turbine/Rotor; measure reconstruction hit rate first |
| Overlap | [producer/pipeline.rs](../crates/node/src/producer/pipeline.rs): detached execution, exact-context reuse, private staged state | Cache hits do not replace certificate verification or final durable publication |
| Rotation | [Document 40](40-live-vrf-network.md): a verified batch and next-committee cache already exist | Simple “PoTB/VRF caching” would not be a new mechanism |
| Limits | Producer defaults to 256 tx/block; reference state is limited to 1,048,576 entries and a 64 MiB snapshot | Larger throughput/state experiments require coordinated limit changes, not a single constant edit |

Document 56 contains historical observations, some predating the AOT cache.
Current code and the fresh run take precedence. A `prefetch` method does not
establish a performance benefit: it is a no-op in `InMemoryState`.

## Fresh local baseline

[Full log](assets/architecture-research-2026-10-14/baseline.log) and
[machine-readable results with environment metadata](assets/architecture-research-2026-10-14/baseline.json).

AMD Ryzen 7 7800X3D; 8 logical processors visible to the process; Windows
10.0.26200; rustc 1.99.0; optimized bench profile; 7 rounds, target 1000 µs.
RAM capacity was not verified in this run because CIM was unavailable. The host
was not isolated from background load. This is one run; the table reports medians
of batch means.

| Operation | Median | Supported interpretation |
|---|---:|---|
| 128 independent transfers, serial | 5.6113 ms | Baseline fixture cost |
| Same transfers, 4 workers | 2.2304 ms | About 2.52× faster than serial in this run |
| Same transfers, 8 workers | 2.1494 ms | About 2.61×; not network TPS |
| 128 dependent transfers, serial | 5.7541 ms | A dependent chain |
| Same chain, 8 workers | 6.1455 ms | No observed speedup |
| 16 independent contract calls, serial / 4 workers | 0.8520 / 0.6133 ms | About 1.39× for this workload shape |
| State prepare: 4096 entries, 1 change | 2.3109 ms | The full scan is noticeable even with a small diff |
| State prepare: 4096 entries, 256 changes | 2.3888 ms | Cost is close to the preceding case; this is not a statistical test of equality |
| Full state root, 16 / 256 / 4096 entries | 0.008339 / 0.135350 / 2.445100 ms | Growth is consistent with a full scan |

The execution benchmark's `shared_code` fixture shares the code key **and writes
to the same contract key `k`**. Its 16 singleton waves cannot be attributed solely
to overly conservative code access. Evaluating a read/write optimization requires
a new fixture: one code key, distinct senders, and disjoint state keys.

This run measures neither p99, durable commit, nor network TPS. The log's `ops/s`
counts complete benchmark operations, each of which may contain many transactions.
Unit tests marked ignored in `cargo bench` output are not counted as passed.

Reproduce in PowerShell (this host's PATH selects rustc 1.93.1 first):

```powershell
$env:RUSTC = (rustup which --toolchain 1.99.0 rustc).Trim()
$env:RUSTDOC = (rustup which --toolchain 1.99.0 rustdoc).Trim()
$env:ASTROLUNE_BENCH_ROUNDS = '7'
$env:ASTROLUNE_BENCH_TARGET_US = '1000'
rustup run 1.99.0 cargo bench --locked -p state -p execution
```

## Adoption priorities

These are selected directions for the next stage, not optimizations already implemented.

| Priority | Change | Compatibility and acceptance criteria |
|---|---|---|
| P0 | E2E benchmark environment: from signed transaction submission to a verifiable receipt after durable commit | Separate queueing, verification, execution, root, consensus, and storage times; retain raw samples |
| P1 | Cached Merkle levels and persistent/COW state for updates to existing keys | Byte-identical existing roots/proofs; reference fallback for initial insertion/deletion support; also eliminate full-map copying and full size scans |
| P1 | Semantically precise read/write access | Start with the code key of an ordinary Call; Deploy remains Write; unknown cases remain conservative; add a disjoint-state fixture |
| P2 | Readiness graph instead of a global wave barrier | Preserve RAW/WAR/WAW, nonce, and all implicit account accesses; results, gas, first error, and atomicity must match serial execution |
| P2 | Long-lived bounded workers and a threshold for beneficial parallelism | Check small blocks, failures, shutdown, and memory bounds; acceleration must not change results |
| P3 | Prefetching for a real backend and bounded hashing/execution overlap | Cold/warm disk scenarios; disclose RAM/I/O growth; do not claim an in-memory no-op as a speedup |
| P3 | Compact propagation tuning, then bounded erasure-coded transport if a bottleneck is established | Measure bytes/finalized tx, fallback, and p99 first; test Byzantine withholding, amplification, and malformed fragments |
| R&D | VeyraFold and LuneSeal | Separate experimental paths with the stopping conditions in document 62 |

Full signed read/write lists change the wire format and lease validation, so they
require a separate versioned proposal. Deriving a read-only code key from verified
Call semantics may be possible without changing the format. Even then,
differential tests must come first, including deploy→call and call→later conflict.

Do not adopt yet: global TON/NEAR sharding, Sui's object model, replacing PoTB with
Mysticeti/Snowman, Monad's delayed state roots, or unrestricted JIT enabled by
relaxing the unsafe policy. These are separate architectural migrations with
different obligations.

## Evaluating a “fastest network” claim

The claim must specify the workload class and conditions. One leaderboard cannot
combine transfers, contended contracts, DA bandwidth, and finality latency.

The primary metric is **unique, successfully executed user transactions with
verifiable finalized receipts and completed durable publication per second,
subject to a p99 bound and a stable queue**. Count votes, retries, rejected
transactions, and internal messages separately. For TON, also distinguish messages,
account transactions, and completed user operations.

Minimum experiment matrix:

- Independent transfers; one hot recipient; one hot sender; an A→B→C funding
  chain; self-transfers.
- One contract with distinct keys; one shared key; mixed payments/contracts;
  expensive WASM; invalid signatures and late failures.
- State sizes of 10k, 100k, and up to the supported limit; larger profiles only
  after explicitly expanding backend/protocol limits. Separate existing-key
  updates from insertion/deletion churn.
- 4/16/64 validators where the profile supports the size; loopback, LAN, and at
  least three geographic regions. Record CPU, RAM, NVMe, bandwidth, stake/weights,
  client versions, durability, and genesis. Do not silently bypass profile limits.
- Packet loss of 0/0.1/1%, slow disks, an unavailable leader, PoTB rotation,
  restarts, withholding, and recovery after a network partition.

Use an open-loop generator with scheduled submission times so overload does not
disappear from latency measurements. Identify duplicates by canonical transaction
ID; also count rejected, pending, and timed-out requests. Measure submit→receipt
with one client's monotonic clock; account for clock error in internal cross-host
stage measurements.

Initial plan: 2 minutes of warmup, 10 minutes of steady state, 5 independent
repeats, an offered-load sweep, and the same seeds/workloads. This is a proposed
experiment protocol, not a completed run. Publish per-transaction p50/p95/p99,
goodput, queue growth, abort/replay rate, CPU, peak RSS, bytes/tx, fsync latency,
confidence intervals across independent repeats, and all configurations.

Comparisons with other clients require matching operation semantics and completion
guarantees. Where that is impossible, publish explicitly separate profiles.
Do not compare AstroLune local execution with another network's WAN finality.
At 256 tx/block, the theoretical ceiling is
`256 / mean finalized-block interval`; increasing the limit alone does not reduce
computation, transmission, or durable commit costs.

## Outcome of this stage

The comparison and local baseline are complete. Applicable mechanisms to adopt
and two specific research designs have been selected. Their implementation,
novelty validation, external audit, and a winning distributed comparison remain
outstanding.
