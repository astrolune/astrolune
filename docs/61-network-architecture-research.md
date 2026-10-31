<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 61. AstroLune Architecture Research and Development Plan

Research dates: October 14–15, 2026, Europe/Moscow. Source revision:
`cfd94fd640051855bf6a1c3e6c445b815e817b99`.

**Status: research document, not a normative protocol change.**
This stage assesses AstroLune architecture, records local measurements, and
defines development priorities and experiment designs. It introduces no changes
to Rust code or network rules. Original candidates are described in
[document 62](62-original-architecture-proposals.md).

Subsequent implementation: the state-backend portion of P1 is described in
[document 63](63-incremental-state.md), and precise code access plus readiness
dispatch are described in [document 64](64-trocto-native-llvm.md). The research
tables and measurements below retain the revision stated above; the separate
implementation update distinguishes them from current execution semantics.

## Implications for the project

State and execution costs come first, followed by data propagation and finality.
AstroLune already has parallel execution, access lists, prefetching, compact
transport, an AOT cache, and bounded overlap between processing stages. New names
for these existing mechanisms would not create a technical advantage.

The practical sequence is: reproducible benchmark environment → incremental state
and removal of unnecessary dependencies → execution without global wave barriers →
original experimental mechanisms → distributed qualification. There is no reason to
change PoTB for branding or remove checks to increase TPS.

PoTB is a short, distinctive name worth retaining. Under the current
[specification](01-consensus-potb.md), it determines validator weight; VRF selection
and BFT with prevote/precommit follow. The system's name should not obscure this
separation. New execution mechanisms do not need to be named Proof-of-something.

## Architectural directions for AstroLune

Each direction is evaluated against AstroLune transaction semantics, PoTB weights,
VRF selection, certified finality, and durable publication. A faster processing
stage is useful only when it preserves these guarantees and improves the complete
execution path.

| Direction | Potential benefit and limit | Development decision |
|---|---|---|
| Precise read/write access | Independent reads can run together; writes to the same key remain ordered | Refine access classification where verified call semantics establish it |
| Bounded coded propagation | Reduces repeated transmission; missing fragments and withholding require explicit recovery | Measure compact-exchange fallback and leader bandwidth before adding coding |
| State locality and bounded queues | Reduces working-set and scheduling costs; cross-region operations still need ordered effects | Improve locality within the current state model before considering partitioning |
| Targeted conflict handling | Avoids unnecessary global replay; speculation can add work under contention | Preserve the serial error order and require workload evidence before activation |
| Execution and storage overlap | Hides some computation and I/O latency; staged results must remain private | Keep exact-context checks and publish only through the certified durable commit |
| Cached state commitments | Reuses unchanged subtrees; insertion and deletion affect sorted-leaf positions | Preserve existing roots and proof formats, with explicit fallback |
| Separate propagation and execution metrics | Identifies the actual bottleneck; bandwidth alone does not establish executed throughput | Measure successful finalized user operations and every completion stage |

## Implementation at the research revision

This table records the October 14 baseline. Its write-only scheduling and
between-wave barriers have since been replaced for canonical code access and
mixed dependency plans, as described in the following update.

| Area | Verified implementation | Implication |
|---|---|---|
| Scheduling | [scheduler.rs](../crates/execution/src/scheduler.rs): earliest wave after prior access to a key/sender; all access-list keys are treated as Write | Potential false dependencies on shared code and read-only data |
| Execution | [parallel_payment.rs](../crates/execution/src/parallel_payment.rs): bounded worker pool per attempt, barriers between waves, singleton-wave fusion, serial replay after speculative failure | More workers alone do not resolve dependencies; a long transaction can delay a narrow wave |
| Contracts | [contract.rs](../crates/execution/src/contract.rs): calls read the code key, deployment writes it; `ArtifactCache` is already used | Access can be refined where semantics establish it; no need to reinvent the AOT cache |
| State | [memory.rs](../crates/state/src/memory.rs), [snapshot.rs](../crates/state/src/snapshot.rs), [commitment.rs](../crates/state/src/commitment.rs): map copying, size scanning, and full Merkle rehashing | Cost depends on the entire state, not just changed keys |
| Commitments | Sorted leaves; proofs include the index and leaf count | Insertions/deletions shift positions; replacing the structure with a Patricia trie would change roots and proofs |
| Transport | [Document 54](54-compact-blocks-and-execution-pipeline.md): optional compact exchange with full 32-byte IDs and bounded fallback | Already implemented; measure reconstruction hit rate and fallback cost first |
| Overlap | [producer/pipeline.rs](../crates/node/src/producer/pipeline.rs): detached execution, exact-context reuse, private staged state | Cache hits do not replace certificate verification or final durable publication |
| Rotation | [Document 40](40-live-vrf-network.md): a verified batch and next-committee cache already exist | Simple “PoTB/VRF caching” would not be a new mechanism |
| Limits | Producer defaults to 256 tx/block; reference state is limited to 1,048,576 entries and a 64 MiB snapshot | Larger throughput/state experiments require coordinated limit changes, not a single constant edit |

Document 56 contains historical observations, some predating the AOT cache.
The run below records this research revision; current behavior is described in
the implementation update. A `prefetch` method does not
establish a performance benefit: it is a no-op in `InMemoryState`.

## Subsequent execution implementation

The October 31 implementation retains the transaction order fixed by consensus
and changes when independent work can start:

| Area | Current implementation | Compatibility and limit |
|---|---|---|
| Scheduling | Canonical ABI-v2 and Trocto ABI-v3 calls read only their exact immutable code key; other declared keys and deployments remain writes | Shared code with disjoint writable state can run together; shared writable state and sender dependencies remain ordered |
| Mixed execution | A readiness DAG releases jobs when their own predecessors complete, without a whole-wave barrier; workers read frozen declared-key overlays | RAW/WAR/WAW, sender order, canonical output positions and atomic publication are retained; deterministic failures replay serially |
| Worker lifetime | One bounded scoped pool is reused within a block attempt; linear dependency paths can share a private session | Single-wide-wave batching and entirely serial fusion remain; threads and speculative state do not persist across blocks |
| Native contracts | Explicit committed runtime profile 3 executes checked Trocto source through isolated LLVM workers | Historical ABI-v2 bytes and domains retain their interpretation; native infrastructure failures remain local `NativeUnavailable` errors without a fallback backend |

The [readiness comparison](assets/trocto-readiness-2026-10-31/comparison.json)
switches only wave/ready dispatch in an isolated source copy with identical
fixtures. For 44 payments in a 16-wave dependency shape, four-worker median
changed from 1.4465 ms to 1.1710 ms (1.235x), while two workers regressed from
1.4423 ms to 1.6334 ms. Unchanged controls fluctuated 5–15% under background
load. These seven-round local samples establish neither a general speedup nor
network TPS. The raw before/after logs, source artifacts and reproduction
metadata remain linked from that comparison.

## Local research baseline (October 14)

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
a separate fixture: one code key, distinct senders, and disjoint state keys.
That fixture and its later [scheduler comparison](assets/trocto-architecture-2026-10-31/comparison.json)
are now available; they do not change the October 14 baseline below.

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

## Development priorities

These are the priorities selected at the research revision, with their original
acceptance criteria. Precise code access, readiness dispatch and the state-backend
portion of P1 subsequently landed. Cross-block worker lifetime, an E2E benchmark
environment and distributed performance qualification remain separate work.

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
Call semantics is now implemented without changing historical transaction bytes.
Differential tests cover deploy→call, call→later conflicts, complete outputs,
resource charges, first-error order and rollback. Broader signed read/write modes
still require their own versioned proposal and qualification.

Global state partitioning, a new ownership model, changes to finality rules,
and delayed state roots require separate versioned designs and qualification.
The current plan prioritizes the existing protocol and state model. Runtime
optimizations must continue to satisfy the unsafe-code policy.

## Distributed performance qualification

Every result must specify its workload and conditions. Transfers, contended
contracts, data propagation, and finality latency need separate measurements.

The primary metric is **unique, successfully executed user transactions with
verifiable finalized receipts and completed durable publication per second,
subject to a p99 bound and a stable queue**. Count votes, retries, rejected
transactions, and internal messages separately.

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

Comparisons between AstroLune configurations require matching operation semantics
and completion guarantees. Publish local execution and distributed finalized
throughput as separate profiles.
At 256 tx/block, the theoretical ceiling is
`256 / mean finalized-block interval`; increasing the limit alone does not reduce
computation, transmission, or durable commit costs.

## Outcome of this stage

The architecture assessment and its local baseline are complete. The original
priorities and research designs remain recorded above. Later state and execution
implementation is distinguished from that baseline; novelty validation, external
audit, further development and distributed qualification remain outstanding.
