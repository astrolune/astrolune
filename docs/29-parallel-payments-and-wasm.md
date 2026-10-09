<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 29. Parallel payments and the WebAssembly contract sandbox

## Parallel payment execution

`execute_payments_parallel` executes the existing signed payment rules with
1–32 local workers. It checks actual sender/recipient keys against declarations
before trusting the existing dependency-preserving wave planner. Independent
transactions run concurrently against immutable snapshots and a private overlay;
later dependent waves see preceding writes. Results and receipts return in the
original transaction order. Block resource totals are checked in that order,
and the database receives one atomic commit.

Speculative failures and worker creation failures replay through the serial
reference executor. Invalid inputs therefore preserve the reference error and
leave no published prefix. The producer uses up to eight available local workers
when verifying/replaying genesis-backed payment blocks. Mempool selection and
proposal admission remain sequential so rejected candidates cannot consume
nonce, balance or capacity. Worker count never changes block bytes.

Differential tests compare outputs, roots, retained snapshots and errors for
independent transfers, dependent account creation, self-transfers, multiple
nonces, forged signatures, missing access declarations, capacity exhaustion and
stale parents.

Local execution performance is now measured by `crates/execution/benches/execution.rs`
on one eight-core host, and the measurement qualifies the parallel path more
narrowly than equivalence testing alone suggested. Against the serial path on
fully independent transfers in one wide wave, the best observed speedup is 2.56x
at 128 transactions and four workers, roughly a third of linear. Below about
eight transactions per worker the parallel path loses: at eight transactions it
is slower at every worker count, and 35 percent slower at eight workers. Scaling
saturates at four workers on this host, and sixteen workers are both slower and
unstable run to run.

A `pool_floor` group that holds exactly one transaction per worker isolates the
cause. The per-attempt scoped pool costs on the order of 50 us per worker
thread, and a single payment transaction executes in about 41 us, so one worker
thread costs about as much as one transaction. The pool is created per block
attempt, so that charge is paid whether or not the plan is wide enough to repay
it. A rejected batch costs the parallel path 1.4x to 1.6x the serial path,
because the discarded speculative pass precedes the full serial replay by
design. Planning itself is not a factor at 26.6 us for 128 transactions.
Figures describe one host and establish no bound;
[measurement limits](56-performance-measurement.md).

## Execution-parent cache and planner allocation

`execute_signed` and contract-enabled `execute_parallel` share a read-through
cache of immutable parent values across calls and waves within one execution
attempt. Values and absent keys are cached on first use, with at most 4096
entries and 8 MiB of combined key/value bytes; map metadata is additionally
bounded by the entry count. Full caches and oversized entries read directly
from the parent. Reads occur outside the cache lock, so simultaneous misses
may read the same key more than once. Storage errors are never cached.

Private overlay writes and deletions take precedence over cached parent data.
The cache is discarded after the attempt; serial replay creates a fresh cache,
and a following block reads its own parent. Proof methods delegate to the parent.
There is no cross-block state, eager prefetch, result caching or change to
resource charges. Direct `SignedSession` callers retain their supplied snapshot;
the payment-only path uses its existing account/write overlays without this
additional cache.

The wave planner borrows access keys from the transaction batch instead of
allocating normalized leases during planning. It computes all predecessor waves
before updating its per-key index, preserving plans for unordered or duplicate
keys and repeated senders. The public lease operation is unchanged.

Deterministic tests compare the planner against an independent pairwise
predecessor implementation on 256 generated blocks, alongside the existing 512
access patterns. Contract tests compare complete outputs, resource charges,
roots, retained snapshots and first errors against uncached `SignedSession`
execution at 1, 2, 3, 8 and 32 workers. Three successive calls to each of two
previously deployed contracts reduce parent code reads from three to one per
contract; the next block performs a fresh read. Cache tests cover absence,
entry/byte limits, errors, shared worker hits and overlay write/delete visibility.
These are read-count and equivalence checks, not wall-clock throughput claims.

The distinction matters, because the read-count reduction buys no measurable wall
clock against an in-memory parent. On 16 calls to one shared contract,
`execute_signed` with the cache and a direct uncached `SignedSession` loop both
measure 1 202 us; on 16 independent contracts the cached path measured 4 to 9
percent slower across runs. Against `InMemoryState` the cache replaces a map
lookup and value clone with a mutex-guarded map lookup and the same clone, so
there is nothing to recover. A disk-backed parent is where the saved reads could
pay and was not measured, so the cache is retained on the read-count grounds
above rather than on a measured speedup;
[measurement limits](56-performance-measurement.md).

## Per-block worker reuse

Parallel execution creates one scoped worker pool per block attempt and reuses
its threads across all parallel waves. Its size is the smaller of the requested
worker count and the widest wave, with the existing maximum of 32. Singleton
waves execute on the coordinator; a plan containing only singleton waves creates
no workers. Threads are joined before the attempt returns, including on failure.

Each worker has a one-slot request channel and a one-slot result channel. The
coordinator dispatches at most one chunk to each worker per wave and receives
every dispatched result before advancing the shared private overlay. Workers
hold read access only while executing their chunk; the coordinator applies
results between waves. A fresh execution session per chunk retains the existing
resource accounting. Result order, chunk boundaries, resource charges and the
final atomic commit are unchanged.

Task failures and closed worker channels drain outstanding results and close the
pool. Worker panics are consumed by explicit joins; execution falls back to the
existing serial path, as it does for worker creation failures. No worker, task
queue or speculative overlay survives into another execution attempt.

Tests compare 16 waves with changing widths, new account visibility, a late
resource failure and a clean retry against serial execution for 1, 2, 3, 8 and
32 requested workers. Snapshot read instrumentation records actual thread IDs:
six four-wide waves use four worker threads at a requested count of four or
more, instead of creating 24 threads. Separate pool tests cover ordered results,
reuse, smaller/empty batches, task errors, worker panics and joining idle workers.
This qualifies thread reuse and functional equivalence; end-to-end throughput
has not been benchmarked. Reuse is visible in the per-operation figures: a
44-transaction batch spanning 16 waves reaches 1.51x serial, which a pool created
per wave could not do, since 16 pool creations alone would exceed the whole
measured block. The pool's cost is still charged once per attempt and is the
dominant reason parallel execution needs about eight transactions per worker to
win; [measured scaling](56-performance-measurement.md).

## Fusion, prefetch and result-buffer reuse

Consecutive waves containing one transaction each execute in one sequential
session. Later transactions see that session's private writes, including account
creation and contract changes, before the combined results reach the block
overlay. Each transaction retains its own output, receipt, resource accounting
and committed position. Wider waves retain parallel execution. Any speculative
failure still triggers serial replay to preserve the canonical error; a failed
attempt publishes no state.

Each public payment or signed-execution invocation offers at most one advisory
prefetch hint, after checking the parent snapshot root. The hint inspects at most
256 transactions and 1024 declared accesses, and copies at most 256 unique keys
with at most 64 KiB of total key bytes. Keys are deduplicated in canonical order;
oversized keys are skipped. Empty selections make no prefetch call. Hint errors
are ignored, and serial replay does not issue the hint again. Prefetch never
substitutes for state reads or transaction validation. Existing database backends
implement it as a no-op, so this hook alone establishes no speedup.

The executor drains each worker's output vector into committed-order result
positions and recycles the empty allocation for later waves. The coordinator's
result envelope, singleton result buffer and fused-index buffer are reused within
the execution attempt. Buffers and worker threads are dropped at its end; no
transaction output or speculative state is shared with another block or retry.
This is a pool of result buffers, not a pool of contract instances or state values.

Differential checks cover dependent singleton runs, changing wave widths, resource
failures and serial replay. Prefetch checks cover limits, deduplication, hint
failure and stale parents; worker-pool checks cover result-buffer reuse and error
cleanup. Alongside parent caching and borrowed-key planning, these implement the
reference execution locality, fusion, prefetch and buffer-pool scope. Signature
batching remains unimplemented and deferred with cryptographic verification work.
End-to-end throughput has not been benchmarked.

Per-operation measurement narrows what fusion and prefetch achieve. Fusion
prevents a loss rather than producing a gain: a plan of only singleton waves
creates no workers, so an all-singleton dependent chain of 128 transactions costs
5 458 us at eight workers against 5 329 us serial, avoiding the pool charge
instead of beating the serial path. Shapes with and without runs of consecutive
singletons reach the same 1.5x, so fusion is not separately visible as a speedup.
Bounded declared-key prefetch has no measurable effect at any batch size, and the
sign of the difference changed between runs, because `InMemoryState::prefetch` is
a no-op and only the key-set construction is left to measure.

One planner consequence is worth stating plainly: repeated calls to a single
contract do not parallelize at all. Sixteen calls to one contract plan as sixteen
singleton waves, because the shared contract code key is declared and the planner
treats every declared key as a write, giving 1 237 us at eight workers against
1 202 us serial. Sixteen calls to sixteen distinct contracts plan as one wave and
reach 1.72x. This is a consequence of conservative access declaration, not a
tuning parameter; [measurement limits](56-performance-measurement.md).

## WebAssembly ABI v2

`WasmRuntime` validates binary WebAssembly and executes it using pinned Wasmi
2.0.0 with eager validation, portable dispatch, integer operations and fuel.
The previous XOR interpreter remains a demonstration helper. The explicit new
runtime version is `{ abi: 2, metering: 1 }`. [Genesis profile 2](30-signed-contracts.md) explicitly activates signed contracts in the daemon.

A module exports `memory` and `call() -> i32`. Zero means success; nonzero returns
or traps discard all staged writes, return data and events. Start functions,
floating-point instructions/types, WASI, unknown imports, imported memories,
threads, SIMD, memory64 and multiple memories are rejected. No clock, filesystem,
network or ambient randomness is available to contracts.

Imports use module name `astrolune_v2`. Pointers and lengths are nonnegative i32
byte offsets checked against the exported memory; negative lengths trap.

| Import | Arguments | Result |
| --- | --- | --- |
| `input_len` | none | input length |
| `input_copy` | input offset, memory output pointer, length | 0 |
| `output` | pointer, length | 0; replaces return data |
| `state_get` | key pointer, key length, output pointer, output capacity | length, or -1 for absence |
| `state_put` | key pointer, key length, value pointer, value length | 0 |
| `state_delete` | key pointer, key length | 0 |
| `caller` | output pointer | 0; writes 32 address bytes |
| `block_height` | none | i64 containing all u64 height bits |
| `emit` | topic pointer, data pointer, data length | 0; appends a 32-byte topic and body |

All results except height are i32. State operations require exact keys from the
call's access set. Reads see staged writes/deletes. Caller identity, height,
scoped state and access authorization are supplied by the outer executor.
`WasmOutput` returns canonical writes and actual accessed keys for later commit.
The sandbox cannot directly transfer balances or publish state.

## Bounds and metering

Modules are at most 1 MiB. Input/return data are at most 256 KiB. Memory must have
an explicit maximum of at most 256 standard pages (16 MiB), further bounded by
the call's memory budget. Tables are limited to 4096 elements and one table;
recursion is capped at 128 and stack height at 16384. `memory.grow` respects the
module maximum, including WebAssembly's normal -1 failure result.

Calls permit at most 10 million fuel units, 1 MiB of state I/O, 256 KiB of output
bandwidth, 1024 state/access entries, 256-byte nonempty keys, 64 KiB values/event
bodies and 256 events. The supplied state view is bounded to 1 MiB. Host work
charges 20 fuel units plus copied/processed byte counts for each helper operation;
state I/O and output/event bandwidth are charged separately. Wasmi instruction
fuel is part of the pinned metering version, not measured elapsed time.

Changing engine version, fuel schedule or allowed features requires an explicit
runtime-version change. Alternate native backends are not yet qualified.

## Qualified alternate engine configurations

`RuntimeBackend::execute` documents that an optimized backend must match the
interpreter. `WasmBackend` is the alternate implementation that claim is now
tested against: it executes real ABI-v2 WebAssembly behind that seam over a
`WasmRuntime` built by `WasmRuntime::with_profile`. `EngineProfile` enumerates
the engine tuning axes a backend may move, and `WasmRuntime::new` is exactly
`EngineProfile::Reference`. Every profile is the same pinned Wasmi 2.0.0
interpreter with the same rejected proposals, the same fuel schedule, the same
128-frame recursion cap and the same 16,384-byte value stack cap, so `kind`
reports `BackendKind::Interpreter` for all of them.

Two axes are qualified as consensus-neutral and are varied.
`EngineProfile::PreallocatedStack` raises the initial value-stack height from the
Wasmi default of 1,000 bytes to the configured maximum of 16,384 bytes, so the
stack is allocated once instead of growing. `EngineProfile::UnpooledStack`
reduces the engine stacks kept for reuse from 2 to 0.
`EngineProfile::Alternate` moves both at once. Those three are
`EngineProfile::ALTERNATES`; `EngineProfile::QUALIFIED` adds the reference.

Compilation strategy was expected to be a third neutral axis and measurably is
not. On 2026-10-08, Windows with Rust 1.99.0 and pinned Wasmi 2.0.0, the minimal
returning module charges 2 compute units under `CompilationMode::Eager`, 30
under `CompilationMode::LazyTranslation` and 38 under `CompilationMode::Lazy`,
because Wasmi charges deferred translation, and under `Lazy` deferred validation
as well, to the executing call's own fuel. The gap grows with the size of the
translated body. Return data, events, staged writes and accessed keys remain
identical across all ten structured modules, so the disagreement is confined to
charged compute, which alone is enough to split consensus.
`EngineProfile::LazyTranslation` and `EngineProfile::Lazy` are therefore
retained as `EngineProfile::DISQUALIFIED`, reported as not neutral by
`is_consensus_neutral`, and asserted to keep disagreeing so a later engine
bump cannot silently admit them.

Four further axis classes are excluded by construction rather than by
measurement, because each is part of the runtime version. `set_max_recursion_depth`
and `set_max_stack_height` decide where a `StackOverflow` trap occurs, which a
call observes directly. `fuel_cost` and `operator_cost` define charged compute.
`enforced_limits` and `ignore_custom_sections` decide which modules validate.
The `wasm_*` proposal toggles define the accepted instruction set. A backend may
not move any of them.

`RuntimeOutput` and `WasmOutput` are different types, so the comparison is
explicit. `wasm_difference` compares two complete ABI-v2 results and returns the
first disagreeing field as an `OutputDifference`: acceptance, error variant,
return data, events in order, staged writes, actually accessed keys, then
compute, memory, I/O and bandwidth. Consumed resources are compared exactly and
no tolerance is applied. `RuntimeOutput` has exactly two fields, `return_data`
and `resources`, and has no field able to carry `WasmOutput::events`,
`WasmOutput::writes` or `WasmOutput::accessed`; `project_wasm_output` drops
precisely those three, and `runtime_difference` compares only what remains. The
seam comparison is therefore strictly weaker than the complete one and never
substitutes for it, so every seam result is additionally pinned to
`project_wasm_output` of the interpreter result for the same context. Widening
`RuntimeOutput` would change the legacy ABI-v1 interface and is not done here.

The consensus-visibility of the two excluded stack bounds is itself measured
through the public interface. On 2026-10-08, Windows with Rust 1.99.0, a
self-recursive module whose frames hold only an `i32` parameter succeeds at
depth 126 and returns `RuntimeError::LimitExceeded` at depth 127, where the
128-frame cap retires it. The same recursion with thirty-two additional `i64`
locals per frame succeeds at depth 60 and fails at depth 61, where the
16,384-byte value stack cap retires it first. All four qualified profiles agree
on both thresholds, which is what makes the allocation axes neutral and the
bounds themselves consensus-visible.

The qualification campaign reuses the contract corpus and the deterministic
xorshift64 mutator of the contract fuzz campaign. It validates and executes each
candidate under the reference interpreter and under all three alternate
profiles, compares complete outputs with `wasm_difference`, compares the seam
with `runtime_difference`, and requires rejected candidates to be rejected with
the same `RuntimeError` variant by every profile, because a backend that accepts
what the interpreter rejects is a consensus split.

```text
cargo test -p runtime --test backends
cargo test -p integration --test backends
cargo test -p integration --test backends -- --ignored
```

On 2026-10-08, Windows with Rust 1.99.0 and the unoptimized dev profile,
`backend_qualification_smoke` compared 3,012 candidates, 72 accepted modules,
8,511 validation results, 216 complete executions, of which 126 were accepted
and 90 rejected, and 216 seam executions, finding 0 disagreements.
`extended_backend_qualification` compared 100,012 candidates, 2,514 accepted
modules, 284,016 validation results, 7,542 complete executions, of which 4,716
were accepted and 2,826 rejected, and 7,542 seam executions in 23.93 seconds,
finding 0 disagreements. `million_backend_qualification` compared 1,000,012
candidates, 24,681 accepted modules, 2,838,960 validation results, 74,043
complete executions, of which 47,466 were accepted and 26,577 rejected, and
74,043 seam executions in 238.45 seconds, finding 0 disagreements. The runtime
crate additionally pins the ten structured modules, ten rejected candidates, the
measured lazy-compilation gap, the seam projection, the fields the seam cannot
express, and the two stack thresholds.

This qualifies configuration independence across the `RuntimeBackend` seam for
two allocation axes, and it records one measured configuration axis that is not
independent. It is not an ahead-of-time, just-in-time, SIMD or independently
implemented backend; no such backend exists in this workspace, and
`BackendKind::Aot` and `BackendKind::Jit` remain reserved declarations. The
compared profiles share one interpreter, one translator and one fuel schedule,
so agreement between them does not establish agreement with a hypothetical
native backend. Nothing here changes the runtime version, enables an alternate
backend for live execution, or establishes any throughput, compile-time or
memory-footprint claim; the reported seconds are campaign durations, not
benchmarks.

## Contract tooling

```text
cargo contract build contract.rs contract.wasm
cargo contract validate contract.wasm
cargo contract test contract.wasm input.bin
cargo contract verify contract.wasm <expected-code-hash>
```

`build` accepts a standalone `no_std` Rust source, resolves rustc 1.99.0 through rustup and requires its
`wasm32-unknown-unknown` libraries, and compiles twice with fixed optimization,
panic, metadata, memory and symbol settings. It validates equal binary outputs
before exclusively creating the destination. `ASTROLUNE_CONTRACT_SYSROOT` can
select an isolated installation of the pinned target libraries. Dependency-based
Cargo contract packages are not supported yet. Compiler diagnostics remain visible.

`validate` checks actual module restrictions; `test` executes with empty state,
zero caller and height one; `verify` compares the exact version-bound code hash.
Code-hash verification does not prove published source or deployment authenticity.
Unsupported commands, including deployment, fail with nonzero status.

Tests include real CLI validation/execution and a separately invoked pinned-Rust
build test. The latter needs the target libraries and is ignored in the default
workspace run; run `cargo test -p cargo-contract --test commands -- --ignored`.
The pinned build test has been run locally with the official target component.

Signed deploy/call envelopes, fees/nonces, mixed waves and explicit daemon activation are implemented in [document 30](30-signed-contracts.md). The allocation-free Rust SDK host adapter is implemented and tested; see [document 31](31-rust-sdk-and-wallet-vaults.md). Restricted source manifests and exact offline package reconstruction are implemented in [document 34](34-contract-source-packages.md). Alternate AOT/JIT backends, their runtime/metering qualification and contract fuzz campaigns remain open and deferred.
