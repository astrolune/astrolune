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
stale parents. Local execution performance has not been benchmarked.

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
has not been benchmarked.

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
