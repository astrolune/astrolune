<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 3. Contract Runtime and Resource Metering

## 3.1 Rust contract model

AstroLune contracts are written in a deterministic Rust subset and compiled to a versioned canonical runtime target. The implemented target is integer-only WebAssembly ABI v2 with Wasmi 2.0.0 metering and pinned Rust 1.99.0 builds; see [sandbox and tooling](29-parallel-payments-and-wasm.md) and [signed activation](30-signed-contracts.md).

The removed ALVM, Trocto, Regol, and Kreep designs are not compatibility requirements. Arbitrary native executables are never consensus artifacts.

## 3.2 Deterministic target restrictions

Contract execution MUST exclude or fully virtualize:

- floating point unless bit-exact semantics and metering are specified;
- threads, atomics, scheduler observation, and data races;
- wall clocks and non-deterministic randomness;
- filesystem, sockets, environment variables, and process APIs;
- undefined or target-dependent behavior;
- unbounded recursion, allocation, output, and host calls;
- unordered iteration that can affect outputs.

The deploy validator checks code format, imports, control flow, memory bounds, entry-point ABI, metering instrumentation, and forbidden features.

## 3.3 AOT, JIT, and native cache

Canonical code may be compiled ahead of time. Nodes may use a JIT for latency and a native execution cache for repeat calls. Cache keys include canonical code hash, runtime version, compiler backend version, target architecture, enabled CPU features, metering schedule, and protocol version.

Native code is a local optimization and is never trusted as a state commitment. The interpreter or a separately validated deterministic backend defines semantics. Differential tests must compare interpreter, AOT, JIT, SIMD, and portable paths.

## 3.4 Execution cache

The executor may cache validated modules, control-flow metadata, compiled artifacts, access predictions, and execution plans. Entries are immutable and content-addressed. Negative cache results are bounded and invalidated by runtime-version changes. Consensus acceptance cannot depend on cache presence or eviction order.

## 3.5 Resource classes

Transactions declare independent limits for:

| Class | Examples |
|---|---|
| compute | instructions, host calls, hashing, signature checks |
| memory | peak pages, allocations, copy volume |
| state I/O | key lookups, bytes read/written, proof work |
| bandwidth | canonical transaction, events, receipts, propagated data |

Metering charges actual work according to the finalized schedule, not host elapsed time. Every counter uses checked integer arithmetic. Exhausting any class stops execution deterministically. Block and lane limits apply to aggregate actual usage.

## 3.6 Multi-lane execution

The initial lanes are payments, contracts, and system operations. Each lane has bounded queue and block capacity. Unused capacity may be borrowed only by a deterministic rule fixed in the protocol. System operations cannot be starved by contract load.

Lanes isolate admission and scheduling; they do not create separate consensus domains or state roots.

## 3.7 Transaction fusion

The executor may fuse compatible operations into one optimized batch: repeated transfers, shared contract preparation, signature batches, and adjacent state reads are examples. Fusion MUST preserve each transaction's nonce, authorization, error boundary, resource accounting, receipt, event order, and committed position.

An unfused reference path must produce identical canonical outputs.

## 3.8 Speculation

Speculative execution may prepare transactions for the likely next proposal or execute optimistic waves before all earlier waves commit. Results are tagged with parent state root, ordered transaction set, capacity, runtime version, and access assumptions. Any mismatch invalidates the result.

Speculation must never hold canonical locks, consume non-refundable protocol state, or make external side effects.

## 3.9 Memory management

Object and memory pools are encouraged only after profiling. Pools are bounded, reset on error, and cannot retain secret material without secure clearing. The runtime imposes explicit linear-memory, stack, call-depth, event, return-data, and allocation limits.
