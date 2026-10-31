<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 64. Trocto and the Native LLVM Runtime

Trocto is the development direction for AstroLune contract source. Files use the
`.tc` extension. The compiler and native runtime are implemented in Rust;
Trocto compilation produces LLVM IR and native machine code.

The first implementation is a local development backend. It establishes the
frontend, checked integer semantics, deterministic fuel, and a persistent native
worker. Stateful host calls and consensus activation require the milestones below.

## Compilation and execution

```text
source.tc -> bounded lexer/parser -> checked immutable instruction program
          -> LLVM IR -> clang 22.1.8 -> native worker
                                      -> result and charged fuel
```

`trocto-compiler` owns the checked program and LLVM lowering. `trocto-runtime`
accepts that program, builds a worker, and compares native results with the Rust
reference evaluator. Native executables received from producers are not accepted
by this development interface.

The worker persists across calls so compilation and process startup can be
amortized. Compile and response deadlines bound local waiting. A local timeout or
toolchain failure is distinct from deterministic contract failure and must not
be used as a consensus verdict.

## Initial language

```rust
fn call(input: u64) -> u64 {
    let fee: u64 = 7;
    let total: u64 = input + fee;
    return total;
}
```

Language version 1 supports a single `call` entry point, a `u64` input and return
value, immutable local bindings, integer literals, parentheses, and checked
`+`, `-`, `*`, `/`, and `%`. Names must resolve to earlier bindings; duplicate
bindings and unsupported types or constructs are rejected.

There are no references, pointers, allocation, mutable aliases, arbitrary calls,
imports, loops, recursion, floating point, or operating-system access in this
subset. This small language avoids several memory-safety hazards by construction.
It does not yet implement a Rust-style ownership and borrowing system.

Frontend limits are 65,536 source bytes, 16,384 tokens, 4,096 instructions,
1,024 local bindings, 64 nested expressions, and 64 bytes per identifier.
Malformed and oversized input must fail before native compilation.

## Integer semantics and fuel

Overflow and underflow fail the call. Division and remainder by zero fail the
call. LLVM lowering uses checked arithmetic and explicit failure paths; optimizer
assumptions must not introduce undefined integer behavior.

Metering version 1 charges one unit per source-derived instruction: literal,
input/local copy, or binary operation. Binding and return syntax add no separate
charge. The charge follows the reference program even when LLVM optimizes away
machine instructions. Failure order and charged work must match the reference
evaluator for every input and budget.

The native function boundary is:

```text
i32 trocto_call(u64 input, u64 fuel, u64* output, u64* used)
```

Status values are `0` for success, `1` for fuel exhaustion, `2` for arithmetic
overflow, and `3` for zero division. Output fields are published only on success.
The process protocol uses bounded canonical integer messages; pointers stay inside
the generated worker and are not exposed to Trocto source.

## Development commands

```powershell
. ./tools/enter-dev.ps1
cargo run --locked -p cargo-contract -- trocto check examples/contracts/trocto/checked_payment.tc
cargo run --locked -p cargo-contract -- trocto emit-llvm examples/contracts/trocto/checked_payment.tc target/payment.ll
cargo run --locked -p cargo-contract -- trocto run examples/contracts/trocto/checked_payment.tc 42 100
```

Set `ASTROLUNE_LLVM_CLANG` to the clang 22.1.8 executable when it is not in PATH.
The toolchain must include LLVM lld. Compilation disables external clang
configuration files and runs with a restricted environment. Cancellation reaps
the direct compiler process; complete ownership of compiler subprocesses remains
part of the OS-isolation milestone.
IR export refuses to overwrite an existing file. The native runner requires the
supported local LLVM toolchain; frontend checks do not.

## Safety and activation milestones

1. Extend typed semantics with bounded byte values, explicit effects, and scoped
   state capabilities. Establish ownership and borrowing rules before adding
   references or mutable aggregates. Every extension needs rejection tests and
   reference/native conformance vectors.
2. Implement state reads/writes, context, events, and resource accounting through
   a bounded host ABI. Effects remain private until a successful certified commit;
   failure discards the complete attempt.
3. Add an operating-system sandbox and enforce memory, process, file, network,
   and syscall restrictions. A separate process alone is not an OS sandbox.
4. Qualify native compilation and execution across supported CPU/OS targets,
   optimization settings, toolchain identities, hostile input, and worker recovery.
   Evaluate code generation independently of the reference oracle.
5. Specify a new deployment/runtime profile, signed source commitments, compiler
   and metering identities, migration, and historical replay. Preserve declared
   behavior for existing deployments.
6. Complete independent compiler/runtime review before enabling untrusted native
   contracts in validators. The development worker has no consensus activation.

## Performance work

The first execution improvement derives read-only access to shared contract code
from decoded call semantics. Distinct senders calling disjoint local state can
share a wave; writes and sender effects retain their predecessor order. Malformed
payloads use conservative planning, and serial replay remains the error oracle.

An initial Windows measurement uses the same isolated source and fixtures with
only the scheduler changed between runs. For 16 shared-code calls with disjoint
state, the plan changed from 16 waves to one. The median with four workers changed
from 0.889 ms to 0.539 ms, about 1.65 times faster; with eight workers it changed
from 0.898 ms to 0.589 ms, about 1.53 times faster. Four-call batches regressed
because worker startup cost exceeded the saved execution time.

This is one host with background load and seven rounds, not distributed throughput
or a statistical significance result. The [comparison and environment metadata](assets/trocto-architecture-2026-10-31/comparison.json),
[before log](assets/trocto-architecture-2026-10-31/before.log), and
[after log](assets/trocto-architecture-2026-10-31/after.log) retain the evidence.

Next steps are readiness scheduling without global wave barriers, persistent
bounded workers across execution attempts, state/commitment overlap, and the
experiments in [documents 61](61-network-architecture-research.md) and
[62](62-original-architecture-proposals.md). Each needs complete receipt, state,
error, and recovery equivalence before activation.

Performance qualification measures successful user transactions after verified
finality and durable publication, including queue growth and p99 latency. Local
compiler or executor speed cannot establish a worldwide throughput ranking.
