<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 5. Trocto Contract Language

## 5.1 Direction and current implementation

Trocto (`.tc`) is the source-language direction for new AstroLune contracts. Its
compiler emits LLVM IR and native code through a pinned LLVM toolchain. The first
implementation provides typed values, mutation and control flow, checked
arithmetic, explicit state capabilities, events, deterministic fuel and isolated
native workers. Genesis runtime profile 3 enables signed deployment and execution. See
[Trocto and the native LLVM runtime](64-trocto-native-llvm.md) for syntax, limits,
commands, and activation requirements.

Existing signed deployments use the versioned WebAssembly ABI-v2 profile and
restricted Rust tooling described in [document 29](29-parallel-payments-and-wasm.md).
A new source language does not silently change the semantics of deployed code.
Trocto uses its own signed profile and source identity for stateful execution.

## 5.2 Build pipeline

```text
Trocto source (.tc)
  -> bounded parsing and type checking
  -> immutable checked instruction program
  -> deterministic metering and LLVM IR
  -> pinned native compilation
  -> isolated native execution and conformance verification
```

Source identity, language version, metering version, compiler identity, and native
artifact provenance have separate roles. Native bytes are local derived artifacts;
validators must independently establish source semantics and accepted execution.

## 5.3 Safety model

The numeric profile supports copied `u64` and `bool` values, lexical initialization
rules, checked mutations, and metered branches/loops. It rejects pointers,
references, heap allocation, arbitrary calls, imports, recursion and floating point.
Memory safety uses bounded scalar storage and checked capability indexes.
Ownership and borrowing for richer values require a later language profile.

Native workers establish Linux seccomp/resource limits or Windows
AppContainer/job isolation and probe enforcement before execution. Full state,
events and fuel results are compared with an independent reference evaluator.
`cli devnet --trocto` provisions runtime profile 3. Independent security review
remains part of production qualification.

## 5.4 Host ABI and state

The native entry point consumes one integer and authenticated context/capabilities,
then returns one integer, charged fuel and private state/events. Literal and
dynamic transaction keys address bounded numeric storage; public address limbs
can be compared with caller limbs. A failure discards the complete staged call.
Byte aggregates, nested contract calls and richer host APIs require later profiles.

The contract language must not expose networking, files, clocks, random devices,
threads, environment variables, process functions, or unrestricted allocation.

## 5.5 Compatibility and upgrades

Language, runtime, ABI, serialization, standard library, and metering schedules
are independently versioned. Existing deployments retain their declared versions.
Compiled artifacts may be regenerated or discarded without changing results.
Source authorization and upgrade authority must remain explicit.

## 5.6 Qualification

Frontend bounds and rejection tests, arithmetic/fuel conformance, native/reference
differential tests, reproducible compilation, supported-platform execution,
resource isolation, state rollback, and historical replay are required milestones.
A compiler or SDK release becomes consensus-supported only after its new runtime
profile and conformance vectors have been reviewed and qualified.
