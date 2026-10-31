<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 5. Trocto Contract Language

## 5.1 Direction and current implementation

Trocto (`.tc`) is the source-language direction for new AstroLune contracts. Its
compiler emits LLVM IR and native code through a pinned LLVM toolchain. The first
local implementation provides immutable integer expressions, checked arithmetic,
a reference evaluator, deterministic fuel, and a native worker. See
[Trocto and the native LLVM runtime](64-trocto-native-llvm.md) for syntax, limits,
commands, and activation requirements.

Existing signed deployments use the versioned WebAssembly ABI-v2 profile and
restricted Rust tooling described in [document 29](29-parallel-payments-and-wasm.md).
A new source language does not silently change the semantics of deployed code.
Trocto stateful execution and consensus activation require a separate profile.

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

The initial subset has only immutable `u64` values and checked integer operations.
It rejects pointers, references, allocation, arbitrary calls, imports, recursion,
loops, and floating point. It avoids mutable aliasing and dangling references by
not exposing them. Ownership and borrowing for richer values remain to be designed.

A native process is a development boundary, not a production sandbox. Untrusted
execution requires operating-system restrictions, bounded resources, hostile-input
qualification, and independent review. No current Trocto command activates a
validator runtime profile.

## 5.4 Host ABI and state

The initial native function consumes one integer and returns one integer plus
charged fuel. State, events, caller identity, value transfer, hashing, and nested
contract calls are subsequent host-ABI work. Those APIs must expose explicit
capabilities, bounded byte values, typed errors, and staged effects.

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
