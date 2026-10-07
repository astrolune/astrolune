<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 5. Rust Smart Contracts

## 5.1 Decision

Rust is the only first-party smart-contract source language in the current architecture. Earlier custom languages and their custom VM are removed. This reduces duplicated compiler work and lets the project use established Rust parsing, tooling, testing, formatting, and developer knowledge.

The source language decision does not mean arbitrary Rust is deterministic or safe. Contracts use a restricted SDK and compile profile targeting a canonical runtime format.

## 5.2 Build pipeline

```text
Rust contract source
  -> pinned Rust toolchain and AstroLune SDK
  -> restricted target artifact
  -> canonicalization and validation
  -> deterministic metering instrumentation
  -> deployment container
  -> interpreter/AOT/JIT execution with differential verification
```

A deployment records source metadata separately from canonical executable bytes. Consensus identifies code by canonical code hash, runtime ABI version, and metering version.

## 5.3 SDK surface

The SDK provides deterministic types and host calls for caller identity, contract address, block context, state reads/writes, events, hashing, signature verification, value transfer, and contract calls. Host APIs use explicit byte slices, bounded outputs, and typed errors.

The SDK does not expose networking, files, clocks, random devices, threads, environment variables, process functions, or direct operating-system allocation.

## 5.4 Compatibility and upgrades

Runtime, ABI, serialization, standard library, and metering schedules are independently versioned. Existing deployed code keeps its declared versions. Nodes may cache compiled native artifacts, but must be able to regenerate or discard them without changing results.

Contract upgradeability is an application pattern, not implicit code replacement. Immutable deployments plus an explicitly authorized proxy or migration contract are preferred because upgrade authority remains visible.

## 5.5 Tooling targets

Planned tooling includes:

- `cargo astrolune` build, validate, test, deploy, and verify commands;
- a deterministic local runtime;
- state-access-list generation and inspection;
- resource reports by compute, memory, I/O, and bandwidth;
- reproducible build metadata;
- source verification;
- contract fuzzing and property testing;
- interpreter/AOT/JIT differential tests.

## 5.6 Security rules

Contract authors must use checked arithmetic or explicit wrapping operations, validate authorization, bound user-controlled loops and output, avoid unbounded state growth, and declare state access accurately. The runtime enforces lease and resource limits even if a contract is incorrect.

No compiler or SDK release becomes consensus-supported until reproducible artifacts and cross-platform conformance vectors exist.
