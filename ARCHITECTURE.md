<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# AstroLune Architecture

This document is the short repository map. The detailed engineering specifications begin at [`docs/README.md`](docs/README.md).

## Layers

1. **Foundation:** `codec` and `types` define bounded canonical bytes and shared values.
2. **Chain configuration and security:** `genesis`, `crypto`, and `keystore` define chain identity, cryptographic providers, and key isolation.
3. **Protocol:** `transaction` and `consensus` define admission and finalized ordering.
4. **State and execution:** `state`, `runtime`, and `execution` define snapshots, Rust contract semantics, scheduling, and diffs.
5. **Node policy and persistence:** `mempool`, `storage`, and `sync` remain outside core validity rules where possible.
6. **Transport and orchestration:** `p2p`, `rpc`, `config`, `telemetry`, and `node` connect bounded subsystems.
7. **Products:** `daemon`, `cli`, `cargo-contract`, DNS are executable integration surfaces.

## Dependency rules

- Shared protocol values live in `types`; crates must not create subtly different address, hash, resource, or block types.
- Consensus has no socket, database engine, RPC, telemetry, or native compiler dependency.
- Runtime defines module semantics and backends; execution defines scheduling and state-transition coordination.
- P2P carries canonical bytes; external RPC is not used inside consensus.
- Storage means validator-local blockchain persistence, not a user storage/share service.
- Telemetry, prediction, caches, SIMD, AOT, JIT, and parallelism may alter performance but never canonical outputs.
- Services use separate identities and cannot access validator signing authority.

## Finalization path

```text
transactions -> bounded validation -> mempool -> compact proposal
             -> PoTB weighted committee -> prevote/precommit
             -> immutable snapshot -> deterministic execution
             -> commitment verification -> atomic finalized storage
```

Consensus fixes transaction order. Execution produces receipts and state diffs. Finalized state is published only after the certificate and execution commitments both validate.

## Status vocabulary

Every area carries one grade from this ladder, recording how far that area has been
carried:

- **Planned:** specified in the engineering documents, with no Rust interface yet.
- **Interface baseline:** compileable types and traits fix the boundary before behavior lands.
- **Implemented:** concrete behavior exists.
- **Tested:** positive and negative behavior is automated.
- **Benchmarked:** reproducible measurements exist for a stated machine and revision.
- **Audited:** an independent external review has completed and its findings are addressed.
- **Production-ready:** release gates, operations, and a supported-version policy are complete.

The repository implements a certified reference network, deterministic execution,
durable storage and ecosystem services. Its daemon integrates
[compact propagation and bounded execution-stage overlap](docs/54-compact-blocks-and-execution-pipeline.md).
The [implementation status](docs/08-implementation-status.md) carries the current
grade for every area and the release gates that remain.
