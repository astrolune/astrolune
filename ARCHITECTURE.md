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

- **Planned:** documented target without a Rust interface.
- **Interface baseline:** compileable types and traits without operational implementation.
- **Implemented:** concrete behavior exists.
- **Tested:** positive and negative behavior is automated.
- **Benchmarked:** reproducible measurements exist.
- **Audited:** an independent review has been completed and findings addressed.
- **Production-ready:** release gates, operations, and supported-version policy are complete.

Most of the repository is currently an **interface baseline**. The `node` crate now contains **implemented** block production and pipeline coordination with real subsystem integration.
