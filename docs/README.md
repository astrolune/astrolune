<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# AstroLune Engineering Documentation

These documents define the Rust-first engineering direction for AstroLune. They replace the earlier C/C++ and custom contract-language design. Unless a feature is explicitly marked **implemented**, it is a target or compileable interface baseline rather than an audited claim.

For a concise source-tree map, read [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Reading order

| Document | Subject |
|---|---|
| [00-overview.md](00-overview.md) | goals, scope, principles, terminology |
| [01-consensus-potb.md](01-consensus-potb.md) | PoTB, weighted VRF committees, rotation, BFT finality |
| [02-architecture.md](02-architecture.md) | Rust workspace, node pipeline, P2P, adaptive capacity |
| [03-vm-and-gas.md](03-vm-and-gas.md) | deterministic Rust runtime, AOT/JIT, lanes, metering |
| [04-state-and-transactions.md](04-state-and-transactions.md) | transactions, leasing, parallel scheduling, snapshots, state commit |
| [05-contract-languages.md](05-contract-languages.md) | Rust smart-contract model and SDK boundary |
| [06-deferred-services.md](06-deferred-services.md) | AstroLune DNS |
| [07-validator-requirements.md](07-validator-requirements.md) | validator behavior and preliminary requirements |
| [08-implementation-status.md](08-implementation-status.md) | baseline, roadmap, gates, and open risks |
| [09-cryptographic-foundations.md](09-cryptographic-foundations.md) | implemented hash/signature suite, signed admission, and compatibility |
| [10-state-and-recovery.md](10-state-and-recovery.md) | Merkle state commitments, proofs, atomic transitions, snapshots, and recovery |
| [11-chain-archives.md](11-chain-archives.md) | atomic whole-chain archives, historical recovery, pruning, bounds, and compatibility |
| [12-genesis-and-accounts.md](12-genesis-and-accounts.md) | bounded genesis, initial account/validator state, commitments, and operator verification |
| [13-native-payments.md](13-native-payments.md) | signed transfers, sequential account overlays, fees, atomic commits, and daemon RPC |
| [14-versioned-transactions.md](14-versioned-transactions.md) | signed expiry, explicit lanes, resource prices, canonical format, and compatibility |
| [15-authenticated-finality.md](15-authenticated-finality.md) | signed votes, committee commitments, weighted certificates, bounded collection, and certified commits |
| [16-durable-signing.md](16-durable-signing.md) | persistent signing decisions, monotonic recovery, process locks, failure handling, and typed votes |
| [17-local-bft-voting.md](17-local-bft-voting.md) | fixed-height voting, verified prevote proofs, timeout transitions, atomic vote/lock recovery, and proposal validation |
| [18-signed-proposals-and-participants.md](18-signed-proposals-and-participants.md) | signed proposer envelopes, explicit round-robin designation, reference node participant, and recovery |
| [19-reference-network.md](19-reference-network.md) | certified daemon networking, peer exchange, payment gossip, provisioning, catch-up, and restart recovery |
| [20-authenticated-transport.md](20-authenticated-transport.md) | mutual TLS 1.3, independent transport keys, trust boundaries, migration, and deadline enforcement |
| [21-observer-nodes.md](21-observer-nodes.md) | non-voting full nodes, independent verification, payment gossip, RPC, and role-safe recovery |
| [22-append-only-chain-storage.md](22-append-only-chain-storage.md) | append-only block/delta log, atomic publication, recovery, compatibility, and remaining limits |
| [23-signing-journal-rollover.md](23-signing-journal-rollover.md) | bounded protected signing, alternating watermarks, recovery, and compatibility |
| [24-wallet-and-rpc-client.md](24-wallet-and-rpc-client.md) | offline payment signing, real account/status queries, bounded RPC, submission and retry semantics |
| [25-potb-evidence.md](25-potb-evidence.md) | authenticated double-vote evidence, durable outbox, experimental scoring and activation limits |
| [27-explorer-rpc.md](27-explorer-rpc.md) | finalized block history, TCP framing, browser gateway and explorer display limits |
| [28-vrf-and-weighted-selection.md](28-vrf-and-weighted-selection.md) | RFC 9381 proofs, typed domains, canonical envelopes, weighted draws, rotation and activation boundaries |
| [29-parallel-payments-and-wasm.md](29-parallel-payments-and-wasm.md) | parallel payment execution, deterministic WebAssembly sandbox, host ABI, metering and contract tools |
| [30-signed-contracts.md](30-signed-contracts.md) | explicit genesis activation, signed deploy/call, namespaces, fees, mixed waves and certified recovery |
| [31-rust-sdk-and-wallet-vaults.md](31-rust-sdk-and-wallet-vaults.md) | allocation-free WASM SDK, FFI boundary, encrypted wallet custody and password handling |
| [32-certified-state-proofs.md](32-certified-state-proofs.md) | certified membership/absence queries and independent offline verification |
| [33-authenticated-name-registry.md](33-authenticated-name-registry.md) | name ownership, bounded leases and proof-verifying resolver |
| [34-contract-source-packages.md](34-contract-source-packages.md) | bounded offline source bundles and exact artifact reconstruction |
| [35-certified-receipts.md](35-certified-receipts.md) | durable receipts, recent transaction lookup and authenticated finality waiting |
| [36-private-network-operations.md](36-private-network-operations.md) | scoped peer discovery, bounded sessions, local metrics and authenticated observer recovery |
| [37-protocol-qualification.md](37-protocol-qualification.md) | shared decoder/WASM mutation oracle, fuzz entry points and qualification limits |
| [38-authenticated-committee-handoff.md](38-authenticated-committee-handoff.md) | complete VRF batches, old-quorum handoff, rotating system execution and authenticated recovery |
| [39-toolchain-and-release-qualification.md](39-toolchain-and-release-qualification.md) | compiler/dependency upgrades, deterministic native artifacts and verification evidence |
| [40-live-vrf-network.md](40-live-vrf-network.md) | live rotation, standby participation, historical proof catch-up and measured transition reuse |
| [41-protocol-compatibility.md](41-protocol-compatibility.md) | frozen fixed/rotating histories, independent framing checks and compatibility policy |
| [42-historical-potb-evidence.md](42-historical-potb-evidence.md) | bounded historical committee commitments, portable offence bundles and admission policy |
- [Quorum admission authorization](43-quorum-admission.md)
- [Explicit PoTB state transitions](44-potb-state-transitions.md)
- [Live PoTB network and operator workflow](45-live-potb-network.md)
- [Rotating network delivery simulations](46-rotating-network-simulations.md)
- [Historical state index and exact-height proofs](47-historical-state-index.md)
- [Quorum parameter governance](48-parameter-governance.md)
- [Pinned history retention](49-pinned-history-retention.md)
- [Public interface naming and compatibility](50-public-interfaces.md)

Legacy-shaped filenames such as `03-vm-and-gas.md`, `05-contract-languages.md`, and `06-deferred-services.md` are retained temporarily to preserve links. Their contents describe the current Rust architecture.

## Status vocabulary

- **planned** — documented target without an interface;
- **interface baseline** — compileable types and traits, no operational implementation;
- **implemented** — concrete behavior exists;
- **tested** — positive and negative behavior is automated;
- **benchmarked** — reproducible measurements exist;
- **audited** — independent review completed and findings addressed;
- **production-ready** — supported release and operational gates completed.

## Normative language

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express intended protocol requirements. Normative consensus behavior eventually belongs in versioned specifications and test vectors; these engineering documents establish initial boundaries.

## Explicit scope decisions

- All first-party implementation is Rust.
- PoTB remains the primary consensus-weight model.
- Weighted VRF selection and partial committee rotation are required.
- Finality uses prevote/precommit and voting power strictly greater than two thirds.
- Consensus orders transactions; execution independently verifies state transitions.
- Contracts use a deterministic Rust subset; custom languages and ALVM are removed.
- AstroLune DNS is an ecosystem service.
- General-purpose user storage or file sharing is outside scope; validator-local chain persistence remains required.

## License

MIT, copyright AstroLune contributors, 2026.
