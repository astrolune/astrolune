<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# AstroLune Roadmap

Dates are intentionally absent until maintainers publish resourced release targets. Milestones describe dependency order, not promises.

## Baseline — in progress

- [x] Rust 2024 workspace and strict lint policy.
- [x] Core protocol, execution, storage, network, service, and tooling crate boundaries.
- [x] Repository documentation, CI, dependency policy, and contribution templates.
- [x] Initial pure invariant and integration tests.
- [x] Review public interface naming, preserve compatibility aliases and distinguish demonstration/runtime trust boundaries; [baseline](docs/50-public-interfaces.md).

## M1 — canonical foundations

Canonical encodings, protocol domains, hashes, addresses, signatures, checked resource arithmetic, golden vectors, property tests, and decoder fuzzing.

- [x] Strict primitive/current-transaction codecs and canonical-byte regression tests.
- [x] Standard BLAKE2s-256, strict Ed25519, transaction signing/ID domains, and address derivation.
- [x] Checked resource pricing and cryptographic conformance vectors.
- [x] Bounded version-1 genesis, validated commitments, initial account/validator state, and CLI verification.
- [x] Atomic daemon genesis activation, restart identity checks, and preserved initial account state.
- [x] Version-1 signed transactions with expiry, explicit lanes, signed prices, and strict decoding.
- [x] Version-1 signed votes and finality certificates, checked committee commitments, and independent Ed25519 quorum verification.
- [x] Versioned reference-network envelopes and opt-in certified daemon finality.
- [x] Canonical RFC 9381 VRF proofs, role-bound context, RFC vectors and malformed-proof rejection.
- [x] Freeze supported genesis-v1/v2 histories in 50 binary compatibility fixtures, with authenticated replay and independent commitment/framing checks; [details](docs/41-protocol-compatibility.md).
- [x] Freeze eight separate PoTB producer-profile fixtures, with authenticated replay and independent framing/commitment checks; [details](docs/44-potb-state-transitions.md).
- [x] Qualify explicit governance envelopes, daemon activation and preserved legacy compatibility; [rules and tests](docs/48-parameter-governance.md).
- [x] Shared extension fuzz oracle, 99 structured seeds and deterministic one-million-input mutation campaign; [qualification details](docs/37-protocol-qualification.md).
- [ ] Long fuzz campaigns, dependency/security review, and cross-platform suite qualification.
- [x] Upgrade qualification: current stable dependencies, legacy vault compatibility,
  strict Rust 1.99.0 checks and bounded registry advisory lookup; [evidence](docs/39-toolchain-and-release-qualification.md).

## M2 — transactions and state

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, state diffs, atomic commit, recovery, pruning, and snapshot exchange.

Current progress: signed admission validates existing transaction fields against an account view. Merkle state commitments, membership and absence proofs, immutable snapshots, bounded transitions, atomic state/whole-chain archive recovery, and verified snapshot exchange are implemented with rollback tests. Proposal execution stays private until successful commit. Sequential signed payment overlays, balance/nonce transitions, fixed reference fees, execution revalidation, and daemon account/submission RPC are implemented. The [versioned transaction envelope](docs/14-versioned-transactions.md), expiry enforcement, and post-commit expiry eviction are implemented. [Append-only block/delta logs](docs/22-append-only-chain-storage.md) now provide durable publication, disk history reads, linear replay and legacy compatibility for new network directories. [Protected signing-journal rollover](docs/23-signing-journal-rollover.md) now continues after the former decision cap with constant file size and lock-preserving recovery. Bounded recent transaction indexing and certified receipt recovery are implemented. Quorum fee/capacity governance and bounded historical state indexing are implemented. Explicit bounded history export and pinned recovery are implemented; automated retention and rollback-resistant key custody remain open. Local daemon block/state restart integration is implemented; daemon signing-state integration and independent authentication of recovered history are implemented in the certified reference-network profile. See [state and recovery](docs/10-state-and-recovery.md) and [chain archives](docs/11-chain-archives.md).

## M3 — deterministic Rust contracts

Pinned contract toolchain, canonical target selection, validator, interpreter, host ABI, metering, SDK, reproducible artifacts, source verification, and differential backends.

- [x] Integer-only WebAssembly ABI v2 validator and interpreter with bounded memory, fuel, state access and staged writes/events.
- [x] Pinned Rust 1.99.0 standalone contract builds, repeated-byte comparison, artifact validation, sandbox execution and code-hash verification CLI.
- [x] Signed deployment/call transactions, nonce/fee transitions, explicit genesis activation and certified restart/catch-up tests.
- [x] Allocation-free Rust SDK bindings, bundled builds and real wasm32 host-call tests.
- [x] Restricted Cargo package/source manifests and offline published-source verification.
- [ ] Qualified alternate backends and contract fuzz campaigns.

Implemented behavior and the remaining activation boundary are specified in [document 29](docs/29-parallel-payments-and-wasm.md).

## M4 — parallel execution

Access leasing, execution waves, multiple lanes, optimistic validation, deterministic conflict replay, locality, fusion, caches, prefetch, object pools, and signature batches.

- [x] Parallel signed payment waves with checked actual access, private overlays and serial error replay.
- [x] Node verification/replay integration and serial/parallel differential tests across worker counts.
- [x] Mixed contract/payment waves, aggregate capacity enforcement and deterministic serial replay.
- [x] Explicit rotating-producer system lane with reserved VRF resources, mixed application execution and atomic publication.
- [x] Explicit genesis-v2 daemon activation of the VRF system lane.
- [x] Consensus capacity/fee governance: more than 2/3 incumbent weight, next-epoch activation; [details](docs/48-parameter-governance.md).
- [x] Bounded verified VRF transition cache and single-pass evidence history verification, with equivalence tests and [local measurements](docs/40-live-vrf-network.md#repeated-verification-cost).
- [x] Bounded execution-parent read cache and borrowed-key wave planning, with uncached/serial equivalence and deterministic read-count checks; [scope](docs/29-parallel-payments-and-wasm.md#execution-parent-cache-and-planner-allocation).
- [x] Reuse a bounded worker pool across each block's parallel waves, with thread-count and serial-equivalence checks; [scope](docs/29-parallel-payments-and-wasm.md#per-block-worker-reuse).
- [x] Reference execution locality through borrowed-key planning and parent caching, consecutive singleton-wave fusion, bounded declared-key prefetch and reusable worker result buffers, with serial-equivalence checks; [scope](docs/29-parallel-payments-and-wasm.md#fusion-prefetch-and-result-buffer-reuse).
- [ ] Signature batching with equivalence tests; deferred with cryptographic verification work.

## M5 — PoTB and finality

PoTB state transitions and evidence, audited VRF provider, weighted sampler, partial rotation, producer selection, prevote/precommit state machine, certificates, anti-equivocation journal, formal models, and adversarial simulations.

- [x] Registered-key ECVRF proof generation/verification and offline operator commands.
- [x] Complete-roster weighted sampling without modulo bias, partial-rotation computation and producer-role sampling.
- [x] Bounded full-roster collection, parent randomness, authenticated handoff, rotating execution/history replay and proof-verifier APIs; [details](docs/38-authenticated-committee-handoff.md).
- [x] Activate VRF in the daemon: contribution gossip, complete-roster availability policy, standby signing participation, persisted handoff serving and RPC/CLI/DNS catch-up; [profile and tests](docs/40-live-vrf-network.md).
- [x] Bounded historical committee commitments and portable offence bundles; [format and selected quorum-admission policy](docs/42-historical-potb-evidence.md).
- [x] Candidate consent, protected incumbent approvals, weighted quorum certificates and offline operator CLI; [details](docs/43-quorum-admission.md).
- [x] Canonical evidence inclusion, active PoTB weights and quorum-authorized admission in an explicit producer profile, with atomic application execution and authenticated recovery; [details](docs/44-potb-state-transitions.md).
- [x] Activate the PoTB profile in daemon provisioning, gossip, persisted handoff serving and RPC/CLI/DNS catch-up; [workflow and limits](docs/45-live-potb-network.md).
- [x] Deterministic rotating-network delivery simulations with partitions, loss, delay, duplicates, invalid messages, durable restart and authenticated catch-up; [scope](docs/46-rotating-network-simulations.md).
- [ ] Broader Byzantine/churn simulations, formal safety/liveness and independent provider review.

The [VRF and sampler specification](docs/28-vrf-and-weighted-selection.md) distinguishes implemented selection from daemon activation.

Current progress: authenticated fixed-height vote collection separates rounds/phases/blocks, rejects equivocation and replays, and emits bounded canonical certificates. The producer can verify a trusted committee and certificate before atomic execution/state publication. [Protocol details](docs/15-authenticated-finality.md). [Durable signing](docs/16-durable-signing.md), monotonic decision recovery, process locking, and typed vote signing are implemented/tested. [Local BFT voting](docs/17-local-bft-voting.md), verified prevote proofs, timeout transitions, and atomic version-2 vote/lock recovery are implemented/tested, including payment execution and certified archive recovery. [Signed proposals and a reference round-robin participant](docs/18-signed-proposals-and-participants.md) now coordinate authenticated proposal signing, execution, vote collection, timeout events, and atomic publication. [Certified reference networking](docs/19-reference-network.md) now adds daemon integration, monotonic timers, persisted available values, explicit provisioning, and certified catch-up. Verified weighted VRF selection, certified handoff and explicit rotating block execution/recovery are implemented. Genesis-v2 daemon activation, historical handoff serving and client catch-up are implemented. Formal distributed liveness and production network qualification remain open.

PoTB progress: [double-vote evidence and a policy workbench](docs/25-potb-evidence.md)
now verify offences, retain durable bounded proofs and evaluate capped integer
scores over finalized history. VRF collection, activation and committee handoff are implemented.
Canonical evidence inclusion, active weight transitions and admission are implemented
in the [separate producer profile](docs/44-potb-state-transitions.md), with
[live daemon and client activation](docs/45-live-potb-network.md).

## M6 — node and networking

Authenticated encrypted transport, peer discovery, rate limiting, compact blocks, finalized sync, bounded queues, stage pipelining, speculative work, external RPC, and adaptive-capacity governance.

- [x] Prepare owned outgoing response snapshots and encode outside the daemon node lock, with byte-equivalence and snapshot-lifetime tests; [scope](docs/19-reference-network.md#response-preparation-and-encoding).
- [x] Decode incoming exchanges once in peer workers and pass owned messages through the bounded mailbox, with receive-path equivalence tests; [scope](docs/19-reference-network.md#incoming-exchange-preparation).
- [x] Integrate optional compact block propagation with owned transaction dictionaries, inline missing bodies and legacy fallback; [format and scope](docs/54-compact-blocks-and-execution-pipeline.md#compact-transport).
- [x] Integrate bounded detached execution, speculative candidate preparation and next-height fetch with sequential voting/publication checks; [pipeline and limits](docs/54-compact-blocks-and-execution-pipeline.md#detached-execution-and-publication).

Current progress: [certified reference networking](docs/19-reference-network.md) connects independent daemon processes with fixed genesis membership, signed proposals/votes, step timers, payment gossip, bounded mutually authenticated TLS 1.3 exchanges, protected journals, durable available-value recovery, and sequential certified catch-up. Local devnet generation and explicit signer provisioning are implemented. Real process tests cover quorum operation, RPC payments, restart, and late join. [TLS identity validation and provisioning](docs/20-authenticated-transport.md) are implemented with independent transport keys and deadline tests. [Non-voting full nodes](docs/21-observer-nodes.md) now independently authenticate history, execute imported blocks, relay payments, serve RPC, and recover without signing authority. [Scoped private-network discovery, bounded TLS sessions, local metrics and authenticated observer recovery](docs/36-private-network-operations.md) are implemented/tested. Explicit pinned history retention is implemented. Public-network hardening and automated retention remain open. Explicit genesis-v2 rotating consensus is implemented.

## M7 — ecosystem

Wallet integration and DNS registry and resolver.

Current progress: the [native-payment CLI wallet](docs/24-wallet-and-rpc-client.md)
derives real public identities, signs payments offline to non-overwritable files,
checks signatures and policy, reads finalized accounts/status, and submits saved
transactions with explicit ambiguous-outcome handling. The typed RPC client has
bounded frames, strict response checks and whole-call deadlines. Encrypted wallet custody is implemented with fixed-cost Argon2id and authenticated encryption; see [SDK and vaults](docs/31-rust-sdk-and-wallet-vaults.md). Certified state membership/absence queries and the on-chain DNS registry with an authenticated resolver are implemented; see [state proofs](docs/32-certified-state-proofs.md) and [DNS](docs/33-authenticated-name-registry.md). Certified receipt queries, bounded recent transaction lookup and authenticated finality waiting are implemented; see [receipts](docs/35-certified-receipts.md).

## M8 — public testnet and production gates

Distributed calibration, interoperability, long fuzz campaigns, reproducible releases, dependency review, external cryptography/consensus/runtime/security audits, key ceremonies, monitoring, incident response, and operator runbooks.

- [x] Deterministic native archive generation, complete binary/document payloads and per-file checksums.
- [x] Two independent native builds with byte-identity checks; Windows verified locally, Linux/Windows gates configured in CI.
- [x] Run pinned Rust-to-WASM SDK and source-package tests in the release CI matrix.
- [x] Provide routine operations and a bounded read-only calibration sampler with raw reports; [runbook and measurement limits](docs/52-network-operations.md).
- [ ] Observe Linux and independent-machine reproducibility and finish release authority/signing qualification.

Detailed status and unresolved decisions are tracked in [`docs/08-implementation-status.md`](docs/08-implementation-status.md).

## Remaining software for a closed network

Private membership does not remove the following unimplemented software work.
External audits, public-testnet calibration and key ceremonies are separate release activities.

- [x] Activate VRF and committee transitions, including restart, complete-roster unavailable-proof policy and catch-up.
- [x] Activate the tested PoTB producer profile across daemon networking, operator provisioning and client verification.
- [x] Connect signed deploy/call transactions to the WebAssembly runtime.
- [x] Complete the Rust SDK host adapter.
- [x] Complete bounded source-package tooling and exact artifact reconstruction.
- [x] Complete mixed-lane execution, capacity/fee governance and reference execution optimizations with deterministic equivalence checks; [scope](docs/29-parallel-payments-and-wasm.md#fusion-prefetch-and-result-buffer-reuse).
- [ ] Qualify signature batching; deferred with cryptographic verification work.
- [x] Add bounded state/transaction indexes and exact-height certified state proofs; [details](docs/47-historical-state-index.md).
- [x] Add explicit bounded history export and independently pinned recovery; [operator workflow and limits](docs/49-pinned-history-retention.md).
- [x] Add encrypted wallet custody, OS-generated wallet keys and direct vault signing.
- [x] Add certified state membership/absence proofs and offline verification.
- [x] Add receipt queries and transaction finality waiting.
- [x] Implement the authenticated on-chain DNS registry and operational resolver.
- [x] Complete scoped private-network peer discovery, bounded sessions, operational telemetry and authenticated observer recovery tooling.
- [x] Complete fixed/rotating protocol compatibility fixtures and deterministic mutation qualification.
- [ ] Complete coverage-guided fuzzing, remaining platform and reproducible-release qualification.

## Remaining work by scope

The reference execution optimizations above do not complete the whole roadmap.

- Security-related work is deferred: signature batching, long coverage-guided and contract fuzz campaigns, Byzantine/churn simulations, formal safety/liveness, provider/dependency review, key custody, release signing and external audits. Alternate runtime backends and automated history retention also remain unimplemented; they require runtime/metering qualification and checkpoint/signing-state recovery design respectively.
- Platform and release evidence remains external to the local Windows checks: Linux suite execution, cross-platform contract artifacts and reproducibility on independent machines. Configured CI gates do not establish observed results.
- M6 reference compact propagation and bounded stage overlap are implemented: peer fetch/decode, detached execution, node-thread voting and sequential commit. Speculation covers local candidate preparation and bounded next-height fetch; execution/voting on uncommitted descendant state is outside this reference profile. [Exact behavior and bounds](docs/54-compact-blocks-and-execution-pipeline.md).
- Routine operations and calibration tooling are implemented. Actual distributed calibration, deployment-specific production acceptance and independent-machine reproducibility remain release activities. Functional equivalence and deterministic read/thread/allocation checks do not establish end-to-end throughput.
