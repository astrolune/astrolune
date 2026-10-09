<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to AstroLune will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use [Semantic Versioning](https://semver.org/) until a protocol-specific compatibility policy supersedes it.

## [Unreleased]

### Fixed

- Clear the inherited non-blocking mode on accepted sockets, which Windows copies
  from a non-blocking listener and read/write timeouts do not reset. The daemon
  metrics endpoint read its request a byte at a time and discarded the resulting
  `WouldBlock`, so a Prometheus scrape could be dropped silently on Windows; three
  test peers raised the same error as a spurious failure.

- Report an exact-height state proof above the answering node's finalized head as
  unavailable rather than a null result, keeping catch-up distinguishable from an
  already finalized height that left the bounded retained index. This changes no
  retention bound and adds no new error surface. Restart tests now wait on the
  queried height instead of a finalized payment, which only proves current state.

- Activate the explicit PoTB configuration in daemon/observer networking, candidate
  provisioning, bounded admission/evidence gossip and atomic `ALEFF003` handoff storage.
  Add authenticated RPC/CLI/DNS catch-up, offline sidecars and operator submission.
  Restore pending inclusions even when a single-member VRF batch is already complete.
  Preserve legacy encodings and add TLS, client, CLI, DNS and recovery coverage.

- Add deterministic delivery simulations for genesis-v2 and PoTB networks, checking
  shared finalized history under partitions, loss, delay, duplication, invalid
  messages and restart, followed by authenticated observer catch-up.

- Qualify the Rust 1.99.0 update against strict Clippy and the renamed atomic API.
  Resolve native/contract compilers explicitly through rustup, and bind archive
  compiler identity and binary hashes to the independent-build report.

- Refresh the 2026-10-02 stable toolchain to Rust 1.99.0 and `wat` 1.260.0,
  including an explicitly new contract source-package compiler profile.

- Add candidate consent, typed protected admission approvals, incumbent weighted
  quorum certificates and an offline CLI using authenticated committee sidecars.
  Keep activation separate from existing genesis-v1/v2 execution and expand the
  deterministic million-input campaign to 71 structured seeds.

- Reuse one fully verified VRF transition across repeated execution without changing
  canonical results or committee authority; verify recovered evidence through one
  shared historical stream. Add cache equivalence and mixed execution measurements.
- Authenticate CLI double-vote proofs against historical rotating committees and
  retain bounded offline handoff sidecars; reject votes from former members.
- Keep partial TCP reads/writes on their original absolute deadline when Windows
  reports an early socket timeout. No transaction or whole RPC call is resubmitted;
  real connection failures still propagate.

- Activate explicit genesis-v2 VRF networking with complete-roster proof gossip,
  protected standby participation, verified restart, persisted handoff RPC,
  bounded client catch-up, offline CLI proof sidecars and rotating DNS verification.
  Version-1 networks retain their fixed profile. Add real mutual-TLS process and
  adversarial recovery tests and extend the mutation corpus to 16 structured seeds.

- Upgrade the pinned native/wasm32 compiler to Rust 1.98.1 and refresh dependency
  locks. Migrate vault encryption to the current AEAD API while retaining a
  compatibility fixture produced by the original providers.
- Add the project README banner and deterministic native archives containing all
  four binaries, documentation, normalized metadata and per-file SHA-256 hashes.
- Run real Rust-to-WASM package/SDK checks in the Linux/Windows release-test matrix.

- Add complete VRF contribution collection, bounded authenticated committee handoff,
  rotating-producer system execution with reserved resources, full history replay,
  and state/receipt verification against an independent handoff stream.
  Version-1 daemon profiles retain fixed membership.

- Verify RFC 9381 VRF proofs for registered keys, reject noncanonical/malleable proofs,
  bind inputs to chain/parent/height/role, and implement unbiased weighted selection.
- Correct partial-rotation replacement counts and distinguish the legacy demonstration sampler.
- Add parallel signed payments and ABI-v2 mixed contract waves with serial replay and atomic commit.
- Add bounded integer WebAssembly execution, pinned Rust artifact tools, explicit genesis
  contract activation, signed deployment/call CLI and certified recovery/catch-up coverage.
- Remove the README warning and update implementation status.
- Add allocation-free Rust host bindings with a dedicated wasm32 FFI boundary,
  bundled SDK builds and interpreter tests covering all host imports.
- Add OS-generated wallet keys, fixed-cost Argon2id/XChaCha20-Poly1305 vaults,
  bounded stdin passwords and direct encrypted-wallet signing.

- Replace stale simulated-network consensus documentation with the certified
  fixed-committee implementation boundary and explicit PoTB activation limits.

- Fund newly generated devnets at the domain-separated wallet address accepted by
  signed-payment execution; the former raw public-key hash could not spend its
  allocation. Existing genesis files are not rewritten.

- Replace CLI offline status and mock-key output with real node queries and public
  wallet identity derivation. Bound shared JSON nesting and reject ambiguous
  duplicate keys, malformed numbers/control characters and invalid Unicode escapes.

- Reject relabelled non-consensus handles when requesting consensus signatures from the mock keystore.

- Authenticate consensus votes before counting power; isolate heights, rounds, phases, and blocks, reject repeated nil votes, distinguish signed conflicts, and check full-width committee sums.

- Release exact mempool byte capacity on single and batch removal; reject byte-count overflow.
- Compute strict two-thirds quorum without saturation for the full `u128` validator-weight range.
- Remove the workspace member reference to the deleted isolation service.
- Bound and preflight genesis lists before allocation; reject unsupported versions, invalid identities/order/committee parameters, and aggregate validator-weight overflow before hashing or materialization.
- Reject malformed daemon arguments and fail startup on listener errors; expose only durably committed heads and bound the service observation history.
- Replace XOR block IDs and receipt commitments with canonical domain-separated BLAKE2s; reject child headers after height exhaustion.
- Authenticate the genesis header contents and first-child height when checking synchronized ancestry.
- Verify stored transaction bodies against header commitments before publication, and enforce the transaction decoder's access-list count limit.
- Replace truncated XOR state/diff commitments with domain-separated BLAKE2s commitments and count-bound Merkle state roots.
- Stage state before checking finalized roots; preserve state, checkpoints, and pending transactions on rejected proposals or failed commits.
- Propagate node commit failures, enforce parent linkage and checked heights, and preserve the latest checkpoint during pruning.

- Replace the custom hash and forgeable signature placeholders with standard BLAKE2s-256 and strict Ed25519; reject unknown validator keys and unsupported VRF proofs.
- Bind transaction IDs to every canonical field and signature, and use consistent transaction IDs and cryptographic Merkle roots in block assembly.
- Check exact transaction sizes, resource-cost overflow, and nonce exhaustion; preserve sender nonce and admission sequence when mempool insertion fails.
- Reject non-minimal length prefixes, reserved length markers, and non-canonical receipt booleans without changing canonical encoder output.
- Validate complete transaction structure before allocating access lists and payloads; enforce state-key limits before reading key content.
- Make the codec fuzz package independently resolvable and add exact-byte re-encoding checks for transactions, state keys, and execution receipts.

### Added

- Add a standard-library benchmark harness and per-crate benchmarks for the
  cryptographic, codec, transaction, state, storage, execution, runtime and
  consensus paths. No dependency is added, so the pinned licence baseline is
  unchanged. Benchmarks carry no assertions and cannot fail CI, which lints but
  does not run them. Several documents asserted costs that had never been
  measured and are now corrected: recovery replay is not linear when the account
  set grows, the execution-parent cache and declared-key prefetch show no
  wall-clock benefit against an in-memory parent, and parallel payment execution
  peaks near 2.6x rather than scaling with worker count.

- Add a separately committed PoTB configuration, canonical evidence/admission
  batches, active age weights, permanent exclusion records and old-quorum state
  handoffs. Integrate the profile with explicit block production, reserved system
  resources, atomic payment execution and authenticated replay on both storage
  backends. Existing genesis-v1/v2 networks retain their rules; daemon activation
  remains separate. Expand the shared mutation corpus to 78 structured seeds.

- Add bounded committee-history frontiers and portable historical double-vote bundles.
  Verified handoffs build this local history atomically; active PoTB inclusion remains
  an explicit future profile. Record quorum-authorized admission as the chosen policy.

- Freeze 50 fixed/rotating protocol fixtures with authenticated replay and independent
  Python framing/commitment checks; expand the shared oracle to 64 seeds and qualify
  a one-million-input deterministic mutation campaign.

- Scoped private-network peer discovery over mutual TLS, bounded reusable sessions,
  reconnect backoff, fixed-cardinality Prometheus metrics and authenticated history
  verification/export for observer recovery without copying signing authority.
- Certified state membership/absence RPC, independent genesis/quorum verification
  and offline proof CLI.
- On-chain name registry with bounded leases, owner-authorized transitions,
  confusable-name reservations and an authenticated operational resolver.
- Bounded offline Rust source packages, bundled SDK/profile commitments, exact
  artifact reconstruction and real multi-file WASM reproducibility tests.
- Atomically persisted execution receipts, bounded recent transaction indexes,
  certified receipt queries, offline verification and finality waiting without
  transaction resubmission; receipt-aware archive version 3 and log payload tag 2.

- Canonical authenticated double-vote proofs, bounded BFT evidence retention,
  durable validator evidence files with restart verification and CLI proof tools.
- Conservative integer-only PoTB policy workbench over authenticated contiguous
  finalized history; candidate scores remain separate from active genesis weights.

- Offline native-payment signing, signature/policy inspection, exclusive saved
  transaction files and explicit submission with chain/expiry checks, transaction
  ID verification and ambiguous-outcome reporting.
- Typed TCP RPC client with bounded frames, strict response validation, finalized
  account decoding and one absolute deadline per call; no automatic retry.

- Bounded protected signing-journal rollover beyond 100,000 decisions using two alternating watermarks in the same exclusively locked file, preserving the immutable prefix and BFT locks.
- Rollover fault-injection, mutation/vector, hard-link/process-lock and abrupt-exit tests, plus certified payment/restart coverage across the real journal boundary.

- Append-only block/state-delta logs for new certified validator and observer directories, durable head publication, on-demand disk history reads, and non-destructive legacy archive compatibility.
- Streaming recovery, historical snapshot replay, crash-tail and uncertain-publication tests, progress beyond 4096 blocks, and daemon shutdown on local history read corruption.

- Explicit non-voting full nodes with independently verified finalized catch-up, re-execution, account/payment RPC, and certified history serving without consensus keys or journals.
- Shared validator/observer archive authentication, persistent observer role separation, optional observers in devnet provisioning, and multi-process TLS payment/restart tests.

- Mutually authenticated TLS 1.3 peer sessions with explicit CA trust, mandatory ALPN, startup identity validation, separate random transport keys, and absolute handshake/packet deadlines.
- TLS provisioning in `cli devnet` and standalone `cli init-network-tls`, explicit loopback-only plaintext mode, negative authentication/deadline tests, and multi-process payment/recovery tests over TLS.

- Opt-in certified daemon network with fixed genesis membership, signed round-robin proposals, real weighted BFT quorums, monotonic timers, payment gossip, and sequential certified catch-up.
- Bounded versioned network envelopes and TCP packets with absolute I/O deadlines; protected signer provisioning, a durable proposal/evidence cache, and independent authentication of recovered history.
- `cli devnet` local fixtures and launch instructions, `cli init-validator` explicit journal provisioning, real multi-process network/restart tests, quorum-loss and locked-round recovery tests, and a network decoder fuzz target.

- Canonical genesis-bound signed proposal envelopes, protected proposal reservations, designated-author verification, valid-round evidence binding, and restart-safe proposal retries.
- Explicit reference round-robin validator participant connecting proposal execution, authenticated voting, bounded collection, timeout events, atomic commit, and recovery; four-participant payment and round-change conformance tests.

- Fixed-height local prevote/precommit guard, authenticated valid-round proofs, lock-preserving timeout transitions, restart recovery, and bounded canonical prevote certificates.
- Version-2 signing journals atomically reserve the vote digest, committee, and lock; reject raw signing downgrades and invalid safety transitions while retaining explicit version-1 compatibility.
- Read-only producer proposal validation and a signed payment/local vote/finality/archive recovery pipeline with failed-write rollback tests.

- Durable Ed25519 signing with a bounded append-only decision journal, chain/genesis/key binding, process locks, strictly increasing signing positions, and idempotent retries after restart.
- Typed vote signing with protected phase mapping, fault-injection and process-exit recovery tests, and independent signing-journal checksum vectors.

- Version-1 committee commitments, signed vote/certificate envelopes, registered Ed25519 quorum verification, and bounded round-local collection.
- Explicit certified producer proposal/commit APIs, independent hash vectors, decoder fuzz target, weighted-subset regressions, and payment/certificate archive recovery with failed-write retry tests.

- Version-1 canonical transaction envelopes with signed expiry, explicit lanes, and resource prices; enforce policy during admission and execution and release expired pool entries after durable commit.
- Reject unsupported transaction versions before storage publication; archive version 2 rejects incompatible version-1 files without rewriting.

- Version-1 signed native payments on genesis-backed chains: sequential account overlays, balance/nonce transitions, deterministic one-unit burned fees, declared access/resource checks, execution revalidation, atomic rollback and recovery.
- Daemon RPC submission and committed account reads connected to the node, with real TCP/restart tests and replay rejection.
- Daemon `--genesis PATH` activation with atomic height-zero state installation, genesis identity checks on restart, configured chain/capacity and demonstration committee, plus recovery/failure conformance tests.
- Deterministic genesis account/validator materialization, canonical shared account records, authenticated snapshot reads, independent commitment vectors, recovery/admission tests, and a genesis decoder fuzz target.
- Read-only `cli genesis <file>` verification reporting the genesis hash and initial state root.
- Authenticated state absence proofs with adjacent Merkle witnesses, bounded versioned transport, immutable snapshot/file recovery coverage, and a decoder fuzz target.
- File-backed node service and daemon recovery of block height, parent hash, and execution state; strict data-directory/listener options and recovery-only startup.
- Daemon RPC status follows recovered and newly committed checkpoints; genesis-free account and transaction operations return unavailable.
- Process restart/failure tests and differential state/block checks across repeated node service restarts.
- Bounded file-backed whole-chain archives with atomic commit/import/pruning, retained historical snapshots, writer locks, corruption checks, and process-recovery tests.
- Independent block/receipt hash fixtures and archive format/compatibility documentation in `docs/11-chain-archives.md`.
- Immutable shared state snapshots, bounded transitions, and strict Merkle membership proofs.
- Versioned state files with synchronized atomic replacement, process-held writer locks, corruption detection, and recovery tests.
- Bounded historical snapshot export and staged import against an independently authenticated checkpoint, plus a snapshot decoder fuzz target.
- State-format compatibility specification in `docs/10-state-and-recovery.md`; old flat files and XOR roots require explicit migration.
- State-aware signed transaction admission with explicit resource prices, address/public-key binding, and ordered validation stages.
- Normalized access leases and deterministic greedy execution waves that preserve conflict and sender order, with serial-equivalence tests.
- Standard cryptographic vectors and signed admission-to-mempool integration tests.
- Rust 2024 workspace with protocol, execution, state, networking, node, service, and tooling boundaries.
- PoTB weighted committee and fast BFT finality interfaces.
- Deterministic Rust contract SDK and runtime architecture.
- AstroLune DNS service baseline.
- Validator-local persistence, finalized sync, configuration, keystore, telemetry, RPC, mempool, genesis, and canonical codec crates.
- Workspace integration tests, CI, dependency checks, contribution templates, and project documentation.

[Unreleased]: https://github.com/astrolune/astrolune
