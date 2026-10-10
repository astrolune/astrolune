<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

<div align="center">

![AstroLune — Rust, VRF and BFT](docs/assets/astrolune-banner.png)

# AstroLune

### A Rust-first foundation for a verifiable, fast-finality network

AstroLune implements **Proof of Trusted Behavior (PoTB)**, weighted VRF committees,
gradual committee rotation, and prevote/precommit BFT finality in a modular Rust workspace.

<p>
  <a href="https://github.com/astrolune/astrolune/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/astrolune/astrolune/ci.yml?branch=master&style=for-the-badge&logo=githubactions&logoColor=white&label=CI" alt="CI status"></a>
  <a href="https://github.com/astrolune/astrolune/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/astrolune/astrolune/security.yml?branch=master&style=for-the-badge&logo=github&logoColor=white&label=Security" alt="Security workflow status"></a>
  <a href="https://github.com/astrolune/astrolune/actions/workflows/markdown-links.yml"><img src="https://img.shields.io/github/actions/workflow/status/astrolune/astrolune/markdown-links.yml?branch=master&style=for-the-badge&logo=markdown&logoColor=white&label=Links" alt="Markdown links workflow status"></a>
</p>
<p>
  <img src="https://img.shields.io/badge/Rust-1.99.0%20%7C%20Edition%202024-dea584?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 1.99.0 and Edition 2024">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/astrolune/astrolune?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="MIT License"></a>
  <a href="https://github.com/astrolune/astrolune"><img src="https://img.shields.io/github/repo-size/astrolune/astrolune?style=for-the-badge&logo=github&logoColor=white" alt="Repository size"></a>
</p>

<p>
  <a href="#overview">Overview</a> ·
  <a href="#design-pillars">Design</a> ·
  <a href="#repository-layout">Repository</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#documentation">Documentation</a>
</p>

</div>

## Overview

AstroLune is a modular blockchain node implemented as a Rust workspace. It is built around explicit subsystem boundaries, deterministic behavior, bounded resource use, and wire interfaces that carry explicit version and profile tags.

| Area | Direction | Current shape |
| --- | --- | --- |
| Consensus | PoTB weight, weighted VRF committees, partial rotation | [Live VRF rotation, standby participation and verified catch-up](docs/40-live-vrf-network.md) |
| Finality | Proposal, prevote, and precommit with > ⅔ voting power | Certified fixed or genesis-v2 rotating daemon network |
| Execution | Deterministic state transitions with parallel scheduling | Parallel signed payments and ABI-v2 contract waves |
| Persistence | Snapshots, archives, genesis, accounts, and recovery | Append-only chain log, atomic publication, verified replay recovery |
| Contracts | Restricted deterministic Rust runtime boundary | Metered integer WebAssembly; signed deployment and calls |
| Ecosystem | AstroLune DNS registry and resolution | On-chain ownership/leases and certified-proof resolver |

## Design pillars

| Pillar | What it means |
| --- | --- |
| **PoTB consensus weight** | Finalized time, behavior, trust, penalties, and caps contribute to validator weight. |
| **Verifiable committees** | Weighted VRF selection and gradual rotation make committee changes explicit and auditable. |
| **Fast finality** | Proposal, prevote, and precommit require voting power strictly above two thirds. |
| **Separated execution** | Consensus fixes order; deterministic execution independently computes state transitions. |
| **Parallel performance** | State leasing, execution waves, optimistic replay, lanes, batching, locality, and prefetch are designed as separate concerns. |
| **Deterministic contracts** | Restricted Rust source targets a versioned canonical runtime; the interpreter and the ahead-of-time backend are qualified to agree field for field, including charged compute. |
| **Lean networking** | Bounded binary P2P frames and compact-block reconstruction keep the network surface explicit. |
| **Independent services** | DNS registry and resolution remain separate from validator signing authority. |

## Architecture at a glance

```mermaid
flowchart LR
    A[Binary P2P ingress] --> B[Canonical decode<br/>and validation]
    B --> C[Bounded mempool<br/>and proposal]
    C --> D[PoTB committee<br/>and BFT finality]
    D --> E[Immutable state<br/>snapshot]
    E --> F[Deterministic parallel<br/>execution]
    F --> G[Receipt, resource,<br/>and state commitments]
    G --> H[Atomic local commit]
    H --> I[RPC and ecosystem<br/>notifications]

    classDef core fill:#1f2937,stroke:#94a3b8,color:#f8fafc;
    classDef boundary fill:#312e81,stroke:#a5b4fc,color:#f8fafc;
    class A,B,C,I boundary;
    class D,E,F,G,H core;
```

Prediction, telemetry, cache state, worker count, SIMD availability, and JIT availability may change latency only. They cannot change canonical results.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `apps/cli` | Operator and developer CLI |
| `apps/daemon` | Certified reference network and local demonstration mode |
| `crates/codec` | Canonical bounded encoding |
| `crates/config` | Validated non-secret configuration |
| `crates/consensus` | PoTB committees and BFT finality |
| `crates/contract-sdk` | Rust contract host boundary |
| `crates/crypto` | BLAKE2s, Ed25519, and RFC 9381 VRF |
| `crates/execution` | Deterministic parallel scheduling |
| `crates/genesis` | Validated chain configuration |
| `crates/keystore` | Purpose-separated signing interfaces |
| `crates/mempool` | Bounded admission and proposal policy |
| `crates/node` | Subsystem pipeline coordination |
| `crates/p2p` | Binary frames and compact blocks |
| `crates/rpc` | External wallet/application API |
| `crates/runtime` | Bounded WebAssembly validator and interpreter |
| `crates/state` | Snapshots, leases, and state diffs |
| `crates/storage` | Validator-local durable persistence |
| `crates/sync` | Finalized block and snapshot sync |
| `crates/telemetry` | Local-only observability |
| `crates/testkit` | Deterministic fixtures and the bounded benchmark harness |
| `crates/transaction` | Transaction validation boundaries |
| `crates/types` | Canonical shared protocol types |
| `services/dns` | Authenticated in-network naming |
| `tests/integration` | Workspace-level conformance tests |
| `tools/cargo-contract` | Pinned Rust builds, artifact verification and sandbox tests |

## Prerequisites

Validator hardware requirements depend on the deployment profile:

| Profile | CPU | RAM | Storage |
| --- | --- | --- | --- |
| Mainnet minimum | 12 cores at 2.8 GHz or higher | 128 GB | 1 TB NVMe SSD |
| Mainnet recommended | 24 cores at 2.8 GHz or higher | 256–512 GB | 2 TB NVMe SSD |
| Testnet / local development minimum | 8 cores | 16 GB | 50 GB free disk space |

Mainnet participation targets operators able to meet this hardware profile. These are design requirements rather than measured figures, and the daemon does not enforce them. See [validator hardware and operational requirements](docs/07-validator-requirements.md).

The repository pins Rust `1.99.0` with rustfmt and Clippy through [`rust-toolchain.toml`](rust-toolchain.toml). Install Rust with [rustup](https://rustup.rs/); entering the repository selects the pinned toolchain.

On Windows with an older standalone Rust installation in `PATH`, run
`. ./tools/enter-dev.ps1` to select the rustup proxies in the current shell.

Cryptographic foundations use pinned BLAKE2s and Ed25519 backends; dependency versions are recorded in `Cargo.lock`. Reference state and [whole-chain archive persistence](docs/11-chain-archives.md) use standard-library file I/O and locks.

## Quick start

Clone the repository and verify the complete workspace:

```sh
git clone https://github.com/astrolune/astrolune.git
cd astrolune

cargo metadata --no-deps --format-version 1
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

On PowerShell, set rustdoc flags with:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps
```

Try the intentionally minimal entry points:

```sh
cargo run -p cli -- --help
cargo run -p daemon -- --help
cargo run -p cargo-contract -- --help
```

### Certified local network

```sh
cargo run -p cli -- devnet target/local-network 4
# Optional rotating committee with contracts and an observer:
cargo run -p cli -- devnet target/rotating-network 4 --vrf --contracts --observer
```

Add `--observer` to provision an additional non-voting full node with its own TLS identity and RPC endpoint. [Observer setup and recovery](docs/21-observer-nodes.md) describe independent verification and operation without consensus keys.

Run the four commands in `target/local-network/START.txt` in separate terminals. Validators exchange signed proposals and votes over mutual TLS 1.3, gossip native payments, publish certified blocks, and catch up after reconnecting. Consensus and wallet keys are public test fixtures; separate random TLS identities are provisioned automatically. See [network setup, recovery, protocol bounds, and limitations](docs/19-reference-network.md).

New network directories use an [append-only chain log](docs/22-append-only-chain-storage.md). Existing archives remain readable with their original limits; startup identifies the storage format. [Protected signing journals](docs/23-signing-journal-rollover.md) continue beyond 100,000 decisions through bounded watermark rollover.

The [native-payment CLI wallet](docs/24-wallet-and-rpc-client.md) can query real
status/balances, derive wallet addresses, sign payments offline, inspect saved
transactions and submit them through validator or observer RPC. Submission
reports admission separately from finalization and preserves the signed file
when the network outcome is uncertain.

[Certified receipt queries](docs/35-certified-receipts.md) and `wait-finality` independently verify execution against trusted genesis membership. [State proofs](docs/32-certified-state-proofs.md), the [DNS resolver](docs/33-authenticated-name-registry.md) and [contract source packages](docs/34-contract-source-packages.md) have dedicated operator instructions.

[Private-network operations](docs/36-private-network-operations.md) cover scoped peer discovery, reusable TLS sessions, local Prometheus metrics and authenticated history export for observer recovery.

### Local demonstration chain

Run the daemon, then resume it with two additional blocks:

```sh
cargo run -p daemon -- --data-dir node-data --blocks 3
cargo run -p daemon -- --data-dir node-data --blocks 2
cargo run -p daemon -- --data-dir node-data --blocks 0
```

`--blocks 0` verifies recovery without starting listeners or producing blocks. `--dry-run` validates arguments without filesystem or network effects. `--run` produces blocks until stopped or a storage bound is reached. `--p2p-listen` and `--rpc-listen` accept IP socket addresses.

### Genesis-backed node

Verify a canonical binary genesis and calculate its initial account/validator state root:

```sh
cargo run -p cli -- genesis genesis.bin
```

Start or resume a local chain with the same trusted genesis on every invocation:

```sh
cargo run -p daemon -- --genesis genesis.bin --data-dir node-data --blocks 3
```

Genesis initializes a durable height-zero anchor with account balances and validator weights; produced blocks start at height one. A different or missing genesis is rejected on restart. Native signed payments update balances and nonces; without `--validators` this local mode publishes placeholder finality rather than certificates. See [genesis verification and materialization](docs/12-genesis-and-accounts.md), [payment rules and RPC](docs/13-native-payments.md), and the [versioned transaction format](docs/14-versioned-transactions.md).

<details>
<summary>Operational notes</summary>

Without genesis, the daemon uses chain ID 7 and keeps account/submission RPC unavailable. Genesis-backed nodes accept signed native payments and serve committed account bytes through RPC. The mode without `--validators` still uses placeholder certificates; certified networking requires an exact public-key registry and a previously provisioned protected signing journal.

Archive versions 2 and 3 are readable; receipt-producing commits write version 3. Old version-1 archives are rejected without migration or rewriting. The consensus library authenticates votes and certificates; see [authenticated finality](docs/15-authenticated-finality.md). `BlockProducer` provides an explicit certified commit path. The [local BFT guard](docs/17-local-bft-voting.md) verifies prevote proofs and preserves vote locks across timeouts and restarts using a [protected durable journal](docs/16-durable-signing.md).

The [reference round-robin participant](docs/18-signed-proposals-and-participants.md) authenticates signed proposals and coordinates execution, voting, round changes, and atomic publication. The [network driver](docs/19-reference-network.md) connects it to the daemon, mutually authenticated TLS exchange, timers, durable proposal recovery, and certified catch-up. [Transport identity validation and provisioning](docs/20-authenticated-transport.md) are implemented. Verified weighted VRF selection and [live committee rotation](docs/40-live-vrf-network.md) are implemented; distributed calibration and independent review remain open. [Contract profile 2](docs/30-signed-contracts.md) adds explicit genesis activation of signed deployments, calls and parallel mixed execution.

</details>

## Non-goals

- AstroLune provides no transaction privacy or anonymity; finalized account activity is public.
- AstroLune does not include a general-purpose user storage or file-sharing marketplace. `storage` is validator-local blockchain persistence.
- External RPC does not carry internal consensus traffic.
- Arbitrary native Rust binaries are not deployable contracts.
- Ecosystem services do not receive validator signing authority.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Concise source-tree and subsystem map |
| [Engineering documentation](docs/README.md) | Detailed protocol and implementation documents |
| [Contributing](CONTRIBUTING.md) | Contribution workflow and expectations |
| [Security policy](SECURITY.md) | Vulnerability reporting and security scope |
| [Support](SUPPORT.md) | Help and issue routing |
| [Governance](GOVERNANCE.md) | Project decision-making |
| [Roadmap](ROADMAP.md) | Planned work and milestones |
| [Changelog](CHANGELOG.md) | Notable changes |
| [Release process](RELEASING.md) | Release checklist |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Community standards |

## License

AstroLune is available under the [MIT License](LICENSE).

<div align="center">

<sub>Built with Rust · Designed for deterministic, verifiable systems</sub>

</div>
