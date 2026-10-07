<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 7. Validator Requirements

## 7.1 Status

AstroLune targets a mainnet validator set running on powerful hardware, with a separate, lighter profile for testnet and local development. Participation is open to operators who meet the applicable hardware and protocol requirements; mainnet validation is not designed for arbitrary consumer machines.

The following hardware baseline is a project design requirement, not a measured throughput or latency guarantee. The current daemon does not automatically enforce these hardware thresholds. Distributed benchmarks must validate performance and operating headroom before production capacity and timing parameters are finalized.

### Mainnet validators

| Resource | Minimum | Recommended |
| --- | --- | --- |
| CPU | 12 cores, 2.8 GHz or higher | 24 cores, 2.8 GHz or higher |
| RAM | 128 GB | 256–512 GB |
| Storage | 1 TB NVMe SSD | 2 TB NVMe SSD |

Mainnet capacity planning targets this validator class. Additional CPU, memory, and storage headroom supports deterministic execution, signature verification, state access, and recovery under load. Core counts refer to CPU cores, not a count inflated by simultaneous multithreading.

### Testnet and local development

| Resource | Minimum |
| --- | --- |
| CPU | 8 cores |
| RAM | 16 GB |
| Storage | 50 GB of free disk space |

This lighter profile is for testnet participation and local development with appropriately reduced network load and retained data. It does not qualify a machine for mainnet validation. Running several local validators on one machine shares its resources; aggregate requirements depend on process count and workload. Storage requirements must be revisited as retained chain history grows.

## 7.2 Functional responsibilities

A validator must:

- maintain and verify finalized state;
- compute PoTB weight from finalized inputs;
- produce and verify VRF proofs for assigned roles;
- follow proposal, prevote, precommit, lock, timeout, and rotation rules;
- persist anti-equivocation decisions before sending signed consensus messages;
- reconstruct and validate compact blocks;
- execute committed transaction order deterministically;
- verify receipts, resources, and state commitments;
- retain or obtain data required for synchronization and evidence validation;
- isolate validator keys from public ecosystem services.

## 7.3 Operational requirements

Production operators will need low and stable network latency to committee peers, sufficient bandwidth for fallback full blocks, CPU capacity for signature batches and deterministic execution, memory for snapshots and caches, and predictable durable I/O for sequential commits.

Capacity headroom must cover degraded conditions, not only average blocks. Nodes that merely match current limits cannot safely absorb compact-block misses, replay conflicts, snapshot work, or catch-up traffic.

## 7.4 Key safety

Consensus keys should use a dedicated signer or hardware-backed isolation where supported. Network identity, wallet, service, and validator consensus keys are separate. Active/passive failover must prevent two instances from signing at the same height and round.

Backups protect key availability but increase exposure. Recovery procedures must be tested without running a second active signer.

## 7.5 Adaptive capacity participation

Validators may publish quantized capacity observations defined by protocol. Raw machine metrics stay local. Operators must not expect reported hardware to grant PoTB weight or rewards automatically; otherwise adaptive sizing becomes a purchasable-consensus channel.

The network activates only bounded capacity values finalized under the protocol. Mainnet capacity is calibrated for the mainnet hardware baseline; testnet and development capacity is calibrated separately. A node cannot lower its network's consensus limits by selecting a lighter local hardware profile. Operators meeting the existing baseline need a documented upgrade and deprecation window before protocol floors rise.

## 7.6 Preliminary benchmark suite

Before a public testnet, measure:

- operation on the 8-core, 16 GB RAM, 50 GB free-space testnet baseline;
- proposal-to-prevote, prevote-to-precommit, and certificate latency at p50/p95/p99;
- committee sizes and 5%, 10%, 15%, and 20% rotation;
- compact-block reconstruction success and fallback bandwidth;
- signature verification by batch size and worker count;
- sequential and parallel execution by conflict rate;
- prediction accuracy and deterministic replay cost;
- snapshot read scaling, prefetch, cache tiers, and commit latency;
- AOT, JIT warm-up, native-cache hit rate, and interpreter parity;
- behavior under packet loss, partitions, slow disks, corrupt frames, and worker failure.

The calibration report must state hardware, software revision, network topology, sample sizes, confidence intervals, and raw reproducible data.

Before mainnet, repeat calibration on both the minimum and recommended mainnet configurations, including catch-up and degraded conditions. The lighter testnet results do not establish mainnet capacity.

## 7.7 Security posture

Until cryptographic suites, PoTB behavior, rotating weighted BFT, execution semantics, state recovery, P2P defenses, and key operations receive independent review, AstroLune validators are experimental and must not secure material value.
