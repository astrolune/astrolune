<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 21. Non-voting Full Nodes

## Implemented role

The certified reference daemon supports an explicit `--observer` role. An observer maintains the complete certified chain and account state, independently checks finality, re-executes imported blocks, serves finalized history to other nodes, and accepts signed native payments through the existing RPC for peer gossip.

An observer never loads a consensus seed, opens a signing journal, originates a proposal, signs a vote, or contributes voting power. It ignores live proposal/vote/available-value messages and never relays them. The trusted genesis and exact public validator registry still determine the committee that authenticates every finalized block. Observer count has no effect on the strict greater-than-two-thirds quorum. Transport admission still requires a [TLS identity](20-authenticated-transport.md); a transport certificate provides no consensus authority.

## Start a local network with an observer

```sh
cargo run -p cli -- devnet target/observer-network 4 --observer
```

The optional flag creates four validators plus a separate `observer` directory with its own random TLS identity. It does not create a consensus seed or journal for the observer. `START.txt` contains five commands and configures reciprocal peer polling. Validator ports retain their existing assignments; the observer uses P2P port 18000 and RPC port 19000. The genesis membership remains four validators.

For an existing network, supply a transport identity trusted by its CA, the original public genesis and registry, and a separate data directory:

```sh
cargo run -p daemon -- --observer --run \
  --genesis genesis.bin --validators validators.bin \
  --tls-dir observer-tls --data-dir observer-data \
  --p2p-listen 127.0.0.1:18000 --rpc-listen 127.0.0.1:19000 \
  --peers 127.0.0.1:18001,127.0.0.1:18002,127.0.0.1:18003
```

Configure validators to poll the observer address as well if transactions submitted to its RPC must reach them, or enable [scoped discovery](36-private-network-operations.md) for reciprocal authenticated routes. The version-1 request selects a height; gossip is returned when peer heights agree. An observer that only polls validators can catch up and serve RPC reads, but its outbound polling alone does not push pending transactions to them. Payment admission at an observer's current head does not guarantee inclusion or finality.

`--observer` requires `--validators` and `--genesis`, rejects `--validator-key` and `--round-timeout-ms`, and uses the same explicit transport selection as validators. `--blocks N` counts imported certified heights; with no available finalized blocks it waits. `--blocks 0` verifies recovery without opening listeners. `--dry-run` validates public network context, TLS identity, and directory-role compatibility without writing files.

## Recovery and role separation

Observers share the validator's complete-history recovery path: every retained certificate is checked against a height-bound committee reconstructed from the original genesis, and ancestry must reach that exact genesis. During synchronization, certificate verification precedes block execution and atomic state publication. Gaps, stale blocks, forged signatures, inconsistent bodies, and malformed exchanges cannot advance the head. The observer serves only durably committed account and chain state.

The data directory contains `chain.bin` and a 36-byte `observer.mode` marker (`ALOB` followed by the genesis hash). The marker is synchronized and validated on restart. Local demonstration mode rejects this marker even when the observer is still at genesis, preventing accidental placeholder finality. Observer startup rejects directories containing `signing.journal` or `consensus-cache.bin`; use a separate directory instead of switching an active validator's data directory to another role.

No observer API provides signing authority. Storage failures propagate as fatal local errors, preserving the previous published checkpoint and pending transactions until the process exits. Recovery reopens and authenticates the archive before retrying synchronization. Pending transactions remain volatile across process loss, as in the validator profile. TLS private keys remain secrets even though observer operation needs no consensus secret.

## Validation and limits

Tests cover payment admission/gossip, certified catch-up, observer-to-observer history serving, restart, replay rejection, forged finality, mutated block bodies, nonsequential heights, truncated exchanges, insufficient validator quorum, archive write failure, role separation, and rejection of demonstration history. A multi-process TLS test submits a payment to an observer, finalizes it with three of four validators, and checks recovery without any observer consensus seed or journal.

New observers use the append-only log and fixed genesis committee; legacy archives remain supported. Signed contracts, scoped discovery, bounded sessions, metrics and authenticated observer export are implemented. Physical retention, PoTB/VRF activation, committee rotation and public-network qualification remain open for this role. No new hardware benchmark or throughput claim is made.
