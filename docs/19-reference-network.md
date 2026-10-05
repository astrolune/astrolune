<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 19. Certified Reference Network

## Working path

The daemon has an explicit network mode connecting signed native payments, transaction gossip, signed proposals, weighted prevote/precommit quorums, durable locks, certified atomic publication, RPC, and sequential catch-up. Independent processes exchange packets over [mutually authenticated TLS 1.3](20-authenticated-transport.md). The original local demonstration mode remains available when `--validators` is absent.

This profile uses the **complete, fixed genesis validator set**, with at most 32 members and the round-robin designation in [document 18](18-signed-proposals-and-participants.md). Genesis weights determine voting power. It does not implement PoTB updates, weighted VRF selection, or committee rotation; `rotation_count` remains committed genesis metadata but is not activated in this explicitly selected profile. All nodes must select the same profile and trusted genesis. The contract runtime remains unfinished.

## Start a local network

The testnet/local-development hardware baseline is 8 CPU cores, 16 GB RAM, and 50 GB of free disk space. Multiple local validator processes share the host's resources, so the required headroom depends on their combined workload. Mainnet has a separate, higher [hardware baseline](07-validator-requirements.md#mainnet-validators).

```sh
cargo run -p cli -- devnet target/local-network 4
```

Open `target/local-network/START.txt` and run its four commands in separate terminals. P2P listeners use ports 18001–18004; RPC uses 19001–19004. The generator creates a canonical genesis, public-key registry, funded test wallet, and a separate seed, protected journal, and TLS identity for each validator. An existing destination is rejected.

**Consensus and wallet keys are public deterministic test fixtures.** Validator seeds repeat bytes 1 through the requested count; `wallet.seed` repeats byte 240. Transport keys are independent random secrets with one-year certificates. The funded wallet receives 1,000,000,000 units. These fixtures are only for local development. For a one-validator smoke test, use `devnet target/single-validator 1`.

Generated commands use the adjacent daemon executable when available (PowerShell invocation on Windows), otherwise `cargo run`. The source-build form is:

```sh
cargo run -p daemon -- --run \
  --genesis target/local-network/genesis.bin \
  --validators target/local-network/validators.bin \
  --validator-key target/local-network/node-1/validator.seed \
  --tls-dir target/local-network/node-1/tls \
  --data-dir target/local-network/node-1 \
  --p2p-listen 127.0.0.1:18001 --rpc-listen 127.0.0.1:19001 \
  --peers 127.0.0.1:18002,127.0.0.1:18003,127.0.0.1:18004
```

Use the generated single-line commands in PowerShell. Peers poll configured addresses and reconnect automatically. Configure reciprocal connections; a full mesh is the tested default. New peers and disconnected peers request their first missing finalized height until caught up. Transactions submitted to any participating RPC are gossiped and considered by subsequent proposers. RPC account and status responses expose only committed state. The existing [payment RPC](13-native-payments.md) format is unchanged.

`--blocks N` stops after N additional certified heights, including imported blocks. Use `--run` for a cluster: a validator that exits no longer serves its final certificate to slower peers. `--blocks 0` authenticates local history and opens the protected journal without listening or signing. `--dry-run` checks genesis, registry, seed membership, and TLS identity without writing files, opening the journal, or starting listeners. Initial step timeout is 1000 ms; `--round-timeout-ms` accepts 100–60000 ms. Existing networks can provision TLS separately with `cli init-network-tls`; see [transport migration](20-authenticated-transport.md#provisioning-and-migration). Plaintext requires explicit `--allow-plaintext` and loopback-only endpoints.

## Non-voting full nodes

Use `--observer` with the trusted genesis, public registry, a separate data directory, and TLS identity to verify finalized history and serve account/payment RPC without a consensus key. `cli devnet <directory> 4 --observer` provisions the additional node and reciprocal peer connections. See [observer setup and role-safe recovery](21-observer-nodes.md).

## Provision a supplied key

For an independently prepared genesis containing the derived validator ID:

```sh
cargo run -p cli -- init-validator genesis.bin validator.seed node-data
```

The seed file must contain exactly 32 raw bytes. Provisioning creates a protected version-2 `signing.journal` without overwriting an existing journal. It refuses directories containing `chain.bin` or `consensus-cache.bin`. The public registry is the concatenation of one 32-byte Ed25519 public key per genesis validator; duplicates, missing keys, weak keys, and mismatched identities fail validation. Registry file order does not change committed committee seat order.

The daemon only **opens** an existing journal. A missing journal is an error, even when the chain is empty. Restart with the original seed, genesis, data directory, and public registry. Never replace, truncate, clone, or roll back a journal to bypass a signing error. Encrypted custody and external anti-rollback anchors remain future work; the journal does not contain the secret seed, and the daemon zeroizes its seed buffers.

Starting a provisioned validator directory in demonstration mode is rejected. The demonstration service also rejects an archive whose latest block contains a canonical finality certificate, preventing an accidental mode downgrade from appending placeholder finality to certified history.

## Consensus driver and recovery

`node::network::NetworkNode` drives the existing `RoundRobinValidator`. Only the designated proposer signs a proposal; each participant independently executes its body before voting. Incoming votes are authenticated before retention and relaying. A strict weighted quorum produces a certificate; it never substitutes for execution validation. No synthetic votes or opaque demonstration certificates enter this path.

Monotonic step timers carry exact height, round, and step. Each round's deadline is the configured base multiplied by `round + 1`. Proposal and prevote timeouts reserve nil votes; precommit timeout advances the round without releasing a lock. Earlier-round quorum evidence and its available block survive round changes, allowing the next designated validator to repropose the locked value. This is a reference timer policy, not a formal distributed-liveness claim.

`consensus-cache.bin` atomically retains authenticated proposal bodies, available values and their prevote proofs, and cached votes. Bodies are synchronized before signing a prevote; available-value evidence is synchronized before signing a non-nil precommit. The protected journal remains the authority for signing coordinates and locks. Restart reauthenticates cached messages and re-executes bodies. A crash between signing and cache publication permits an identical retry; a conflicting retry remains forbidden. A missing cache may require peer redelivery or a timeout, while malformed cache bytes fail startup. Cache publication errors stop the daemon.

`chain.bin` publishes blocks, certificates, and execution state through the existing atomic storage boundary. On startup, the network node checks every retained block's certificate against independently reconstructed genesis membership, checks sequential heights and ancestry to the exact genesis, and rejects incomplete or demonstration history. Catch-up verifies each certificate before execution and publication; peer-advertised heights never authorize a snapshot or state replacement. Signing or storage durability errors terminate processing rather than being treated as malformed peer input. A finalized-history read failure discovered by either a peer request or block RPC also stops the daemon; it cannot keep signing against known-corrupt local history.

## Version-1 exchange

Each application packet inside TLS starts with a 4-byte little-endian payload length. Reads and writes have an absolute two-second deadline, including partial I/O and record processing; the TLS handshake has a separate two-second deadline. Length is checked before allocation. Each connection carries one request and one response.

The 48-byte request is:

```text
ALRQ || version:u32=1 || genesis:32 || requested_height:u64
```

The response is:

```text
ALNX || version:u32=1 || genesis:32 || message_count:u32 || messages...
```

Each message begins with a one-byte discriminator. Every following field below is a `u32` length followed by exact canonical bytes:

| Tag | Fields |
| --- | --- |
| 0 | Signed proposal, block, optional prevote certificate (empty means absent) |
| 1 | Signed vote |
| 2 | Block, finality certificate |
| 3 | Block, prevote certificate |
| 4 | Signed transaction |

A block is a length-prefixed canonical block header, a `u32` transaction count, and length-prefixed canonical transactions. Execution outputs are recomputed locally and never accepted from a peer. Unknown versions/tags, trailing bytes, truncated fields, and excess lengths/counts fail decoding. Complete structural decoding precedes message processing. Consensus verification remains a separate step.

| Resource | Bound |
| --- | --- |
| Configured validators / outgoing peers | 32 each |
| Request | 48 bytes |
| Complete response / cache | 8 MiB |
| Messages per response | 512 |
| Encoded block | 1 MiB |
| Transaction | 64 KiB |
| Structurally decoded transactions per block | 256 |
| Accepted/produced transactions per reference-network block | 15 |
| Pending response mailbox | 4 packets |
| Concurrent inbound requests | Configured `max_peers` (daemon default 32) |
| Accept work per loop iteration | 8 connections |

The lower production transaction count ensures a block fits the wire bound even at maximum transaction size. Polling is every 50 ms per configured peer; a full response mailbox drops a redundant response for a later retry. Repeated identical votes/proposals do not consume new slots. Incoming untrusted failures do not stop consensus, while local failures do.

## Qualification and remaining work

### Response preparation and encoding

Both validator and observer nodes expose `prepare_response`, returning an owned
`PreparedResponse`. Its messages are selected from one node state; later node
changes do not alter that selection. Consuming `PreparedResponse::encode` uses
the existing exchange codec and its size/message limits without accessing the
node. The existing `respond` API remains a prepare-and-encode wrapper.

The daemon prepares the response under its node mutex and releases that mutex
before encoding. Node ticks, message processing and RPC operations can therefore
proceed while another request is being serialized. Storage selection still occurs
under the lock, and existing error classification, wire bytes, discovery framing,
session limits and write deadlines remain unchanged.

Tests compare live, finalized and empty responses for both node roles, preserve
snapshots across transaction admission, and encode them on another thread after
the nodes have been dropped. This is response-stage overlap only: compact-block
propagation, a full block-stage pipeline and speculative consensus work remain
unimplemented. No end-to-end throughput improvement is claimed.

### Existing network qualification

Automated coverage includes three-of-four progress with an offline validator, two-of-four failure to finalize, payment gossip and replay rejection, late catch-up, all-validator restart after precommit, locked-value reproposal after lost precommits, rejection of demonstration history, malformed envelope bounds, and independent TCP daemon processes with restart and late join. The network decoder has an accepted-input canonical re-encoding fuzz target. Long fuzz campaigns and cross-platform qualification remain separate gates.

Mutually authenticated TLS 1.3 is implemented; see [transport guarantees and limits](20-authenticated-transport.md). Scoped peer discovery, persistent sessions and bounded operational telemetry are implemented in [private-network operations](36-private-network-operations.md). Committee handoff, evidence inclusion and PoTB transitions are implemented in the explicit [live PoTB profile](45-live-potb-network.md). Public-network hardening and formal safety/liveness qualification remain open. Mempool admission is volatile across process loss. New network directories use an [append-only block/delta log](22-append-only-chain-storage.md) without the old whole-chain rewrite or checkpoint cap. Existing archives keep their original 4096-checkpoint / 256 MiB limits; the state engine retains its separate bounds. [Protected signing-journal rollover](23-signing-journal-rollover.md) permits signing beyond 100,000 decisions at a fixed file size, with conservative failure recovery. Production-scale persistence, key custody, distributed calibration and independent audits remain prerequisites for a public production network.
