<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 15. Authenticated Votes and Finality Certificates

## Implemented boundary

The consensus library now authenticates fixed-height votes and precommit certificates using strict Ed25519 and the existing length-framed BLAKE2s domain hash. `AuthenticatedCommittee` takes a chain ID, ordered committee, and the exact public-key set. Validator IDs are BLAKE2s-256 of their Ed25519 public keys. Unknown, duplicate, malformed, weak, or missing keys fail construction; public-key input order is immaterial.

Membership and weights are independently trusted inputs from finalized state. A certificate cannot introduce its own trusted committee. Registration proves a signature's association with an identity, not that the identity deserves a seat or weight. Genesis currently stores IDs and weights without public keys; supplying and authenticating the public-key registry remains a caller responsibility.

The collector is separate from the [local BFT voting guard](17-local-bft-voting.md), which implements fixed-height lock transitions and timeout events using a protected [durable signing journal](16-durable-signing.md). A precommit quorum can be verified without receiving the corresponding prevotes locally; local precommit generation requires verified prevotes and proposal validation. [Signed proposals and a reference round-robin participant](18-signed-proposals-and-participants.md) connect authentication, execution, voting, and publication. Weighted VRF proposer selection ([document 28](28-vrf-and-weighted-selection.md)), monotonic timer scheduling, authenticated committee handoff ([document 38](38-authenticated-committee-handoff.md)) and daemon network orchestration ([document 19](19-reference-network.md)) are built on this boundary. `FullNodeService` and the daemon's local demonstration mode still simulate finality.

## Canonical formats

All integers are unsigned little-endian. Version is a four-byte integer equal to 1. Unknown magic/version, unsupported tags, trailing input, or truncation fail decoding. Hashes and validator IDs are 32 bytes; signatures are 64 bytes. Hashing uses the framing in [cryptographic foundations](09-cryptographic-foundations.md).

### Committee commitment

The committed byte sequence is:

```text
ALCM || version:u32 || chain_id:u32 || height:u64 || count:u32
     || (validator_id:32 || power:u128)[count]
```

The root is `H("astrolune.committee.v1", bytes)`. Seat order is significant. Committees contain 1 through 4096 unique identities with positive weights; their checked `u128` sum must not overflow. No sorting, truncation, saturation, or weight normalization is performed. The quorum is `floor(2 * total / 3) + 1`, calculated without intermediate overflow.

### Vote envelope

| Field | Bytes |
|---|---:|
| Magic `ALVT`, version | 4 + 4 |
| Chain ID, height, round | 4 + 8 + 4 |
| Phase: 0 prevote, 1 precommit | 1 |
| Block-present flag: 0 nil, 1 block | 1 |
| Block hash; all zeros required for nil | 32 |
| Committee root | 32 |
| Voter ID | 32 |
| Signature | 64 |

The complete envelope is exactly 186 bytes. Ed25519 signs the 32-byte digest `H("astrolune.vote.v1", first_122_bytes)`. Chain, height, round, phase, nil/block distinction, committee root, and voter are all covered. A nil vote differs from a vote for the all-zero hash. No unspecified tag values or alternative nil encodings are accepted.

### Finality certificate

```text
ALFC || version:u32 || chain_id:u32 || height:u64 || round:u32
     || committee_root:32 || block_hash:32 || count:u32
     || (voter_id:32 || signature:64)[count]
```

The header is 92 bytes; each signature entry is 96 bytes. Count is 1 through 4096 (maximum envelope size 393308 bytes). Entries must be strictly ascending by validator ID. Decoders check the count and exact remaining length before allocating, then reject duplicate or unsorted signers. Encoders also reject invalid order instead of silently sorting. The certificate commitment is `H("astrolune.finality.v1", complete_bytes)`.

Independent verification reconstructs each signer's precommit vote with the certificate's shared context. Every signature must verify, including signatures after the quorum threshold is reached. Signer weights are taken only from trusted membership. The certificate must match the exact header hash, height, and committee root and carry strictly more than two thirds of the total weight. Decoding or computing the commitment alone does not establish finality.

## Bounded vote collection

`BftFinalityEngine::new` requires an `AuthenticatedCommittee` and starts at round zero. It accepts votes only for that chain, height, committee, and current round. A caller may advance exactly one round; old counters and votes are dropped, so at most two votes per member are retained. Exhausted round numbers and advancing after a certificate exists are rejected. Advancing collection does not authorize unlocking or signing anything.

Each authenticated voter has one slot per phase, including nil votes. Repeating the same value returns `DuplicateVote`; signing another value in that slot returns `Equivocation`. Invalid signatures are rejected before slot/evidence classification and cannot consume a slot. Round, phase, and block counters are separate. Nil quorums and prevote quorums never produce finality certificates. The first non-nil precommit quorum freezes the certificate; later votes cannot replace it. Certificates contain the observed quorum subset in canonical signer order, so different valid arrival orders can yield different signature subsets for the same block.

## Execution and durability

`BlockProducer::produce_block_for_committee` binds a staged proposal to a trusted committee for the producer's exact chain and next height. `commit_certified_block` validates that context and the certificate before re-executing and atomically publishing the proposal. Failed authentication, execution checks, or durable writes leave producer state, height, and pending transactions unchanged. A storage durability-unknown result still requires the existing recovery procedure.

The lower-level `commit_block` and storage interfaces retain their explicit caller-authentication contract for local demonstrations. Certified commits do not change the archive layout: archive version 2 already stores bounded opaque certificate bytes. Archives written in demonstration mode are not upgraded to authenticated history. Recovery restores bytes; callers must reconstruct independently trusted historical committees and verify certificates before trusting that history. Integration tests exercise this verification after each payment-block restart and preserve archive bytes during failed writes.

## Verification and remaining work

Tests cover independent Python BLAKE2s vectors, strict codecs, truncations and mutations, invalid key sets, full-width overflow, replayed nil votes, altered signing fields, phase/round isolation, every subset of several weighted four-member committees, all certificate signatures, certified payment execution, failed-write retry, and independent certificate verification after archive recovery. A decoder fuzz target checks exact accepted-input re-encoding. Long fuzz campaigns and cross-platform qualification remain open.

This layer provides authenticated quorum evidence, not a complete BFT safety/liveness protocol. Durable signing and fixed-height local voting are implemented separately. Authenticated genesis key provisioning, weighted VRF proposer selection, timer policy, committee transition proofs, network delivery, and daemon integration remain separate implementation stages.
