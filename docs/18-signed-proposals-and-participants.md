<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 18. Signed Proposals and Reference Participants

## Implemented boundary

`consensus::Proposal` authenticates a proposer's statement about an exact block and round. `LocalBft::propose` reserves this statement in the protected journal before returning its Ed25519 signature. `prevote_proposal` verifies the designated author, chain/genesis/height/committee, block header, round, and attached evidence before invoking execution validation or reserving a vote.

The expected proposer is a trusted policy input, never an authority inferred from the message. `AuthenticatedCommittee::verify_proposal` checks that identity against the registered committee key. A valid signature from another member is insufficient. The low-level `LocalBft::prevote` retains its caller-authentication contract for custom integrations.

`node::RoundRobinValidator` combines these APIs with a `BlockProducer`, protected local voter, and bounded finality collector. It implements one height under an explicitly selected reference designation policy. It returns outgoing messages to its caller; it opens no sockets, schedules no wall-clock timers, and provisions no keys. The [network driver](19-reference-network.md) supplies transport, timers, and provisioning around it.

## Canonical proposal envelope

All integers are unsigned little-endian. The version-1 envelope is exactly 221 bytes:

```text
ALPR || version:u32=1 || chain_id:u32 || genesis:32 || height:u64 || round:u32
     || committee_root:32 || block_hash:32 || proposer_id:32
     || valid_round_present:u8 || valid_round:u32 || signature:64
```

The signature covers `H("astrolune.proposal.v1", first_157_bytes)`. The block hash commits the complete canonical header, including ordered transaction, receipt, and state roots. The body and execution outputs are checked separately before voting.

Absent valid-round evidence is encoded as flag 0 and round 0. Flag 1 requires a round strictly less than the proposal round. Unsupported magic/version, other flags, noncanonical absence, truncation, and trailing bytes fail decoding. Decoding alone does not authenticate the message. Verification rejects zero or mismatched trusted genesis and any disagreement with the trusted context or exact header.

The optional `PrevoteCertificate` travels separately. Its context, block, and round must match the signed claim exactly; missing or unexpected evidence fails. The signature commits to the supported value/round rather than a particular subset of quorum signatures, allowing independently collected equivalent proofs.

## Durable proposal signing

Proposals use journal phase 0, followed by prevote phase 1 and precommit phase 2. Signing a proposal preserves the current lock. A locked proposer cannot propose another block without earlier-round prevote evidence newer than that lock. All candidates still require execution validation.

A restart after proposal signing restores `AwaitingProposal`, its round, and lock. An identical statement can be signed again. A different statement at the same slot is rejected, including a changed valid-round claim for the same block. Once a prevote has been reserved, proposal signing in that round is stale. No journal reset or format change beyond the existing protected version 2 is introduced.

## Explicit round-robin policy

The reference participant designates seat:

```text
((height mod committee_size) + (round mod committee_size)) mod committee_size
```

Seat order is already committed in the committee root. Public-key registration order is irrelevant. The calculation reduces coordinates before addition, including at maximum `u64` height and `u32` round. Voting weights still determine strict two-thirds quorums; they do not affect this reference designation.

This mode is for deterministic local development and integration. It does not implement the separately specified weighted VRF producer selection, randomness, fairness analysis, or committee rotation. All participating nodes must use the same trusted policy.

## Participant operations and recovery

- `propose` assembles, re-executes, and signs a fresh proposal. `repropose` signs a supplied available block with verified earlier-round evidence. Neither operation casts a prevote automatically.
- `accept_proposal` authenticates and validates a proposal, reserves a prevote, and counts that local vote. Invalid execution yields nil; invalid authentication consumes no signing slot. A valid available proposal is retained for quorum processing.
- `receive_vote` authenticates peer votes and isolates rounds/phases. Repeated local echoes return `DuplicateVote`; callers can discard this result. Outgoing votes are already counted locally.
- `precommit` requires an available proposal, authenticated current-round prevotes, and successful execution validation. It atomically reserves the lock and precommit before returning the vote.
- `commit` verifies locally collected finality and uses the existing atomic producer/storage path. Failed publication preserves execution state and pending transactions; finality stays frozen and the same commit can be retried. A durability-unknown storage result still requires storage recovery.
- `commit_finalized` accepts a complete independently verifiable certificate and available block even when local peer messages were lost. A proposal envelope is unnecessary at this point because the finality certificate authenticates the exact block and execution is revalidated.

Timeout events carry height, round, and step. Old-height, delayed, future, or wrong-step events fail. Proposal/prevote timeouts produce durable nil votes; a precommit timeout advances the local voter and collector together and releases the retained proposal. A collected finality certificate disables timeouts. Scheduling eligibility, quorum-triggered delays, durations, and clock handling remain external.

Recovery restores signing safety but does not recover a persistent message outbox. At a restored prevote step, `accept_proposal` can reconstruct the identical vote from the original message. At a restored precommit step, `restore_proposal` authenticates and re-executes an available body without voting; after recollecting its prevotes, `precommit` can reproduce the durable signature. The journal rejects conflicting retries. Restoring a body alone never supplies missing quorum evidence.

Only one proposal and one round of votes are retained. Callers retain or reacquire valid values/proofs needed for reproposals, authenticate recovered checkpoints, and establish finality before transferring the signer to a higher trusted height. The existing journal rollback and key-custody limitations still apply.

## Verification and remaining work

Tests cover an independent Python proposal-digest fixture, exact codec roundtrips, every truncation and single-byte mutation, noncanonical evidence tags, wrong designation/genesis, proposal-slot conflicts across restart, full-width reference designation, and evidence-bound reproposals without losing locks. The decoder fuzz target also checks proposal re-encoding.

Four independent participants exercise signed payments, authenticated proposals, local vote collection, restart/replay, finality, failed archive writes, atomic retry, and next-height recovery. Further scenarios withhold precommit delivery, advance rounds, re-propose a verified value, reject delayed events, recover lost volatile evidence, and prevent invalid bodies or nil votes from publishing state.

The [certified reference network](19-reference-network.md) now integrates this participant with the daemon, exact genesis-key registration, bounded transport/message framing, monotonic step timers, durable proposal/evidence recovery, and certified catch-up. [Mutually authenticated TLS transport](20-authenticated-transport.md) uses independent network keys. Weighted VRF selection, encrypted key custody, committee handoff, formal distributed liveness, long fuzz campaigns, and independent review remain open.
