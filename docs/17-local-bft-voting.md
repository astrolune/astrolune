<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 17. Local BFT Voting and Durable Locks

## Implemented boundary

`consensus::LocalBft` implements local prevote/precommit decisions for one trusted height and committee. It owns a protected `DurableSigner` and records every outgoing vote together with its committee and lock before returning the signature. `BftFinalityEngine` remains the separate bounded collector of authenticated evidence. The voting design is informed by [The latest gossip on BFT consensus](https://arxiv.org/abs/1807.04938); this implementation does not claim a complete implementation or proof of that protocol.

The caller supplies independently trusted committee membership, keys, weights, chain ID, genesis commitment, and height. The low-level `prevote` callback must authenticate the designated proposer and validate the available block body, parent, capacity, and deterministic execution. The newer [signed-proposal API and reference participant](18-signed-proposals-and-participants.md) authenticate proposer statements before execution callbacks; the latter then only check availability and execution. A quorum alone never substitutes for that validation. `BlockProducer::validate_proposal` provides read-only execution checks against the producer's current state; it does not authenticate a proposer. Header-only callers must obtain and validate the corresponding complete proposal themselves.

This is a fixed-height safety component. Signed proposer envelopes, explicit reference round-robin designation, and evidence-bound reproposals are implemented separately. Weighted VRF, network delivery, timer scheduling and calibration, persistent valid-value availability for liveness, committee handoff, key provisioning, and daemon integration remain open. `FullNodeService` and the daemon still simulate finality.

## Local transitions

The public steps are `AwaitingProposal`, `Prevoted`, `Precommitted`, and `Finalized`. Construction restores the last durably signed round, phase, and lock at the trusted height. The signer must be a committee member with the same chain/genesis namespace. Earlier heights and a changed committee at the last signed height are rejected.

| Input | Result |
|---|---|
| Valid proposal, no lock or same locked block | Prevote for the block |
| Different locked block and verified earlier-round prevotes newer than the lock | Prevote for the proposed block; retain the old lock |
| Missing/invalid proposal or insufficient unlock evidence | Nil prevote; retain the lock |
| Valid proposal and verified current-round prevote quorum | Persist the new lock and block precommit together |
| Matching proposal/prevote timeout | Nil prevote/precommit; retain the lock |
| Matching precommit timeout | Advance one round; retain the lock |
| Verified finality certificate and valid proposal | Freeze local output as finalized |

Malformed, wrong-context, future, or mismatched proofs return errors. Valid proofs too old to authorize a different block lead to nil prevotes. Stale timers, wrong steps, and round overflow return errors. The timer caller determines when an event is eligible; the library only checks its round and local step.

Prevote and precommit methods accept identical retries in their respective steps. A different decision in an already reserved signing slot fails in the journal, including after restart. A round advance without another signature need not be persisted: recovery resumes the earlier precommit step and can repeat the advance. No nil vote or timeout clears a lock.

The in-memory `Finalized` flag is not a chain checkpoint. Callers publish finality through `commit_certified_block` and durable storage, then construct the next height from independently authenticated committed state. Merely requesting a higher height does not prove that it is safe to advance. At a later trusted height the local round and lock start fresh; older journal decisions remain present.

## Verified prevote evidence

`PrevoteCertificate::from_votes` verifies every supplied signature, trusted weight, chain, height, committee, phase, block, and round. It requires strictly more than two thirds of total weight and unique voter IDs in ascending order. Nil votes cannot form this proof. The private representation exposes no unchecked constructor. `BftFinalityEngine::prevote_certificate` produces the same verified type from its current-round collection.

The bounded canonical format uses unsigned little-endian integers:

```text
ALPV || version:u32=1 || count:u32 || vote:186[count]
```

Count is 1 through 4096; maximum size is 761868 bytes. Each vote uses the existing `ALVT` envelope. Decoding checks the size/count before allocating, then authenticates all votes against caller-supplied membership. Accepted bytes re-encode exactly. A prevote certificate is not finality evidence and cannot be used in place of an `ALFC` certificate.

## Protected journal version 2

Create a new protected journal with `DurableSigner::create_protected`. `open` detects either supported version. Version 1 remains byte-compatible for existing raw signing users; it cannot supply the missing lock history required by `LocalBft`. There is no implicit migration, reset, or safe conversion of previously active signing keys to new journals.

Version 2 keeps the 108-byte header and checksum domains from [durable signing](16-durable-signing.md), with the header version changed to 2. Each decision is 154 bytes:

```text
sequence:u64 || height:u64 || round:u32 || phase:u8 || message_digest:32
             || committee_root:32 || lock_present:u8
             || locked_round:u32 || locked_block:32 || record_checksum:32
```

The checksum covers the preceding checksum followed by all 122 bytes of the decision body. A missing lock is encoded only as flag 0, round 0, and an all-zero block. Flag 1 permits every block hash, including zero. Other tags and alternative nil encodings fail. The append-only prefix retains 100000 decisions (15400108 bytes). Protected journals then use [two alternating watermarks](23-signing-journal-rollover.md), keeping the original prefix unchanged and bounding the complete file at 15400456 bytes.

Signing and recovery both enforce a nonzero committee root, a lock round no greater than the signing round, and a fixed committee throughout one height. An existing lock cannot disappear, move backwards, or change its block at the same locked round. Exact retries must preserve the digest and all safety metadata. A later height can establish a new committee and reset the lock. These structural checks do not verify consensus evidence: low-level `sign_protected` callers remain responsible for deriving the correct message and safety state; normal vote callers use `LocalBft`.

Protected journals reject raw `sign_consensus`/`Vote::sign_with` calls, and version-1 journals reject protected requests. The lock metadata and digest share one complete record and one `sync_all` before signature output; after rollover this record occupies an alternating watermark slot. An uncertain write disables the signer; reopening either recovers the entire decision and lock or rejects the partial record. The version-1 locking, directory durability, and hostile-storage/valid-prefix rollback limitations still apply.

## Verification

Tests cover lock restoration, conflicting retries, nil/timeouts over repeated restarts, older/equal/newer valid-round proofs, malformed certificates, all single-byte proof mutations, wrong genesis/committee/height, invalid execution, exhausted rounds, and three locked honest validators refusing conflicting quorums across rounds. Journal tests cover independent Python checksum vectors, partial and complete uncertain writes, and valid-checksum records that attempt to regress locks or change membership.

The integration fixture executes a signed payment, collects four local prevotes, restarts the signers before precommit, verifies finality, injects a failed archive write, retries atomically, and independently verifies the recovered certificate and balances. This tests local execution and persistence boundaries; distributed liveness, long fuzz campaigns, formal analysis, and independent review remain required.
