<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# PoTB evidence and policy workbench

## Implemented operational boundary

The BFT collector now retains authenticated double-vote evidence instead of only
returning an equivocation error. Both Ed25519 signatures must verify against an
independently trusted historical committee. Chain, height, round, phase, voter
and committee root must match; block-or-nil values must differ. A duplicate or
an unauthenticated accusation never produces a proof or changes quorum power.

`DoubleVoteEvidence` uses the fixed 380-byte `ALDV` version-1 format: an 8-byte
tag/version followed by two canonical 186-byte votes. Values are ordered with
nil before non-nil and then by hash. Reversed pairs, duplicates, malformed tags,
truncation and trailing bytes are rejected. Decoding alone does not authenticate
the evidence. The proof ID commits both full votes; the offence ID commits the
shared slot independently of which pair proves three or more conflicting votes.

Collectors retain at most one proof per committee member across round changes.
Voting network nodes persist their first proof per registered member in
`<data-dir>/equivocation/<validator-id>.bin`. Files are created exclusively and
flushed before a successful observation is exposed. Unix directory entries are
also synced. The fixed reference profile has at most 32 members, so stored proof
payloads total at most 12,160 bytes. Repeated accusations cannot grow this store.
Observers currently do not collect gossip votes for evidence.

Restart reauthenticates recognized proof files against their historical committee.
For genesis-v2 networks it sorts the bounded proof set by height and verifies one
shared handoff stream from trusted genesis; it does not replay the entire stream
separately for every proof. Corrupt/truncated files, identity mismatches
and symlinked proof paths fail closed; they are not silently repaired. A write
failure propagates as a local error and stops the normal daemon driving path.
An interrupted first write may therefore require operator investigation. This
outbox has no independent anti-rollback anchor; loss of a proof file cannot be
detected as a consensus violation. Raw evidence itself remains portable and
independently verifiable.

## Operator commands

`cli evidence-create <genesis> <validators> <vote-a> <vote-b> <output> [rpc-address]`
authenticates two binary votes and writes a canonical proof without overwriting
an existing file. Version-1 full-genesis committees need no RPC access. For a
version-2 rotating committee, the optional address selects the node serving the
historical handoffs (the usual local RPC address is the default). The command
verifies at most 10,000 transitions under a shared 60-second deadline and saves
`<output>.handoffs` only after both votes authenticate against that height's committee.
An identity that has left the committee cannot create evidence for that height.

`cli evidence-verify <genesis> <validators> <proof>` verifies a saved proof without
modifying it. Rotating proofs require the matching `<proof>.handoffs` sidecar;
keep both files together. A bare rotating-node outbox proof needs the same verified
history before it can be used offline. Missing, truncated or foreign history is
rejected. Inputs are bounded. Supply independently trusted genesis and the complete
public-key registry. No private key is needed. Proof output is not an automatic
on-chain penalty.

Vote signatures in the existing protocol bind chain ID and committee root, not
the genesis hash directly. Do not reuse chain IDs and identical voting contexts
across deployments and assume that the CLI can distinguish those signatures.

## Reference scoring

`PotbTracker` replays contiguous certified headers from a caller-supplied trusted
anchor. Every transition checks parent, height, committee, signatures and quorum
before atomically publishing counters. Callers must supply independently trusted
historical membership and separately verify execution/state transitions.

For each explicitly enrolled identity the tracker counts finalized heights of
committee membership and certificate mentions. **Membership age is not uptime.**
Certificate mentions are diagnostic only: a producer may publish a valid quorum
subset that excludes an honest participant, so absence cannot justify punishment
or a smaller score. No wall-clock duration, local latency or social endorsement
feeds the score.

An explicit `PotbPolicy` defines epoch size, initial score, age increment and cap.
The integer-only reference formula is:

```text
epochs = eligible_blocks / epoch_blocks
candidate_weight = min(maximum_weight, initial_weight + epochs * age_increment)
```

The implementation avoids intermediate overflow even at full-width u128 limits.
A verified historical double vote yields candidate weight zero for that identity
under this reference policy. Duplicate proofs cannot stack penalties; choosing
the minimum offence ID makes accumulated observations order-independent. Re-entry,
admission costs, identity splitting, ownership concentration and trust-graph
policy are not solved by an age bonus or a per-identity cap.

**These candidate scores are not active consensus weights.** Local observations
are not canonically finalized evidence. The reference daemon continues to use its
genesis weights. Activating PoTB requires a versioned evidence-inclusion/state
transition protocol, finalized parameter activation, a vetted VRF/sampler,
safe weighted committee handoff, admission policy and independent review. Locally
observing an offence must never unilaterally change a node's quorum threshold.
No stake is deducted by this change. Proposal-equivocation evidence remains work.

## Historical inclusion foundation

[Document 42](42-historical-potb-evidence.md) specifies a bounded historical committee
accumulator and portable offence bundle. Handoff verification authenticates this
local history incrementally. The [separate PoTB producer profile](44-potb-state-transitions.md)
commits this frontier and implements canonical inclusion, active age weights,
permanent exclusion and admission execution. [Live activation](45-live-potb-network.md)
adds daemon execution, authenticated inclusion gossip and operator submission.
Admission policy for the closed network requires authorization by strictly more
than two thirds of incumbent voting power.

## Validation and claims

Tests cover forged signatures, mismatched contexts, canonical ordering, all proof
truncations and single-byte mutations, bounded collector retention, atomic failed
replay, certificate-subset neutrality, repeated/out-of-order offences, full-width
arithmetic, real node persistence/restart and CLI proof verification. These
tests establish the implemented invariants, not global superiority or a security
proof for complete PoTB. Network throughput and finality latency still require
published hardware/workload/fault profiles and independently reproducible runs.
