<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 42. Historical evidence for PoTB

`CommitteeHistory` and `HistoricalEvidence` provide bounded historical authority
for the upcoming PoTB inclusion profile. They do not activate penalties, change
voting weights or admit validators in genesis versions 1 or 2.

`HandoffVerifier` now appends each outgoing committee only after the old quorum,
exact ancestry, complete VRF transition and next-state witness authenticate.
Failed handoffs leave both current authority and the history accumulator unchanged.
This is local verifier state; the 50 frozen existing-profile wire fixtures still
reproduce exactly. A future profile must explicitly commit the accumulator in its
consensus state before validators can use it for canonical evidence inclusion.

## Bounded historical authority

Tree shape and inclusion paths follow [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1).
The hash suite and wire formats are AstroLune-specific, not Certificate Transparency
encodings. Separate BLAKE2s domains cover leaves, interior nodes, the empty tree and
the final commitment. Leaves bind chain ID, genesis, exact height and committee
root. The final commitment also binds the exact number of entries.

The frontier stores at most 64 hashes for a u64 height range. Count bits determine
which peaks exist, so there is no alternate occupancy encoding. Updates require
the next contiguous height and matching chain ID. Overflow or invalid coordinates
leave the frontier unchanged. Decoding a frontier establishes structure only;
a peer cannot make its own accumulator authoritative.

| Format | Tag | Maximum encoded size |
| --- | --- | --- |
| Committee history frontier | `ALCHST01` | 2,100 bytes |
| One historical committee inclusion proof | `ALCHPF01` | 2,105 bytes |
| Historical double-vote bundle, at most 32 seats | `ALHDEV01` | 4,034 bytes |

Proof construction reads historical roots exactly once in increasing height order,
uses at most 64 recursive tree frames and 64 sibling hashes, and checks an explicit
caller-supplied work limit before reading anything. It then compares the complete
reconstructed tree with the trusted frontier. Corrupt/missing roots cannot produce
a successful proof. This bounds memory, not the total number of historical reads;
callers must set a suitable work limit.

Verification requires the shortest path for the exact count and height. Old-count,
extra-node, changed-namespace and wrong-height proofs are rejected. A valid proof
at one head does not claim validity against a newer head without updating its path.

## Portable offence bundle

A bundle contains historical public keys and weights in committed seat order,
the history proof and canonical `DoubleVoteEvidence`. Verification reconstructs
the committee, proves that exact committee against independently authenticated
history, then checks both conflicting signatures. Merely registering a key, leaving
a committee or presenting a valid signature under another membership does not
establish an offence at the requested height. Keys, weights and aggregate power
must satisfy the existing strict committee rules.

The signing limitation described in [document 25](25-potb-evidence.md) remains:
legacy votes bind chain ID and committee root, not genesis directly. Deployments
must not reuse an identical legacy signing context and expect history wrappers to
change what the original signatures signed.

## Admission decision and activation work

For this closed network, admission is to require explicit authorization from the
incumbent committee with voting power **strictly greater than two thirds**. This
is the selected governance policy; a single administrator cannot substitute its
signature for the quorum. The [request, protected approval, certificate and operator CLI](43-quorum-admission.md)
are implemented. The [explicit PoTB producer profile](44-potb-state-transitions.md)
now commits this history and implements canonical inclusion, active age weights
and admission execution. [Live daemon activation](45-live-potb-network.md) also
provides authenticated evidence submission and gossip. Local observations and
portable bundles outside finalized inclusion must not change consensus power.

## Checks

Tests compare incremental roots with a separately structured recursive reference
across balanced and unbalanced sizes and verify every leaf at selected boundaries
through 257 entries. They cover full-width u64 counts, failed-update atomicity,
work limits before reads, corrupt historical lookup, namespace/membership changes,
all truncations and one-bit mutations, and historical evidence after an accused
validator leaves the committee. The handoff tests also check authority/history
rollback together through the verifier's complete equality checks.

The shared stable/libFuzzer oracle includes all three new formats, taking the
structured corpus from 64 to 67 seeds. The repeated one-million-input deterministic
campaign passed with 295,800 accepted decoder paths. This is not a coverage metric
or a claim that active PoTB is complete.
