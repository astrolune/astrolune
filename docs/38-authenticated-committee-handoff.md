<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 38. Authenticated committee handoff and rotating execution

The consensus library now collects a complete, verified VRF batch and transfers
authority from the current quorum to the next committee. The producer has an
explicit rotating execution API with a reserved system transaction, atomic
publication and authenticated history replay. State and receipt proof verifiers
can use an independently verified handoff stream.

[Genesis-v2 live activation](40-live-vrf-network.md) now connects these APIs to
contribution gossip, standby participation, complete-roster availability,
historical handoff RPC and CLI/DNS catch-up. Version-1 genesis retains fixed
membership. Active PoTB weights, finalized evidence and admission remain separate.

## Authority and randomness

`CommitteeState::from_genesis` authenticates an exact registry of at most 32
strong Ed25519 keys against the independently supplied genesis identities and
positive weights. The initial committee contains the whole roster at height one.
If the nominal committee is smaller, the first transition samples that many
seats. Otherwise partial rotation starts immediately. Later transitions retain
the newest seats and replace the oldest `rotation_count` seats. Outgoing members
can win a new seat. Roster, weights, capacity and rotation parameters remain fixed
in this format.

Initial randomness is the domain hash `astrolune.rotation.genesis.v1` of the
genesis commitment. For a transition from height `h` to `h + 1`, both VRF inputs
bind chain, genesis, epoch `h + 1`, height `h + 1`, the current randomness, round
zero and their distinct committee/producer roles. No proposer-chosen transaction
data or block hash supplies entropy. The finalized parent header is authenticated
separately by the handoff verifier.

Every eligible validator supplies both role proofs. The committee sampler uses
the entire roster. `producer_for_subset` draws among the selected seats while
retaining entropy from **all** verified producer-role contributors, including
those not selected. The next randomness is the domain hash
`astrolune.rotation.randomness.v1` of the two complete batch randomness hashes.
Round zero uses the selected producer; later timeout rounds walk the same seat
order without requesting another lottery.

`ContributionPool` retains at most one verified contribution per registered
identity. Identical replay is idempotent; invalid replacement cannot erase a
valid entry. `missing()` reports unavailable identities. `complete()` refuses
partial rosters. A new height needs a new pool and newly bound proofs.

Missing proofs stop the explicit rotating producer at that height. There is no
automatic omission, seed change or fallback committee. This is a defined
fail-closed library behavior, not a claim of rotating-network liveness with an
offline eligible participant. The existing fixed daemon retains its tested
quorum behavior when one of four validators is offline.

## Certified handoff

`HandoffVerifier` starts only from independently supplied genesis and keys. It
retains the current committee and last finalized block hash. It cannot install
a deserialized committee as an authority. Each `CommitteeHandoff` contains:

1. The current-height header and its old committee's precommit certificate.
2. The complete next-height committee and producer VRF batch.
3. A state membership witness for the exact computed next committee under
   `astrolune/consensus/committee/v1` in that header's post-state.

Verification checks the exact height, parent, capacity, old quorum and signatures,
recomputes the next committee from every proof, and compares its canonical bytes
with the authenticated state value. Even a correctly signed old-quorum header
cannot substitute a different next randomness or committee. Failed checks leave
the verifier unchanged. The new committee never authenticates its own admission.

Handoffs are consumed individually in sequence. Skipped heights, repeats, foreign
forks, incomplete batches and new-committee self-certification are rejected.
This proves the committee transition; a full node also verifies application
execution. A minimum-height anchor is still required to distinguish a coherent
old history from the newest history.

## Bounded wire formats

All counts and lengths are little endian. Decoders preflight lengths before
allocating, reject trailing bytes and preserve exact accepted-input bytes.

| Object | Framing | Maximum bytes |
| --- | --- | ---: |
| Committee state | `ALCMST01`, chain/genesis/height/randomness/capacity, four u8 counts, producer, ordered keys/weights and seats | 2,712 |
| Contribution | `ALVRFC01`, identity, two canonical 120-byte VRF envelopes | 280 |
| Batch | `ALVRFB01`, u8 count, contributions in strict identity order | 8,969 |
| Handoff | `ALHAND01`, 200-byte header, three u32-length fields: certificate, batch, state witness | 16,449 |

State contains 152 fixed bytes, 48 bytes per eligible key/weight and 32 bytes per
active seat. Eligible identities derive from keys; duplicate keys, weak keys,
zero weights, sum overflow and unknown/duplicate seats are rejected. Handoff
certificates are limited to 32 signers and the committee state witness to 4 KiB.
The four-envelope fixture hashes are pinned in `consensus/tests/handoff.rs`.

## System execution and publication

`BlockProducer::with_rotation(&HandoffVerifier)` explicitly binds the producer to
an authenticated committee and parent. It checks chain, genesis, height, capacity
and, after height one, exact persisted committee-state bytes. `set_vrf_batch`
verifies a complete batch before making it available for local proposal assembly.

Exactly one system transaction must occupy index zero. Its sender and signature
are zero, its nonce and expiry equal the current height, prices are zero, its only
access is the reserved committee key, and its payload is the canonical full VRF
batch. Authorization comes from verified VRF proofs and the enclosing old-quorum
certificate. External mempool admission still rejects it. Imported blocks must
match every canonical envelope field; a second system transaction is rejected
by application execution.

The system receipt reserves `10,000 * roster_count` compute units, 16 KiB memory,
4 KiB I/O and 12 KiB bandwidth. These are explicit protocol charges, not benchmark
claims. The byte allowances cover the maximum batch/state format. The producer
deducts this budget before admitting application transactions and reserves one
transaction slot. Payments and ABI-v2 contracts execute against the private
post-system state; aggregate receipts and roots cover all lanes.

Both local and imported blocks are re-executed before publication. In rotating
mode even the low-level `commit_block` checks the old quorum. Only a successful
storage commit publishes the new state, committee, height and pool eviction.
Failure retains the complete batch and pending transactions for an identical
retry. `rotation_handoff` constructs the portable proof from an executed,
certified proposal; local serving must follow durable publication.

`recover_rotation` replays stored blocks from genesis, authenticating each old
quorum and re-executing both the system and application transitions. It rebuilds
committee authority without trusting saved committee bytes, retains only the
latest state and one block, and compares the final root/head with storage. It
works with append-only logs and version-3 whole-chain archives. It performs no
writes or signing. A fixed-profile recovery rejects a state containing the
reserved committee record, and an unbound producer cannot execute or accept
transactions against it.

## State and receipt proofs

`CertifiedStateProof::verify_with_handoffs` and
`CertifiedReceiptProof::verify_with_handoffs` use a separate `HandoffVerifier`
positioned at the proof header's exact height. They check parent, old quorum,
genesis membership, minimum height and the requested value or receipt. Verify
a proof before applying the handoff for that same block. A stale verifier or
a proof-provided committee cannot bypass missing history. Genesis-only proofs
continue to use the existing verifier. Genesis-v2 daemon, CLI and DNS clients now use the live handoff path.

## Validation

Tests cover complete/partial collection, role/context replay, invalid replacement,
unselected contributors, partial rotation, producer rounds, every truncation,
canonical fixture hashes and malformed lengths. Adversarial cases include old
quorum insufficiency, new committee self-certification, forged state witnesses,
correctly signed wrong transitions, skipped/replayed headers and atomic rejection.

Execution tests combine VRF, signed payments and real WASM deployment, compare
local/imported proposals, inject a disk publication failure, recover three
rotations from each storage backend, reject forged stored certificates and prevent
silent downgrade to fixed-profile execution. The shared mutation/libFuzzer oracle
also covers all four new envelopes. These checks do not substitute for the
remaining formal liveness and independent review work.
