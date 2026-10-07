<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 44. Explicit PoTB state transitions

The `consensus::potb_transition` profile and `BlockProducer` implement canonical
evidence inclusion, active membership-age weights, permanent double-vote
exclusion and incumbent-quorum admission. System and application execution share
one atomic block/state commit. Both append-only logs and legacy archive backends
support independently authenticated, complete-history recovery.

This explicit profile also has [daemon and client activation](45-live-potb-network.md):
protected provisioning, bounded admission/evidence gossip, durable handoff serving,
RPC/CLI verification and DNS catch-up. Existing genesis-v1/v2 networks retain their
current rules. No migration of an existing data directory is supplied.

## Configuration and authority

`PotbConfiguration` contains validated genesis-v2-shaped base parameters and the
four integer `PotbPolicy` fields: epoch length, initial weight, age increment and
maximum weight. All initial validators must have the policy's initial weight.
The maximum is at most `u128::MAX / 32`, so maturation and admission cannot make a
future bounded roster's aggregate weight overflow. Epoch and initial weight must
be positive; the cap cannot be below the initial weight.

Its domain-separated configuration commitment is the new genesis namespace.
Changing the policy changes that commitment, even when allocations and initial
committee power match. This namespace binds ancestry, VRF proofs, admission
intent and committee-history leaves. Bootstrap verifies the exact public-key
registry and materializes allocations, runtime selection, the new genesis
commitment and initial `PotbState`. Initial validator records retain their genesis
meaning; current power is read from `PotbState`, not those static records.

The existing vote format still binds chain ID and committee root rather than
genesis directly. The context-reuse limitation in [document 25](25-potb-evidence.md)
therefore still applies: separate deployments must not reuse legacy vote signing
contexts and rely on a new history/configuration wrapper to change old signatures.

## One deterministic transition

The state at height `h` contains the authoritative committee and registered VRF
roster for `h`, immutable policy, permanent identity records, the committee-history
frontier through `h - 1`, and the preceding batch commitment. A transition:

1. Increments membership age once for every active incumbent seat. A standby does
   not age. Omitting a member from a valid finality certificate has no effect.
2. Verifies each historical double-vote bundle against the **parent's committed
   frontier**. The offence must postdate that identity's admission. Its first
   included offence permanently excludes the key. Already excluded identities
   and repeated offences are rejected; current/future-height offences cannot use
   an unfinalized committee as historical authority.
3. Verifies each candidate's consent and explicit admission certificate against
   the unchanged incumbent committee, exact parent and inclusion height. The
   approvals must exceed two thirds of incumbent power. Newly admitted identities
   start with zero membership age and the policy's initial weight.
4. Verifies **all** parent-roster VRF contributions, including a validator excluded
   by this batch. Committee and producer entropy remain the full parent transcript.
   Policy changes reweight surviving candidates without changing that transcript.
5. Retains eligible newer seats according to the configured rotation count, removes
   excluded seats and fills the target size using the existing unbiased sampler.
   The producer is sampled from the resulting committee with the new weights.
6. Appends the outgoing committee to the history frontier and commits the complete
   next state and exact batch hash. The old committee certifies the inclusion block;
   the computed committee is authoritative only for `h + 1`.

Age weight is `min(initial + floor(age / epoch_blocks) * increment, maximum)`
using checked/capped integer arithmetic. Certificate subsets and arrival order
cannot change it. `PotbTracker` remains a separate diagnostic workbench.

New candidates do not supply proofs or win a seat in their admission transition.
They enter the next registered roster and must contribute to its following draw.
This prevents a candidate from self-authorizing its inclusion block. Admission
does not prove that a transport endpoint is provisioned or online.

Records, including permanent exclusion tombstones, are limited to 32 identities
over this profile's lifetime. Exclusion does not free an admission slot, and an
excluded key cannot re-enter through a fresh request. Aggregate capacity is
checked across the entire batch, not independently per certificate.

There must be enough surviving **previously registered** identities to fill the
configured committee size. Otherwise the transition fails; it does not shrink the
quorum, forgive an offence or substitute a new candidate without a prior-roster
proof. Complete-roster availability remains mandatory. Censorship resistance,
unavailable-proof recovery and network liveness under these constraints are
separate qualification/activation work. Evidence inclusion can change eligibility;
the invariant above fixes VRF entropy, not proposer-independent inclusion policy.

## Canonical envelopes

| Type | Tag | Upper bound |
| --- | --- | --- |
| `PotbConfiguration` | `ALPTCF01` | bounded genesis plus 68 bytes |
| `PotbState` | `ALPTST01` | 7,509 bytes |
| `PotbBatch` | `ALPTBT01` | 243,703 bytes |
| `PotbHandoff` | `ALPTHF01` | 255,620 bytes |

Counts are bounded, lengths use fixed little-endian `u32` framing, and tags,
truncation, trailing bytes and invalid optional-field flags fail closed. Evidence
is strictly sorted by accused identity, with one offence per identity; admission
certificates are strictly sorted by candidate identity. Constructors normalize
arrival order, while decoders reject noncanonical order instead of repairing it.
Decoding never establishes trusted committee, policy or historical authority.

The batch hash commits every included signature and historical witness. The state
commits that hash as well as the history frontier, so even two inputs producing
the same eligible set cannot silently substitute different inclusion bytes.

## Execution and persistence

`with_potb` accepts an independently authenticated `PotbVerifier` only when its
height, parent, chain, capacity, genesis commitment and complete state match the
producer's persisted snapshot. A producer opened from a raw checkpoint refuses
execution/admission until authenticated profile recovery is supplied. Legacy
rotation and PoTB cannot be enabled together.

`set_potb_batch` verifies and privately caches a candidate. Local assembly and
received-block replay require one exact system transaction at index zero, with
zero sender/prices/signature, current height/expiry/nonce, the reserved state key
and the canonical batch payload. Extra system transactions fail application
validation. Applications execute against the privately staged policy state and
remaining resources. Cache hits and full revalidation produce identical outputs.

Let `r` be contribution count, `e` evidence count, `a` total admission approvals
and `b` canonical batch bytes. Fixed protocol charges are:

| Resource | Charge |
| --- | --- |
| Compute | `10000*r + 25000*e + 2000*a` |
| Memory | `16384 + PotbState::MAX_BYTES + b` |
| I/O | `PotbState::MAX_BYTES` |
| Bandwidth | `b + 512` |

These are reference protocol units, not measured CPU time. Application admission
reserves the empty-policy-batch minimum and one system slot. Actual block assembly
reserves the full included batch and may leave additional applications pending.

Commit rechecks finality under old power, re-executes the system and applications,
checks receipts/resource totals and verifies the computed next-state witness.
Only successful durable storage publication advances authority, history, parent,
state and the mempool. A failed write preserves the candidate and pending
transactions for retry. Successful publication clears the candidate cache.

`recover_potb` starts from the explicit configuration, reads every finalized block,
checks old-quorum certificates and ancestry, re-executes all system/application
transactions and compares the final state with the durable checkpoint. A decoded
saved policy state cannot authorize itself. Recovery performs no signing or writes;
rollback protection still requires an independently supplied minimum checkpoint.

`potb_handoff` constructs a portable next-state witness before publication; callers
must serve it only after the corresponding commit succeeds. `PotbVerifier` checks
that witness and updates authority atomically. It authenticates consensus-state
transfer, while a full node additionally re-executes applications. Versioned
`ALEFF003` receipt storage now retains a separate PoTB witness alongside receipts
and genesis binding; the legacy committee witness slot is not repurposed.
The live network serves these atomically published witnesses through `potb_handoff`.

## Verification

Consensus tests exercise membership age/caps, certificate-subset independence,
active weighted handoff, evidence plus admission, permanent exclusions, re-entry
rejection, aggregate roster capacity, delayed eligibility, insufficient surviving
seats, complete-roster proofs, stale/foreign input, exact codecs and failed-update
atomicity. A replay test reconstructs authority from encoded handoffs after each
successive block.

Producer tests cover signed payments with evidence/admission, both storage backends,
uncached/cached execution equivalence, failed-write retry, reserved resources,
system-envelope tampering, profile downgrade rejection and disk records lacking
quorum authority. The shared stable/libFuzzer oracle includes all four formats and
seven additional structured seeds, for 78 total. These tests do not establish
distributed liveness, independent cryptographic review or production readiness.

[Eight frozen binary fixtures](../tests/integration/fixtures/potb-v1/README.md)
cover configuration, initial state and two complete handoffs with evidence and
admission. Separate Python standard-library checks validate their hashes, framing,
configuration namespace, exact batch inclusion, historical frontier and age weights.
The original 50 genesis-v1/v2 fixtures remain unchanged.

On 2026-10-03, Windows/Rust 1.99.0 passed the full debug workspace suite, focused
release consensus/producer/compatibility suites, strict workspace Clippy/rustdoc,
formatting, standalone fuzz-target compilation and all seven Python script tests.
The 78-seed million-input deterministic mutation campaign passed with 292,867
accepted decoder paths. No hosted runs, Linux execution, coverage-guided campaign
or external review are claimed by these local checks.
