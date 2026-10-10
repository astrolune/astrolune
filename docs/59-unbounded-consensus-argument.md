<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 59. Unbounded consensus safety and liveness argument

`crates/consensus/tests/unbounded_model.rs` discharges a parameterized safety and
liveness argument for the fixed-height `BFT` voting rules. Parameterized means the
results do not depend on a fixed validator count, a fixed round count or a fixed
candidate-value space, which is what distinguishes this file from the bounded
exploration recorded in
[the bounded formal model](55-formal-consensus-model.md). It is not a mechanized
proof: there is no proof assistant, no model checker and no solver in this
workspace, and none is a dependency. The argument is decomposed into lemmas, each
lemma has a finite proof obligation, Rust code enumerates and asserts every one of
those obligations, and the composition of the lemmas into the two theorems is
hand-written prose in this document.

## What an enumerated-obligation argument is

Each lemma below is stated precisely in a doc comment immediately above the test
that checks it, and the obligation that test enumerates is finite for one of three
reasons. An arithmetic lemma holds over the whole `u128` range because the
obligation is an identity in integer arithmetic rather than a reachability
question, so a dense sweep together with the range extremes decides it. A quotient
lemma holds for every seat count because the abstraction map reads only four weight
sums, so enumerating the whole simplex of those four sums covers every committee of
every size with every weight vector that produces them. A case-split lemma holds at
every round index because the rules compare round numbers only by order and
adjacency and advance them only by one, so a window of consecutive rounds together
with a check that the verdicts survive shifting that window decides it.

What this framing does not establish: the lemma statements themselves are
hand-written, the composition of lemmas into theorems is hand-written, and nothing
mechanically checks either. A wrong lemma statement or a wrong composition would
not be caught by any assertion in the file. The transition rules are also
transcribed by hand from `crates/consensus/src/local.rs` rather than extracted from
it, so the file establishes properties of the transcription and, only at the
sampled conformance points, of the implementation.

## Quorum intersection over arbitrary committee weight

Voting power is `u128`. The quorum comes from the production
`consensus::quorum_power`, whose closed form is already machine-checked at the
`u128` extremes inside `crates/consensus/src/weight.rs`, and the threshold is
derived from it rather than restated.

```text
quorum_power(total) = (total / 3) * 2 + (total % 3) * 2 / 3 + 1
                    = total - total / 3 + [total % 3 == 0]
threshold(total)    = 2 * quorum_power(total) - total
```

Lemma 1a checks the closed form and the residue-class form at every total in a
dense sweep and at the `u128` extremes, covering all three residue classes at both
ends of the range. Lemma 1b checks that the quorum is strictly above two thirds and
is the least such weight, written as `quorum > 2 * (total - quorum)` and
`quorum - 1 <= 2 * (total - (quorum - 1))` so that no intermediate term can
overflow, and that the quorum never advances by more than one unit per unit of
total. Lemma 1c enumerates every pair of seat subsets over six ten-seat weight
vectors and asserts that two subsets each carrying at least the quorum share at
least the threshold. Lemma 1d checks that the threshold is positive and that the
cut points are totally ordered as
`0 <= total - quorum < threshold <= quorum <= total` at every total, which is what
makes the weight classes of the next section well formed.

The bound is tight, not strict: the enumeration exhibits quorum pairs that share
exactly the threshold, which is why the bounded model reaches a conflicting
certificate on the bound whose equivocating weight equals it. Attainment is a
property of the weight vector rather than of the bound, and the two vectors below
that cannot split exactly are reported as attaining nothing instead of being
asserted.

| Weight vector | Total | Quorum | Threshold | Pairs | Exactly at the threshold |
|---|---|---|---|---|---|
| ten unit seats | 10 | 7 | 4 | 30,976 | 4,200 |
| nine unit seats and one of two | 11 | 8 | 5 | 19,600 | 2,688 |
| powers of two | 1,023 | 683 | 343 | 116,281 | 0 |
| one seat of a hundred | 109 | 73 | 37 | 262,144 | 0 |
| four of three and six of one | 18 | 13 | 8 | 22,801 | 1,080 |
| nine sixteenths of `u128::MAX` and one | 191,408,831,393,027,885,698,148,216,680,369,618,936 | 127,605,887,595,351,923,798,765,477,786,913,079,291 | 63,802,943,797,675,961,899,382,738,893,456,539,646 | 30,976 | 1,680 |

Lemma 1e records a defect in the product form of the threshold. The expression
`2 * quorum_power(total)` overflows `u128` for every total at or above
`3 * 2^126 - 1`, which is 255,211,775,190,703,847,597,530,955,573,826,158,591, so
the product form is not defined over the whole range. The test finds that total by
binary search over `u128` and asserts the closed form. The overflow-free form used
throughout this file is `quorum - (total - quorum)`, which equals the product form
wherever the doubling fits and is defined at every nonzero total.

What this section does not establish: nothing here is about committee membership,
signature authentication or how the weight of a quorum is collected. Equality in
the intersection bound is attainable, so no strict inequality is claimed. The two
existing test-only helpers that compute the threshold as
`2 * quorum_power(total) - total`, in `crates/consensus/tests/formal_model.rs` and
`crates/node/tests/support/hostile.rs`, wrap at the totals Lemma 1e identifies;
they are outside this file's ownership and are reported rather than changed.

## The weight-class abstraction

The seat count is removed from the state in two steps. First a slot of one round
and one phase is aggregated into four `u128` sums: the honest weight behind the
tracked value, the honest weight behind anything else including nil, the honest
weight that has not voted in the slot, and the Byzantine weight, which signs for
every value at once. Second each sum is replaced by its weight class against the
committee total, which gives a state space of exactly `5^4`, that is 625,
configurations with no dependence on the seat count at all.

```text
Zero        w == 0
Minor       0 < w <= total - quorum
Blocking    total - quorum < w < threshold
Accountable threshold <= w < quorum
Quorum      quorum <= w
```

Lemma 2a checks that these five classes partition `0..=total` at every total, that
the class increases with the weight, and that the `Blocking` class is nonempty
exactly when `total % 3 != 1`. Lemma 2b is the simulation obligation and is
enumerated: for every total in the sweep, every point of the aggregate simplex and
every weight an idle seat can move, the abstraction of the successor is a successor
the declared abstract relation permits, every aggregate abstracts to a well-formed
class tuple, and the two certificate predicates the safety argument reads are
decided exactly by the abstract class with no loss. Because the abstraction map
reads only the four sums, and because any point of that simplex is realized by a
committee of at most four seats carrying the corresponding `u128` weights, this
single enumeration covers every seat count and every weight vector.

Lemma 2c reports the precision of the abstraction instead of claiming it.
Enumerating the full `625 * 2 * 625` relation gives the exact number of triples the
declared relation permits and the exact number that a concrete aggregate in the
sweep witnesses; the difference is the slack of the over-approximation and is
printed. Soundness is the direction Lemma 2b checks. Completeness is not claimed in
general: the only completeness assertions are that at least one concrete aggregate
witnesses a triple which newly certifies the tracked value, and the reported counts
of the 625 abstract states that are well formed and that a concrete aggregate
witnesses.

Lemma 2d is the content the abstraction carries. Two different values can both be
certified in one slot exactly when the Byzantine weight reaches the threshold,
because the adversarial best split halves the honest weight and
`(total - faulty) / 2 + faulty >= quorum` is equivalent to `faulty >= threshold`.
The closed form is validated against an exhaustive inner search over every honest
split at the small totals, then applied across the dense sweep and at the `u128`
extremes. Written in the abstraction this is the well-formedness predicate every
abstract state satisfies: the two certificate classes are never both `Quorum`
unless the Byzantine class is `Accountable` or above.

Lemma 2e is the conformance direction and is sampled rather than enumerated. It
drives the real `PrevoteCertificate::from_votes` over real authenticated committees
with real Ed25519 signatures and asserts that the production certificate accepts a
seat subset exactly when the aggregate predicate and the weight class do, over
every subset at the seat counts where the power set is small and a deterministic
selection above them. It also checks that `AuthenticatedCommittee::quorum` equals
`quorum_power` of the committee total at seat counts up to the production ceiling
`MAX_COMMITTEE_MEMBERS`, which is 4,096.

What this section does not establish: the conformance is sampled, so divergence
between the aggregate model and the production certificate outside the listed seat
counts, weight shapes and subsets is possible. The declared abstract relation is a
strict over-approximation and is not claimed to be precise. The abstraction covers
one slot of one round and one phase, so on its own it says nothing about how slots
of different rounds relate, which is the next section's work.

## The inductive safety invariant

The invariant is a conjunction of six clauses over one honest seat's local state
and the authenticated certificates of the height. A held lock is backed by a
prevote certificate at its own round; the lock round never exceeds the active
round; a lock in the active round is held only after a precommit in that round; at
most one value is certified per slot; a finality certificate at a round forbids
every conflicting prevote certificate at that round and above; and an adopted
decision is backed by a finality certificate. The fourth and fifth clauses together
imply agreement.

Lemma 3a discharges the base case. The initial configuration, meaning round zero,
awaiting a proposal, no lock, no decision and no certificate, satisfies every clause
at every window base, and the real `LocalBft` resumed from a fresh protected journal
is exactly that configuration. The bounded model checks properties only on newly
inserted successors, so its initial state is never property-checked; this obligation
covers that gap explicitly.

Lemma 3b checks the implication from the invariant to agreement over every
certificate map in the window, under the side fact that a finality certificate at a
round implies a prevote certificate for the same value at that round. That side fact
is the weight statement that a precommit quorum contains honest weight above the
quorum complement, each unit of which precommitted only after a current-round
prevote certificate, so it comes from Lemma 1c and the production precommit rule
rather than being restated.

Lemma 3c discharges `invariant and guard implies invariant` for every rule. The case
space is the product of one honest local state, the certificate map over the window,
and the rule instance with its optional attached certificate. Neither the seat count
nor the absolute round index appears in it. Two clauses of the successor are
deferred by hypothesis rather than discharged here: a vote that would complete a
second certificate in one slot is excluded by Lemma 2d, and a prevote certificate
that would conflict with an existing decision is excluded by Lemma 3d composed with
Lemma 1c. Both exclusion counts are reported, so nothing is silently skipped, and
every clause other than the single-certificate clause is shown violable over the
case space so that no clause checks nothing. The single-certificate clause is
vacuous among pre-states by construction, because the pre-state space is already
restricted to maps that satisfy it, and it is exercised only in the successor
branch.

Lemma 3d is the crux. Let an honest seat hold a durable lock on a value from a
round, and let its active round be strictly above the lock round. If no prevote
certificate for any other value exists at any round strictly between the two, then
the prevote rule issues either nil or the locked value, for every offered proposal
and every attached proof the rule accepts. That is a finite case split over the lock
round, the active round, the proof round, the value equalities and the certificate
map. The decision lock then follows by choosing the least round at or above the
decision at which a conflicting prevote certificate exists, intersecting the
blocking set of honest precommitters with that certificate's quorum through Lemma
1c, and contradicting minimality through this lemma. That composition is prose in
this document; the well-founded choice of a least round is why the result holds for
unboundedly many rounds, and nothing in the file checks the composition itself.

Lemma 3e discharges the monotonicity obligation that the bounded model asserts only
in prose. Every honest enabling condition that issues a non-nil vote, sets a lock or
adopts a decision is monotone in the Byzantine message pool: adding a message never
disables it. The subset lattice is generated by single-message additions, so
checking every one-message extension discharges monotonicity over every superset,
and the full subset-pair enumeration is run as well. Folding Byzantine weight into
one constant maximal pool is therefore sound for exactly these guards. The nil-vote
outcome is anti-monotone, and the enumeration reports how many single-message
additions turn a nil prevote non-nil rather than asserting the claim away. That is
why the over-approximation is legitimate on the bounded model's asynchronous bounds,
where every timeout is unconditionally enabled, and why it is not a general claim
about the eventual-synchrony timeout guards.

Lemma 3f checks round-index invariance. The whole preservation enumeration is run at
several window bases and the tallies are asserted identical, which is what licenses
reading the finite enumeration at one base as an obligation discharged at every
round index. A window whose top round is `u32::MAX` is the single exception and is
checked separately: every tally except the obligation count is identical, and the
obligation count is strictly lower by exactly the round advances
`timeout_precommit` refuses at the ceiling, so the exception removes transitions
rather than adding any.

What this section does not establish: the invariant is hand-written and so is the
composition of these lemmas into the agreement theorem. The enumeration ranges over
a window of consecutive rounds and treats rounds outside the window as carrying no
certificate, which is a restriction of the case space rather than a statement about
the protocol. Where the durable journal rejects a transition the voting rules
themselves permit, the transcription is deliberately the more permissive of the two,
so preservation is checked over a superset of the production transitions; that makes
the result conservative in the right direction but means the transcription is not an
exact model of what the journal admits. The invariant covers one height and says
nothing about committee rotation, `PoTB` weight transitions, admission, governance
or handoff.

## Unbounded round liveness

The liveness claim is not bounded-round decision reachability. It is that under
eventual synchrony, from any round, a decision is reached within a number of rounds
bounded by the seat count, and the bound is exactly one more than the longest run of
consecutive faulty seats in the committed seat order.

```text
round_robin_proposer(round) = seats[(height % count + round % count) % count]
```

Lemma 4a checks round-robin fairness: over any window of `count` consecutive rounds
the designated seat takes every seat index exactly once, at every height, at every
seat count in the sweep and at every window base that fits in `u32`, including the
window that ends at `u32::MAX`. The transcription is checked against the production
`AuthenticatedCommittee::round_robin_proposer` at every seat count a committee can
be built for here, including the production ceiling of 4,096 seats. Because the
designation advances by exactly one seat per round, consecutive faulty leaders are
exactly cyclic runs of faulty seats, which Lemma 4b turns into the latency bound: it
enumerates every Byzantine placement at the seat counts where the power set is
small, asserts that the worst delay over all window bases equals the longest cyclic
faulty run, and separately checks the adversarial placements that maximise
consecutive faulty leaders, namely one contiguous block one unit below the
accountability threshold, at seat counts up to the production ceiling, at every base
and at the `u32` ceiling.

Lemma 4c checks that the proposer lock rule never blocks an honest leader: proposing
the value it is locked on needs no evidence, and an unlocked leader may propose
anything, over every lock position, every certificate configuration and every round
index in the window. Lemma 4d checks prevote acceptance. Under the delivery
hypothesis that the leader knows the highest prevote certificate any honest seat
holds, a leader reproposing that certificate is prevoted by every honest seat whose
state satisfies the invariant: a lock is backed by a certificate at its own round,
so the reproposed round is at or above every honest lock round, and the prevote lock
rule permits the value both when the reproposed round is strictly above the lock
round and when the two are equal, the latter because at most one value is certified
per slot. The equal case is counted separately so the enumeration is known to reach
it.

Lemma 4e makes the honest-majority precondition explicit and shows it is strictly
stronger than the safety precondition. A certificate can form from honest weight
alone exactly when the Byzantine weight is at most `total - quorum`, whereas safety
needs only `faulty < threshold`, and the first is strictly inside the second at
every total. The gap is exactly the `Blocking` weight class: at such a Byzantine
weight the adversary cannot break safety and can still deny liveness forever. Its
width is `3 * quorum - 2 * total - 1`, which the residue class of the total fixes at
two units, zero units or one unit, so the band never widens as the committee grows.

Lemma 4f pins the round ceiling. `timeout_precommit` is the only rule that changes
the active round, it advances by exactly one, and it uses checked addition, so it
fails at `u32::MAX`. The ceiling is exercised against a real `LocalBft` resumed from
a protected journal already positioned at the last round of the height, which
refuses to advance. The liveness claim therefore holds from any round `base` with
`base + count - 1 <= u32::MAX` and no further.

What this section does not establish: eventual synchrony is assumed, not derived,
and the hypothesis that the leader knows the highest honest prevote certificate
before it proposes is a delivery assumption that nothing here checks. Timeout
durations, clock skew, partial-synchrony calibration and real message latency are
outside the argument entirely, and the latency bound is counted in rounds rather
than in time. The round-robin designation is the reference local policy in
`authenticated.rs`; the planned weighted `VRF` producer selection is a different
policy and is not covered.

## Results

On 2026-10-10, Windows 11 with Rust 1.99.0, the ordinary suite discharged these
obligations in 14.04 seconds unoptimized. Every number is the count the run
printed.

| Lemma | Obligation | Count |
|---|---|---|
| 1a | totals checked against both closed forms | 200,012 |
| 1b | totals checked for strictness and minimality | 200,012 |
| 1c | quorum subset pairs over 6 ten-seat weight vectors | 482,778 |
| 1d | totals checked for threshold ordering | 200,012 |
| 1e | totals where both threshold forms agree | 100,008 |
| 2a | totals checked for the class partition | 4,012 |
| 2b | aggregate slot transitions simulated | 753,984 |
| 2c | abstract relation triples enumerated | 9,376 |
| 2d | exhaustive honest splits, then total-and-faulty pairs | 13,040 and 8,006,101 |
| 2e | signed seat subsets through the production certificate | 220 |
| 3a | window bases, plus the production initial state | 5 |
| 3b | certificate maps checked for agreement | 69,888 |
| 3c | enabled transitions with the invariant preserved | 40,143 |
| 3d | crux lock-and-round pairs over 3 window bases | 78,732 |
| 3e | pool extensions, then full subset pairs | 491,520 and 10,628,820 |
| 3f | window bases with identical preservation tallies | 6 |
| 4a | fairness windows, then production designations | 2,688 and 676 |
| 4b | Byzantine placements enumerated | 32,766 |
| 4c | honest-leader configurations | 7,200 |
| 4d | honest seats accepting the reproposal | 6,576 |
| 4e | total-and-faulty precondition pairs | 41,372 |
| 4f | round advances, then round-preserving transitions | 10,935 and 174,510 |

Several measured facts are worth stating on their own. The least committee total at
which `2 * quorum_power(total)` overflows `u128` is
255,211,775,190,703,847,597,530,955,573,826,158,591. Of the 625 abstract states, 610
are well formed and 111 are witnessed by a concrete aggregate in the sweep; of the
9,376 triples the declared relation permits, 792 are witnessed, leaving 8,584 of
slack. Of the 40,143 preservation obligations, 12,782 complete a certificate, and of
those 1,904 are deferred to Lemma 2d and 4,158 to Lemma 3d, with every other clause
of every successor asserted directly. Of the 78,732 crux pairs, 62,694 satisfy the
hypothesis and force 282,852 nil or locked-value votes. Of the 491,520 single-message
pool extensions, 16,384 turn a nil prevote non-nil, which is the anti-monotone
direction measured rather than assumed. Shifting the preservation window to end at
`u32::MAX` drops the obligation count from 40,143 to 39,054, losing exactly the 1,089
round advances the checked addition refuses. The widest safe-but-not-live Byzantine
weight band over the whole sweep is two units. The `Blocking` class is nonempty at
2,674 of the 4,012 totals checked, which is exactly the totals that are not one
modulo three.

On the same date and machine the extended campaign ran in 27.92 seconds in release
and reported these wider counts.

| Lemma | Wider obligation | Count |
|---|---|---|
| 2b | aggregate slot transitions over totals 1 to 96 | 150,575,040 |
| 2d | total-and-faulty pairs over totals 1 to 40,000 and the extremes | 800,060,101 |
| 2e | signed seat subsets over 10 seat counts and 4 weight shapes | 10,128 |
| 3c | preservation obligations at 4 rounds and 2 values | 339,892 |
| 3c | preservation obligations at 3 rounds and 3 values | 114,780 |
| 3c | preservation obligations at 4 rounds and 2 values against the `u32` ceiling | 333,273 |
| 3d | crux lock-and-round pairs at 5 rounds and 2 values | 393,660 |
| 3d | crux lock-and-round pairs at 4 rounds and 3 values | 294,912 |
| 3e | single-message pool extensions over a 3-round 2-value lattice | 47,185,920 |
| 3e | full subset pairs over a 3-round 2-value lattice | 7,748,409,780 |
| 4b | Byzantine placements over seat counts 15 to 18 | 491,516 |
| 4d | honest seats accepting the reproposal at 4 rounds and 3 values | 35,400 |
| 4d | honest seats accepting the reproposal at 5 rounds against the ceiling | 85,760 |

## Running the checks

```text
cargo test --locked -p consensus --test unbounded_model
cargo test --locked -p consensus --test unbounded_model -- --nocapture
cargo test --release -p consensus --test unbounded_model -- --ignored --nocapture
```

The first command runs the twenty-two ordinary obligations. The second prints the
counts in the first table. The third runs the extended campaign, which repeats the
same finite obligations at wider windows, denser sweeps and wider conformance
sampling; it needs `--release` because the widest enumerations are too slow
unoptimized.

## Limits

This is an enumerated-obligation argument, never a mechanized proof. No proof
assistant, model checker or solver is used, and none is a dependency, so nothing
checks that the lemma statements are the right ones or that the prose composing them
into the agreement and liveness theorems is valid. In particular the well-founded
induction over rounds that turns Lemma 3d into the decision lock, and the
blocking-set intersection that turns Lemma 1c into the quorum overlap step, are
written in this document and are not machine-checked. A reader who wants a
machine-checked composition will not find one here.

The transition rules are transcribed by hand from `crates/consensus/src/local.rs`
and `crates/consensus/src/proposal.rs`. Conformance against the implementation is
sampled, not enumerated: the production quorum, designation, certificate formation,
initial state and round ceiling are exercised at the points named above, and
divergence outside those points is possible. Where the durable signing journal
rejects a transition the voting rules themselves permit, the transcription is the
more permissive of the two, which is conservative for preservation but is not an
exact model of the journal.

Two obligations are deferred rather than discharged, in both cases to a weight
lemma, and both deferral counts are printed by the preservation test so the gap is
visible. Two directions are reported rather than asserted: the precision of the
weight-class abstraction, which is a strict over-approximation with a measured
slack, and the anti-monotonicity of the nil-vote guard, which is counted rather than
claimed away.

The symbolic enumerations range over a window of consecutive rounds, assume no
certificate outside that window, and range over a small candidate-value space.
Round-index invariance is checked, so the window's position is not a limit, but its
width and the value count are: a configuration that needs more distinct rounds or
more distinct values than the widest window run here is outside the enumerated case
space. Liveness additionally assumes eventual synchrony and assumes that a leader
knows the highest prevote certificate any honest seat holds before it proposes;
neither is established here.

The argument covers one height. Committee rotation, `PoTB` weight transitions,
admission, governance, handoff and the planned weighted `VRF` producer selection are
outside it. Timeout durations, clock skew, partial-synchrony calibration and real
network behavior are not modelled. Independent provider review of this argument
remains open, and neither this file nor this document can close it.
