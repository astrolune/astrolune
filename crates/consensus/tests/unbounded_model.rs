// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Unbounded safety and liveness obligations for the fixed-height `BFT` voting rules.
//!
//! Property class: quorum intersection over arbitrary `u128` committee totals, a
//! weight-class abstraction that removes the seat count from the state, an
//! inductive safety invariant whose per-rule preservation obligations are finite,
//! and round-robin liveness at an arbitrary round index. Nothing here fixes a
//! validator count, a round count or a candidate-value space: every obligation is
//! either an arithmetic identity over the whole `u128` range, an exhaustive
//! enumeration of a case space whose size does not depend on those parameters, or
//! an explicitly sampled conformance check against the real `consensus` functions.
//! Derived quantities are taken from the production code rather than restated: the
//! quorum from `consensus::quorum_power` and `AuthenticatedCommittee::quorum`,
//! certificate formation from `PrevoteCertificate::from_votes`, designation from
//! `AuthenticatedCommittee::round_robin_proposer`, and the round ceiling from
//! `LocalBft::timeout_precommit`.
//!
//! This is not a mechanized proof. No proof assistant, model checker or solver is
//! used and none is a dependency, so the composition of these lemmas into the
//! safety and liveness theorems is a hand-written argument recorded in
//! `docs/59-unbounded-consensus-argument.md`; only the individual finite
//! obligations are discharged here. The transition rules are transcribed by hand
//! from `consensus::LocalBft` and are conformance-tested against it only at
//! sampled points, so divergence outside those samples is possible. The symbolic
//! enumerations range over a window of consecutive rounds and assume no
//! certificate outside that window. Nothing here establishes anything about
//! committee rotation, more than one height, timeout durations, clock skew,
//! partial-synchrony calibration or real network behavior, and nothing here is an
//! independent review of this argument.

use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, LocalBft, MAX_COMMITTEE_MEMBERS,
    PotbWeight, PrevoteCertificate, Vote, VotePhase, VotingStep, quorum_power,
};
use keystore::{DurableSigner, SigningContext, SigningPosition, SigningSafety};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

/// Chain identifier shared by every conformance fixture.
const CHAIN: u32 = 7;
/// Fixed trusted height; `round_robin_proposer` mixes it with the round.
const HEIGHT: u64 = 42;

// Lemma 1: quorum arithmetic and quorum intersection, unbounded in total weight.

/// Weight a minimal quorum leaves outside itself.
///
/// `Committee::total_power` rejects empty committees and zero-weight seats, so a
/// real committee total is at least one, and at such a total `quorum_power` never
/// exceeds the total, which is what makes this subtraction safe.
fn complement(total: u128) -> u128 {
    assert!(total > 0, "a trusted committee total is at least one");
    total - quorum_power(total)
}

/// Accountability threshold `2 * quorum_power(total) - total` in difference form.
///
/// The product `2 * quorum_power(total)` overflows `u128` above an exact total, so
/// the threshold is computed as `quorum - (total - quorum)`, which is equal to it
/// wherever the doubling fits and is defined at every nonzero `u128` total.
fn threshold(total: u128) -> u128 {
    quorum_power(total) - complement(total)
}

/// Residue-class closed form of the quorum.
fn residue_form(total: u128) -> u128 {
    let third = total / 3;
    match total % 3 {
        // Two thirds of `3k` is exactly `2k`, and two thirds of `3k+1` is also
        // `2k` after flooring, so the least strictly greater weight is `2k+1` in
        // both classes; in the remaining class it is `2k+2`.
        0 | 1 => 2 * third + 1,
        _ => 2 * third + 2,
    }
}

/// Totals that pin the arithmetic obligations to the edges of `u128`.
const EXTREME_TOTALS: [u128; 12] = [
    1,
    2,
    3,
    u128::MAX / 3,
    u128::MAX / 3 + 1,
    u128::MAX / 2 - 1,
    u128::MAX / 2,
    u128::MAX / 2 + 1,
    3 * (1u128 << 126) - 1,
    u128::MAX - 2,
    u128::MAX - 1,
    u128::MAX,
];

/// Dense sweep of small totals followed by the `u128` extremes.
fn arithmetic_totals(dense: u128) -> impl Iterator<Item = u128> {
    (1..=dense).chain(EXTREME_TOTALS)
}

/// Seat weight vectors used by the subset-pair intersection obligation.
///
/// Uniform, near-uniform, geometric, one dominant seat, blocked and a vector whose
/// seats are each a sixteenth of `u128::MAX`, so no result is an artefact of equal
/// weights or of small numbers.
fn intersection_vectors() -> Vec<Vec<u128>> {
    let huge = u128::MAX / 16;
    vec![
        vec![1; 10],
        vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 2],
        vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512],
        vec![100, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        vec![3, 3, 3, 3, 1, 1, 1, 1, 1, 1],
        vec![huge, huge, huge, huge, huge, huge, huge, huge, huge, 1],
    ]
}

/// Weight of one seat subset, indexed by the bits of `mask`.
fn subset_weight(weights: &[u128], mask: u32) -> u128 {
    weights
        .iter()
        .enumerate()
        .filter(|(seat, _)| mask >> u32::try_from(*seat).unwrap() & 1 == 1)
        .map(|(_, weight)| *weight)
        .sum()
}

/// Exhaustive subset-pair intersection obligation over one weight vector.
///
/// Returns the number of quorum pairs checked and the number that share exactly
/// the threshold, which is what makes the bound tight rather than strict.
fn intersection_obligations(weights: &[u128]) -> (u64, u64) {
    let seats = u32::try_from(weights.len()).unwrap();
    let total: u128 = weights.iter().sum();
    let quorum = quorum_power(total);
    let share = threshold(total);
    let masks = 1u32 << seats;
    let subset: Vec<u128> = (0..masks)
        .map(|mask| subset_weight(weights, mask))
        .collect();
    let mut pairs = 0u64;
    let mut tight = 0u64;
    for first in 0..masks {
        if subset[first as usize] < quorum {
            continue;
        }
        for second in 0..masks {
            if subset[second as usize] < quorum {
                continue;
            }
            let shared = subset[(first & second) as usize];
            assert!(
                shared >= share,
                "quorums {first:#x} and {second:#x} over total {total} share {shared}, below the threshold {share}"
            );
            pairs += 1;
            tight += u64::from(shared == share);
        }
    }
    (pairs, tight)
}

/// Lemma 1a. For every `total: u128`, `quorum_power(total)` equals
/// `total - total / 3 + [total % 3 == 0]` and equals the residue-class form. The
/// obligation is an arithmetic identity, so it is unbounded in committee weight
/// rather than bounded by an explored state space; the sweep plus the extremes
/// cover every residue class at both ends of the range.
#[test]
fn quorum_power_matches_the_closed_form_on_every_residue_class_and_at_the_u128_extremes() {
    let mut residues = [0u64; 3];
    let mut checked = 0u64;
    for total in arithmetic_totals(200_000) {
        let quorum = quorum_power(total);
        assert_eq!(
            quorum,
            total - total / 3 + u128::from(total % 3 == 0),
            "total {total}: quorum {quorum} diverged from the closed form machine-checked in weight.rs"
        );
        assert_eq!(
            quorum,
            residue_form(total),
            "total {total}: quorum {quorum} diverged from the residue-class form"
        );
        residues[usize::try_from(total % 3).unwrap()] += 1;
        checked += 1;
    }
    assert_eq!(quorum_power(0), 1, "no quorum can form over zero weight");
    assert!(
        residues.iter().all(|count| *count > 0),
        "the sweep must cover all three residue classes, saw {residues:?}"
    );
    println!(
        "lemma 1a closed form: {checked} totals checked, residue classes {residues:?}, {} extremes",
        EXTREME_TOTALS.len()
    );
}

/// Lemma 1b. `quorum_power(total)` is strictly above two thirds of `total` and is
/// the least such weight, stated as `quorum > 2 * (total - quorum)` and
/// `quorum - 1 <= 2 * (total - (quorum - 1))` so that no intermediate term can
/// overflow `u128`. The quorum is also non-decreasing in the total and never
/// advances by more than one unit per unit of total.
#[test]
fn quorum_power_is_the_least_weight_strictly_above_two_thirds_at_every_total() {
    let mut checked = 0u64;
    let mut previous: Option<(u128, u128)> = None;
    for total in arithmetic_totals(200_000) {
        let quorum = quorum_power(total);
        let outside = complement(total);
        assert!(
            quorum > 2 * outside,
            "total {total}: quorum {quorum} is not strictly above twice its complement {outside}"
        );
        let lower = quorum - 1;
        assert!(
            lower <= 2 * (total - lower),
            "total {total}: {lower} is already above two thirds, so {quorum} is not the least"
        );
        if let Some((earlier, before)) = previous.filter(|(earlier, _)| *earlier + 1 == total) {
            assert!(
                quorum >= before && quorum - before <= 1,
                "total {total}: quorum moved from {before} to {quorum} across total {earlier}"
            );
        }
        previous = Some((total, quorum));
        checked += 1;
    }
    println!("lemma 1b minimality: {checked} totals checked");
}

/// Lemma 1c. Over one committee total, any two seat subsets that each carry at
/// least `quorum_power(total)` share at least `2 * quorum_power(total) - total`.
/// The bound is tight rather than strict: on weight vectors that admit the split,
/// the enumeration exhibits pairs sharing exactly that weight, which is why the
/// bounded model reaches a conflicting certificate when the equivocating weight
/// equals the threshold. Attainment is a property of the weight vector, not of the
/// bound, so vectors that cannot split exactly are reported rather than asserted.
#[test]
fn two_quorums_over_one_total_always_share_at_least_the_accountability_threshold() {
    let mut pairs = 0u64;
    let mut tight = 0u64;
    let mut attaining = 0usize;
    let vectors = intersection_vectors();
    for weights in &vectors {
        let (checked, exact) = intersection_obligations(weights);
        pairs += checked;
        tight += exact;
        attaining += usize::from(exact > 0);
        println!(
            "  {weights:?}: total {}, quorum {}, threshold {}, {checked} pairs, {exact} exactly at the threshold",
            weights.iter().sum::<u128>(),
            quorum_power(weights.iter().sum::<u128>()),
            threshold(weights.iter().sum::<u128>())
        );
    }
    assert!(
        attaining > 0,
        "no weight vector attains the threshold, so the bound was not shown tight"
    );
    println!(
        "lemma 1c intersection: {pairs} quorum pairs over {} weight vectors of 10 seats, {tight} share exactly the threshold, {attaining} vectors attain it",
        vectors.len()
    );
}

/// Lemma 1d. At every nonzero `u128` total the accountability threshold is at
/// least one, strictly exceeds the quorum complement `total - quorum`, and never
/// exceeds the quorum. The three cut points are therefore totally ordered as
/// `0 <= total - quorum < threshold <= quorum <= total`, which is what makes the
/// weight classes of Lemma 2 well formed at every total.
#[test]
fn the_accountability_threshold_is_positive_and_attained_at_every_total() {
    let mut checked = 0u64;
    for total in arithmetic_totals(200_000) {
        let share = threshold(total);
        let outside = complement(total);
        let quorum = quorum_power(total);
        assert!(
            share >= 1,
            "total {total}: threshold {share} is not positive"
        );
        assert!(
            share > outside,
            "total {total}: threshold {share} does not exceed the complement {outside}"
        );
        assert!(
            share <= quorum && quorum <= total,
            "total {total}: cut points {outside} < {share} <= {quorum} are not ordered"
        );
        checked += 1;
    }
    for total in 1..=512u128 {
        // Over `total` unit seats the first and the last `quorum` seats are both
        // quorums and overlap in exactly `2 * quorum - total` seats.
        assert_eq!(
            2 * quorum_power(total) - total,
            threshold(total),
            "total {total}: unit-seat overlap diverged from the threshold"
        );
    }
    println!(
        "lemma 1d threshold: {checked} totals checked, attainment over unit-seat committees up to 512"
    );
}

/// Lemma 1e. `2 * quorum_power(total)` overflows `u128` for every total at or
/// above `3 * 2^126 - 1`, so the product form of the accountability threshold is
/// not defined over the whole range and the difference form
/// `quorum - (total - quorum)` must be used instead. Below the crossover the two
/// forms agree at every total in the sweep.
#[test]
fn doubling_the_quorum_overflows_u128_above_an_exact_total_so_the_threshold_needs_the_difference_form()
 {
    let overflows = |total: u128| quorum_power(total).checked_mul(2).is_none();
    assert!(overflows(u128::MAX), "the doubling must wrap at u128::MAX");
    let mut low = 1u128;
    let mut high = u128::MAX;
    while low < high {
        let middle = low + (high - low) / 2;
        if overflows(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let first = low;
    assert_eq!(
        first,
        3 * (1u128 << 126) - 1,
        "the least overflowing total diverged from the closed form"
    );
    assert!(!overflows(first - 1), "total {} must not wrap", first - 1);
    let mut agreed = 0u64;
    for total in arithmetic_totals(100_000) {
        if let Some(doubled) = quorum_power(total).checked_mul(2) {
            assert_eq!(
                doubled - total,
                threshold(total),
                "total {total}: the product form and the difference form disagree"
            );
            agreed += 1;
        } else {
            assert!(
                total >= first,
                "total {total} wrapped below the crossover {first}"
            );
            assert!(threshold(total) >= 1, "total {total}: threshold vanished");
        }
    }
    println!(
        "lemma 1e overflow: least overflowing total {first}, {agreed} totals where both forms agree"
    );
}

// Lemma 2: a weight-class abstraction that removes the seat count from the state.

/// Weight class of one aggregate against one committee total.
///
/// The three cut points `total - quorum`, `2 * quorum - total` and `quorum` are
/// totally ordered at every total by Lemma 1d, so these five classes partition
/// `0..=total` for a committee of any size with any `u128` weights. A class is all
/// the abstraction keeps, which is what removes the seat count from the state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Mass {
    /// No weight at all.
    Zero,
    /// Positive but at most `total - quorum`, so the complement still forms a quorum.
    Minor,
    /// Above `total - quorum` and below the accountability threshold: blocks every
    /// quorum that excludes it, yet is too small to sit in two conflicting quorums.
    Blocking,
    /// At or above `2 * quorum - total` and below `quorum`: large enough to be the
    /// shared weight of two conflicting quorums, so an offence here is attributable.
    Accountable,
    /// At least `quorum`, so this weight alone certifies.
    Quorum,
}

/// Classifies one aggregate weight against one committee total.
fn mass(total: u128, weight: u128) -> Mass {
    if weight >= quorum_power(total) {
        Mass::Quorum
    } else if weight >= threshold(total) {
        Mass::Accountable
    } else if weight > complement(total) {
        Mass::Blocking
    } else if weight > 0 {
        Mass::Minor
    } else {
        Mass::Zero
    }
}

/// Every weight class, in increasing order.
const ALL_MASSES: [Mass; 5] = [
    Mass::Zero,
    Mass::Minor,
    Mass::Blocking,
    Mass::Accountable,
    Mass::Quorum,
];

/// One prevote or precommit slot aggregated over an arbitrary number of seats.
///
/// The four fields sum to the committee total. The seat count and the individual
/// weights have already been summed away, so one `Aggregate` stands for every
/// committee of every size whose votes produce those four sums.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Aggregate {
    /// Honest weight that has filled the slot with the tracked value.
    tracked: u128,
    /// Honest weight that has filled the slot with anything else, nil included.
    conflicting: u128,
    /// Honest weight that has not filled the slot yet.
    idle: u128,
    /// Byzantine weight, which signs for every value in the slot at once.
    faulty: u128,
}

impl Aggregate {
    /// Committee total this aggregate covers.
    fn total(self) -> u128 {
        self.tracked + self.conflicting + self.idle + self.faulty
    }

    /// Authenticated weight behind the tracked value, equivocation included.
    fn for_tracked(self) -> u128 {
        self.tracked + self.faulty
    }

    /// Authenticated weight behind some conflicting value, equivocation included.
    fn for_conflicting(self) -> u128 {
        self.conflicting + self.faulty
    }

    /// Whether an independently verifiable certificate for the tracked value exists.
    fn certifies_tracked(self) -> bool {
        self.for_tracked() >= quorum_power(self.total())
    }

    /// Whether an independently verifiable certificate for a conflicting value exists.
    fn certifies_conflicting(self) -> bool {
        self.for_conflicting() >= quorum_power(self.total())
    }
}

/// Direction an idle honest seat can move in one slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Fill {
    /// The seat fills the slot with the tracked value.
    Tracked,
    /// The seat fills the slot with any other value, nil included.
    Conflicting,
}

/// Both fill directions.
const ALL_FILLS: [Fill; 2] = [Fill::Tracked, Fill::Conflicting];

/// Abstract slot configuration: four weight classes and nothing else.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Classes {
    /// Class of the authenticated weight certifying the tracked value.
    tracked: Mass,
    /// Class of the authenticated weight certifying some conflicting value.
    conflicting: Mass,
    /// Class of the honest weight still free to fill the slot.
    idle: Mass,
    /// Class of the Byzantine weight, constant for the height.
    faulty: Mass,
}

/// Abstraction map from one aggregated slot to its weight classes.
fn classes(slot: Aggregate) -> Classes {
    let total = slot.total();
    Classes {
        tracked: mass(total, slot.for_tracked()),
        conflicting: mass(total, slot.for_conflicting()),
        idle: mass(total, slot.idle),
        faulty: mass(total, slot.faulty),
    }
}

/// Every abstract configuration, in a deterministic order.
fn all_classes() -> Vec<Classes> {
    let mut out = Vec::with_capacity(625);
    for tracked in ALL_MASSES {
        for conflicting in ALL_MASSES {
            for idle in ALL_MASSES {
                for faulty in ALL_MASSES {
                    out.push(Classes {
                        tracked,
                        conflicting,
                        idle,
                        faulty,
                    });
                }
            }
        }
    }
    out
}

/// Declared abstract transition relation, independent of the seat count and total.
///
/// A fill moves honest weight out of the idle aggregate into exactly one of the
/// two authenticated aggregates, so the filled aggregate can only grow, the other
/// one and the Byzantine weight cannot change, and the idle weight can only
/// shrink. Reaching the `Quorum` class additionally needs enough idle weight to
/// close the gap, which `closing_mass` states at the class level. Only classes are
/// compared, so the relation is a finite over-approximation of the aggregate
/// relation rather than a faithful copy.
fn abstract_permits(from: Classes, fill: Fill, to: Classes) -> bool {
    if from.idle == Mass::Zero
        || to.faulty != from.faulty
        || to.idle > from.idle
        || !wellformed(from)
        || !wellformed(to)
    {
        return false;
    }
    let (before, after) = match fill {
        Fill::Tracked => {
            if to.conflicting != from.conflicting || to.tracked < from.tracked {
                return false;
            }
            (from.tracked, to.tracked)
        }
        Fill::Conflicting => {
            if to.tracked != from.tracked || to.conflicting < from.conflicting {
                return false;
            }
            (from.conflicting, to.conflicting)
        }
    };
    after != Mass::Quorum || before == Mass::Quorum || from.idle >= closing_mass(before)
}

/// Least idle class that can close the gap from one certificate class to a quorum.
///
/// At a certificate class of weight `w` below the quorum, the moved weight must be
/// at least `quorum - w`, so the idle weight must reach that. Mapping the upper
/// bound of each class through `quorum - w` gives this class-level dual: a `Zero`
/// certificate needs a whole quorum of idle weight, a `Minor` one needs at least
/// the accountability threshold, a `Blocking` one needs more than the complement,
/// and an `Accountable` one needs at least one unit.
fn closing_mass(certificate: Mass) -> Mass {
    match certificate {
        Mass::Zero => Mass::Quorum,
        Mass::Minor => Mass::Accountable,
        Mass::Blocking => Mass::Blocking,
        Mass::Accountable | Mass::Quorum => Mass::Minor,
    }
}

/// Class-level well-formedness, which is Lemma 2d written in the abstraction.
///
/// Two different values cannot both be certified unless the Byzantine weight
/// reaches the accountability threshold, because
/// `for_tracked + for_conflicting + idle == total + faulty` and two quorums force
/// `total + faulty >= 2 * quorum`. The predicate mentions neither the seat count
/// nor the total, so it is the abstract form of the safety property.
fn wellformed(state: Classes) -> bool {
    state.tracked != Mass::Quorum
        || state.conflicting != Mass::Quorum
        || state.faulty >= Mass::Accountable
}

/// Applies one fill of `weight` units to an aggregated slot.
fn fill_aggregate(slot: Aggregate, fill: Fill, weight: u128) -> Aggregate {
    let mut next = slot;
    next.idle -= weight;
    match fill {
        Fill::Tracked => next.tracked += weight,
        Fill::Conflicting => next.conflicting += weight,
    }
    next
}

/// Walks every aggregated slot over one total and every fill it admits.
fn for_each_fill(total: u128, mut visit: impl FnMut(Aggregate, Fill, Aggregate)) {
    for faulty in 0..=total {
        for tracked in 0..=total - faulty {
            for conflicting in 0..=total - faulty - tracked {
                let slot = Aggregate {
                    tracked,
                    conflicting,
                    idle: total - faulty - tracked - conflicting,
                    faulty,
                };
                for fill in ALL_FILLS {
                    for weight in 1..=slot.idle {
                        visit(slot, fill, fill_aggregate(slot, fill, weight));
                    }
                }
            }
        }
    }
}

/// Whether some split of the honest weight certifies two different values at once.
///
/// The adversarial best split halves the honest weight, and
/// `(total - faulty) / 2 + faulty` equals `(total + faulty) / 2` over the
/// integers, so this form decides the question without a term that could overflow.
fn conflicting_certificates_possible(total: u128, faulty: u128) -> bool {
    (total - faulty) / 2 + faulty >= quorum_power(total)
}

/// Exhaustive inner search validating `conflicting_certificates_possible`.
fn conflicting_split_exists(total: u128, faulty: u128) -> bool {
    let quorum = quorum_power(total);
    let honest = total - faulty;
    (0..=honest).any(|first| first + faulty >= quorum && (honest - first) + faulty >= quorum)
}

/// Byzantine weights that bracket the threshold at one total, for the extremes
/// where a dense sweep is impossible.
fn bracket_faulty(total: u128, share: u128) -> Vec<u128> {
    let mut out = vec![0, total];
    for candidate in [
        share.saturating_sub(2),
        share.saturating_sub(1),
        share,
        share + 1,
        share + 2,
        complement(total),
        complement(total) + 1,
        quorum_power(total) - 1,
        quorum_power(total),
        total / 3,
        total / 2,
    ] {
        if candidate <= total {
            out.push(candidate);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Deterministic committee seed for one seat, distinct for every seat index.
fn seed(index: usize) -> [u8; 32] {
    let mut bytes = [1u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
    bytes
}

/// Registered public key for one seat.
fn public(index: usize) -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&seed(index))
}

/// Committee identity for one seat.
fn identity(index: usize) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&public(index)).0)
}

/// Builds the real authenticated committee over one weight vector.
fn authenticated(weights: &[u128]) -> AuthenticatedCommittee {
    let members = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| CommitteeMember {
            id: identity(index),
            power: PotbWeight(*weight),
        })
        .collect();
    let keys: Vec<[u8; 32]> = (0..weights.len()).map(public).collect();
    AuthenticatedCommittee::new(
        CHAIN,
        &Committee {
            height: HEIGHT,
            members,
        },
        &keys,
    )
    .unwrap()
}

/// Canonical header for one candidate value.
fn header(root: Hash256, value: usize) -> BlockHeader {
    BlockHeader {
        height: HEIGHT,
        parent: Hash256([1; 32]),
        transactions_root: Hash256([2; 32]),
        state_root: Hash256([0xA0 ^ u8::try_from(value).unwrap(); 32]),
        receipts_root: Hash256([4; 32]),
        committee_root: root,
        capacity: Resources::ZERO,
    }
}

/// Prevote signed with one seat key, as a Byzantine operator or an honest seat
/// running the production voter would both emit it.
fn signed_prevote(root: Hash256, index: usize, round: u32, block: Hash256) -> Vote {
    let mut vote = Vote {
        chain_id: CHAIN,
        height: HEIGHT,
        committee_root: root,
        round,
        phase: VotePhase::Prevote,
        block: Some(block),
        voter: identity(index),
        signature: [0; 64],
    };
    vote.signature = crypto::blake2s::ed25519_sign(&seed(index), &vote.signing_hash().0);
    vote
}

/// Prebuilt authenticated committee with one signed prevote per seat, so a subset
/// can be offered to `PrevoteCertificate::from_votes` without resigning anything.
struct Certifier {
    /// Real verification context over the weight vector.
    committee: AuthenticatedCommittee,
    /// One real prevote per seat for the same round and block.
    votes: Vec<Vote>,
}

impl Certifier {
    /// Builds the committee and signs one prevote per seat.
    fn new(weights: &[u128]) -> Self {
        let committee = authenticated(weights);
        let root = committee.root();
        let block = header(root, 0).compute_hash();
        let mut votes: Vec<Vote> = (0..weights.len())
            .map(|index| signed_prevote(root, index, 3, block))
            .collect();
        votes.sort_by_key(|vote| vote.voter);
        Self { committee, votes }
    }

    /// Whether the real certificate accepts exactly this seat subset.
    fn certifies(&self, mask: u64) -> bool {
        let votes: Vec<Vote> = self
            .votes
            .iter()
            .enumerate()
            .filter(|(seat, _)| mask >> u64::try_from(*seat).unwrap() & 1 == 1)
            .map(|(_, vote)| vote.clone())
            .collect();
        PrevoteCertificate::from_votes(&self.committee, votes).is_ok()
    }

    /// Weight the subset carries, summed from the trusted committee powers.
    fn carried(&self, mask: u64) -> u128 {
        self.votes
            .iter()
            .enumerate()
            .filter(|(seat, _)| mask >> u64::try_from(*seat).unwrap() & 1 == 1)
            .map(|(_, vote)| self.committee.voting_power(vote.voter).unwrap())
            .sum()
    }
}

/// Lemma 2a. The abstraction map is well defined at every total: the five weight
/// classes partition `0..=total`, they increase with the weight they stand for,
/// and the `Blocking` class is nonempty exactly when `total % 3 != 1`.
#[test]
fn the_weight_classes_partition_every_total_and_increase_with_the_weight() {
    let mut checked = 0u64;
    let mut blocking_totals = 0u64;
    for total in arithmetic_totals(4_000) {
        let quorum = quorum_power(total);
        let share = threshold(total);
        let outside = complement(total);
        assert_eq!(mass(total, 0), Mass::Zero, "total {total}: zero weight");
        assert_eq!(
            mass(total, quorum),
            Mass::Quorum,
            "total {total}: the quorum itself"
        );
        assert_eq!(
            mass(total, total),
            Mass::Quorum,
            "total {total}: the whole committee"
        );
        assert!(
            mass(total, share) >= Mass::Accountable,
            "total {total}: threshold {share} classified as {:?}",
            mass(total, share)
        );
        if outside > 0 {
            assert_eq!(
                mass(total, outside),
                Mass::Minor,
                "total {total}: the complement {outside} must be Minor"
            );
        }
        let blocking = share > outside + 1;
        assert_eq!(
            blocking,
            total % 3 != 1,
            "total {total}: the Blocking class is nonempty iff the total is not 1 mod 3"
        );
        blocking_totals += u64::from(blocking);
        checked += 1;
    }
    for total in 1..=600u128 {
        let mut previous = Mass::Zero;
        for weight in 0..=total {
            let current = mass(total, weight);
            assert!(
                current >= previous,
                "total {total}: class fell from {previous:?} to {current:?} at weight {weight}"
            );
            previous = current;
        }
    }
    println!(
        "lemma 2a classes: {checked} totals checked, {blocking_totals} with a nonempty Blocking class, monotone over every weight up to total 600"
    );
}

/// Lemma 2b (simulation, enumerated). Every aggregate slot transition is matched
/// by a transition the declared abstract relation permits, every aggregate
/// abstracts to a well-formed class tuple, and the two certificate predicates the
/// safety argument reads are decided exactly by the abstract class with no loss.
/// The obligation is the whole aggregate simplex with every fill weight,
/// enumerated for every total in the sweep. Because the abstraction map reads only
/// the four sums, this covers every committee of every seat count with every
/// `u128` weight vector that produces those sums.
#[test]
fn every_aggregate_slot_transition_is_matched_by_an_abstract_class_transition() {
    let (obligations, realized) = simulation_obligations(32);
    println!(
        "lemma 2b simulation: {obligations} aggregate transitions enumerated over totals 1..=32, {realized} distinct abstract triples realized"
    );
}

/// Discharges the simulation obligation over totals `1..=dense`.
fn simulation_obligations(dense: u128) -> (u64, usize) {
    let mut obligations = 0u64;
    let mut realized = std::collections::HashSet::new();
    for total in 1..=dense {
        for_each_fill(total, |slot, fill, next| {
            let from = classes(slot);
            let to = classes(next);
            assert!(
                wellformed(from) && wellformed(to),
                "total {total}: {slot:?} or {next:?} abstracts to an ill-formed class, so two values were certified below the threshold"
            );
            assert!(
                abstract_permits(from, fill, to),
                "total {total}: {slot:?} filled {fill:?} into {next:?} abstracts to {from:?} then {to:?}, which the relation forbids"
            );
            assert_eq!(
                next.certifies_tracked(),
                to.tracked == Mass::Quorum,
                "total {total}: {next:?} tracked certificate predicate diverged from its class"
            );
            assert_eq!(
                next.certifies_conflicting(),
                to.conflicting == Mass::Quorum,
                "total {total}: {next:?} conflicting certificate predicate diverged from its class"
            );
            realized.insert((from, fill, to));
            obligations += 1;
        });
    }
    (obligations, realized.len())
}

/// Lemma 2c (precision, enumerated). The declared abstract relation is a strict
/// over-approximation: of the triples it permits, only some have a concrete
/// aggregate witness. Both counts are enumerated exactly over the full
/// `625 * 2 * 625` abstract relation, and the well-formed and witnessed parts of
/// the `625` abstract states are counted too, so the slack is reported rather than
/// hidden. Soundness is the direction Lemma 2b checks; completeness is not claimed,
/// except that every triple which newly certifies the tracked value is witnessed.
#[test]
fn the_abstract_relation_is_a_strict_over_approximation_with_an_exact_slack_count() {
    let mut realized = std::collections::HashSet::new();
    let mut reachable = std::collections::HashSet::new();
    for total in 1..=32u128 {
        for_each_fill(total, |slot, fill, next| {
            reachable.insert(classes(slot));
            reachable.insert(classes(next));
            realized.insert((classes(slot), fill, classes(next)));
        });
    }
    let states = all_classes();
    assert_eq!(
        states.len(),
        625,
        "the abstract state space must be exactly five classes to the fourth power"
    );
    let formed = states.iter().filter(|state| wellformed(**state)).count();
    let mut permitted = 0u64;
    let mut witnessed = 0u64;
    let mut forming = 0u64;
    let mut forming_witnessed = 0u64;
    for from in &states {
        for fill in ALL_FILLS {
            for to in &states {
                if !abstract_permits(*from, fill, *to) {
                    continue;
                }
                permitted += 1;
                let seen = realized.contains(&(*from, fill, *to));
                witnessed += u64::from(seen);
                if to.tracked == Mass::Quorum && from.tracked != Mass::Quorum {
                    forming += 1;
                    forming_witnessed += u64::from(seen);
                }
            }
        }
    }
    assert!(
        witnessed > 0 && witnessed < permitted,
        "the relation is a strict over-approximation, saw {witnessed} of {permitted}"
    );
    assert!(
        forming_witnessed > 0,
        "no witnessed transition newly certifies the tracked value"
    );
    assert!(
        reachable.iter().all(|state| wellformed(*state)),
        "a concrete aggregate abstracted to an ill-formed class tuple"
    );
    println!(
        "lemma 2c precision: {} abstract states, {formed} well formed, {} witnessed by a concrete aggregate; {permitted} permitted triples, {witnessed} witnessed, {} slack; {forming_witnessed} of {forming} certificate-forming triples witnessed",
        states.len(),
        reachable.len(),
        permitted - witnessed
    );
}

/// Lemma 2d. In one slot, two different values can both be certified exactly when
/// the Byzantine weight reaches the accountability threshold. Equivalently, below
/// the threshold at most one value per slot carries a certificate, whatever the
/// seat count and whatever the weights. The closed form is checked against an
/// exhaustive inner search over every honest split at the small totals, then
/// applied over a dense total sweep and at the `u128` extremes.
#[test]
fn conflicting_certificates_in_one_slot_require_at_least_the_accountability_threshold() {
    let mut splits = 0u64;
    for total in 1..=160u128 {
        for faulty in 0..=total {
            assert_eq!(
                conflicting_split_exists(total, faulty),
                conflicting_certificates_possible(total, faulty),
                "total {total}, faulty {faulty}: the exhaustive split search and the closed form disagree"
            );
            splits += 1;
        }
    }
    let (pairs, safe) = threshold_obligations(4_000);
    println!(
        "lemma 2d single certificate: {splits} exhaustive honest splits over totals 1..=160, {pairs} total-and-faulty pairs over the sweep, {safe} below the threshold"
    );
}

/// Discharges the single-certificate threshold obligation over the sweep.
fn threshold_obligations(dense: u128) -> (u64, u64) {
    let mut pairs = 0u64;
    let mut safe = 0u64;
    let mut discharge = |total: u128, faulty: u128| {
        let share = threshold(total);
        assert_eq!(
            conflicting_certificates_possible(total, faulty),
            faulty >= share,
            "total {total}, faulty {faulty}: conflicting certificates diverged from the threshold {share}"
        );
        safe += u64::from(faulty < share);
        pairs += 1;
    };
    for total in 1..=dense {
        for faulty in 0..=total {
            discharge(total, faulty);
        }
    }
    for total in EXTREME_TOTALS {
        for faulty in bracket_faulty(total, threshold(total)) {
            discharge(total, faulty);
        }
    }
    (pairs, safe)
}

/// Lemma 2e (conformance, sampled). The aggregate certificate predicate agrees
/// with the real `PrevoteCertificate::from_votes` over authenticated committees at
/// many seat counts and many weight vectors, and the real
/// `AuthenticatedCommittee::quorum` agrees with `quorum_power` of the committee
/// total up to the production ceiling `MAX_COMMITTEE_MEMBERS`. This direction is
/// sampled, not enumerated: every subset is covered at the seat counts where the
/// power set is small, a deterministic selection of subsets above them, and
/// nothing else. Each call verifies real Ed25519 signatures, so the ordinary suite
/// keeps the call count small and the extended campaign widens it.
#[test]
fn aggregate_certificate_formation_conforms_to_the_production_certificate() {
    let report = conformance_obligations(&[1, 2, 3, 4], &[7, 16], 2, 16);
    println!("lemma 2e conformance: {report}");
}

/// Drives the production certificate over exhaustive and sampled seat subsets.
///
/// Returns a line naming the exact counts, so the reported numbers are the
/// observed ones at whatever bounds the caller chose.
fn conformance_obligations(
    exhaustive: &[usize],
    sampled: &[usize],
    shapes: u32,
    draws: usize,
) -> String {
    let mut subsets = 0u64;
    let mut accepted = 0u64;
    for (seats, dense) in exhaustive
        .iter()
        .map(|seats| (*seats, true))
        .chain(sampled.iter().map(|seats| (*seats, false)))
    {
        for shape in 0..shapes {
            let weights: Vec<u128> = (0..seats)
                .map(|index| conformance_weight(shape, index))
                .collect();
            let total: u128 = weights.iter().sum();
            let certifier = Certifier::new(&weights);
            for mask in subset_samples(seats, dense, draws) {
                let carried = certifier.carried(mask);
                let expected = mask != 0 && carried >= quorum_power(total);
                assert_eq!(
                    certifier.certifies(mask),
                    expected,
                    "{seats} seats, weights {weights:?}, subset {mask:#x} carrying {carried} of {total}: the production certificate disagreed with the aggregate predicate"
                );
                assert_eq!(
                    expected,
                    mask != 0 && mass(total, carried) == Mass::Quorum,
                    "{seats} seats, subset {mask:#x}: the weight class disagreed with the production certificate"
                );
                accepted += u64::from(expected);
                subsets += 1;
            }
        }
    }
    let mut committees = 0u64;
    for seats in [32usize, 48, 64, MAX_COMMITTEE_MEMBERS] {
        let weights: Vec<u128> = (0..seats)
            .map(|index| conformance_weight(2, index))
            .collect();
        let total: u128 = weights.iter().sum();
        let committee = authenticated(&weights);
        assert_eq!(
            committee.quorum(),
            quorum_power(total),
            "{seats} seats: the committee quorum diverged from quorum_power({total})"
        );
        assert_eq!(
            mass(total, committee.quorum()),
            Mass::Quorum,
            "{seats} seats: the quorum must classify as Quorum"
        );
        committees += 1;
    }
    format!(
        "{subsets} signed seat subsets over {} exhaustive and {} sampled seat counts and {shapes} weight shapes, {accepted} accepted by the production certificate; {committees} large committees up to {MAX_COMMITTEE_MEMBERS} seats agreed on the quorum",
        exhaustive.len(),
        sampled.len()
    )
}

/// Seat subsets offered to the production certificate at one seat count.
///
/// Every subset when the caller asks for the whole power set, and otherwise the
/// empty set, the full set, every single-seat and single-gap subset, and a
/// deterministic xorshift selection.
fn subset_samples(seats: usize, dense: bool, draws: usize) -> Vec<u64> {
    let masks = 1u64 << u64::try_from(seats).unwrap();
    if dense {
        return (0..masks).collect();
    }
    let mut out = vec![0, masks - 1];
    for seat in 0..u64::try_from(seats).unwrap() {
        out.push(1 << seat);
        out.push(masks - 1 - (1 << seat));
    }
    let mut state = 0x5eed_0000_0000_0001u64;
    for _ in 0..draws {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(state % masks);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Weight of one seat under one conformance shape: uniform, ascending, one
/// dominant seat, or a large near-`u128` weight.
fn conformance_weight(shape: u32, index: usize) -> u128 {
    let index = u128::try_from(index).unwrap();
    match shape {
        0 => 1,
        1 => index + 1,
        2 => {
            if index == 0 {
                9
            } else {
                1
            }
        }
        _ => (u128::MAX / 8192) - index,
    }
}

// Lemma 3: an inductive safety invariant with finite preservation obligations.

/// Round window and candidate-value count of one symbolic enumeration.
///
/// The window is a block of consecutive rounds starting at `base`. Every
/// obligation below is stated over offsets inside this window, which is what makes
/// each case space finite; Lemma 3e checks that the verdicts do not depend on
/// `base`, which is what makes the result independent of the round index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shape {
    /// First round of the window.
    base: u32,
    /// Consecutive rounds the window covers.
    rounds: u32,
    /// Candidate values the window covers.
    values: u32,
}

impl Shape {
    /// Bits one certificate plane needs.
    fn plane(self) -> u32 {
        self.rounds * self.values
    }

    /// Rounds in the window, lowest first.
    fn window(self) -> impl Iterator<Item = u32> {
        let base = self.base;
        (0..self.rounds).map(move |offset| base + offset)
    }

    /// Candidate values in the window.
    fn choices(self) -> std::ops::Range<u32> {
        0..self.values
    }

    /// Every round-and-value pair in the window, as a proof might name it.
    fn proofs(self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for round in self.window() {
            for value in self.choices() {
                out.push((round, value));
            }
        }
        out
    }
}

/// Authenticated certificates over one symbolic round window.
///
/// A round outside the window carries no certificate. That restriction is part of
/// the enumerated case space, not a claim about the protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Certs {
    /// Window this map covers.
    shape: Shape,
    /// Prevote-certificate bits, one per round and value.
    prevote: u32,
    /// Finality-certificate bits, one per round and value.
    precommit: u32,
}

impl Certs {
    /// Bit index of one round and value inside a plane.
    fn index(self, round: u32, value: u32) -> Option<u32> {
        let offset = round.checked_sub(self.shape.base)?;
        if offset >= self.shape.rounds || value >= self.shape.values {
            return None;
        }
        Some(offset * self.shape.values + value)
    }

    /// Whether an independently verifiable prevote certificate exists.
    fn prevoted(self, round: u32, value: u32) -> bool {
        self.index(round, value)
            .is_some_and(|bit| self.prevote >> bit & 1 == 1)
    }

    /// Whether an independently verifiable finality certificate exists.
    fn precommitted(self, round: u32, value: u32) -> bool {
        self.index(round, value)
            .is_some_and(|bit| self.precommit >> bit & 1 == 1)
    }

    /// Adds one prevote certificate inside the window.
    fn with_prevote(mut self, round: u32, value: u32) -> Self {
        self.prevote |= 1 << self.index(round, value).unwrap();
        self
    }

    /// Adds one finality certificate inside the window.
    fn with_precommit(mut self, round: u32, value: u32) -> Self {
        self.precommit |= 1 << self.index(round, value).unwrap();
        self
    }
}

/// Symbolic local state of one honest seat: exactly the fields `LocalBft` keeps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Local {
    /// Active round, `LocalBft::round`.
    round: u32,
    /// Local signing phase, `LocalBft::step`.
    step: VotingStep,
    /// Durable precommit lock as a round and value, `LocalBft::locked`.
    lock: Option<(u32, u32)>,
    /// Adopted decision, `LocalBft::finalized_block`.
    decided: Option<u32>,
}

/// One honest transition rule of `consensus::LocalBft`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rule {
    /// `LocalBft::propose` for one value, with an optional prevote certificate.
    Propose {
        /// Proposed candidate value.
        value: u32,
        /// Round and value of the attached certificate.
        proof: Option<(u32, u32)>,
    },
    /// `LocalBft::prevote` on an offered current-round proposal, or on none.
    Prevote {
        /// Offered candidate value, `None` when no proposal arrived.
        offered: Option<u32>,
        /// Round and value of the attached certificate.
        proof: Option<(u32, u32)>,
    },
    /// `LocalBft::timeout_proposal`.
    TimeoutProposal,
    /// `LocalBft::precommit` after a current-round prevote certificate.
    Precommit {
        /// Precommitted candidate value.
        value: u32,
    },
    /// `LocalBft::timeout_prevote`.
    TimeoutPrevote,
    /// `LocalBft::timeout_precommit`, the only round-advancing rule.
    TimeoutPrecommit,
    /// `LocalBft::finalize` on an independently verified finality certificate.
    Finalize {
        /// Decided candidate value.
        value: u32,
    },
}

/// Certificate slot one transition contributed weight to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Filled {
    /// Round of the slot.
    round: u32,
    /// Phase of the slot.
    phase: VotePhase,
    /// Non-nil value, or `None` for a nil vote, which can never certify.
    value: Option<u32>,
}

/// Outcome of one enabled honest transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Outcome {
    /// Local state after the transition.
    local: Local,
    /// Certificate slot the transition contributed weight to.
    filled: Option<Filled>,
}

/// Applies one rule, returning `None` when the transcribed guard rejects it.
///
/// Transcribed by hand from `crates/consensus/src/local.rs`: the proposer lock
/// rule, `Proposal::verify_valid_round`, the prevote lock rule, the precommit and
/// lock-setting rule, the three timeouts and the finality adoption. Where the
/// durable journal rejects a transition the voting rules themselves permit, such
/// as a second conflicting signature in one reserved slot, this transcription is
/// deliberately the more permissive of the two, so preservation is discharged over
/// a superset of the production transitions rather than a subset.
fn fire(local: Local, certs: Certs, rule: Rule) -> Option<Outcome> {
    match rule {
        Rule::Propose { value, proof } => fire_propose(local, certs, value, proof),
        Rule::Prevote { offered, proof } => fire_prevote(local, certs, offered, proof),
        Rule::TimeoutProposal => {
            if local.step != VotingStep::AwaitingProposal {
                return None;
            }
            Some(nil_vote(local, VotePhase::Prevote, VotingStep::Prevoted))
        }
        Rule::Precommit { value } => fire_precommit(local, certs, value),
        Rule::TimeoutPrevote => {
            if local.step != VotingStep::Prevoted {
                return None;
            }
            Some(nil_vote(
                local,
                VotePhase::Precommit,
                VotingStep::Precommitted,
            ))
        }
        Rule::TimeoutPrecommit => {
            if local.step != VotingStep::Precommitted {
                return None;
            }
            // The only round-advancing rule, and it uses checked addition.
            let next = local.round.checked_add(1)?;
            Some(Outcome {
                local: Local {
                    round: next,
                    step: VotingStep::AwaitingProposal,
                    ..local
                },
                filled: None,
            })
        }
        Rule::Finalize { value } => fire_finalize(local, certs, value),
    }
}

/// `LocalBft::propose` with the proposer lock rule and `verify_valid_round`.
fn fire_propose(
    local: Local,
    certs: Certs,
    value: u32,
    proof: Option<(u32, u32)>,
) -> Option<Outcome> {
    if local.step != VotingStep::AwaitingProposal {
        return None;
    }
    // `verify_valid_round`: the attached proof must name a strictly earlier round
    // and the proposed value, and the certificate it claims must really exist.
    if let Some((round, carried)) = proof
        && (round >= local.round || carried != value || !certs.prevoted(round, carried))
    {
        return None;
    }
    // The proposer lock rule: a locked proposer must not offer a conflicting value
    // without strictly newer evidence.
    if local
        .lock
        .is_some_and(|(held, on)| on != value && proof.is_none_or(|(round, _)| round <= held))
    {
        return None;
    }
    Some(Outcome {
        local,
        filled: None,
    })
}

/// `LocalBft::prevote` with the prevote lock rule; a forbidden value votes nil.
fn fire_prevote(
    local: Local,
    certs: Certs,
    offered: Option<u32>,
    proof: Option<(u32, u32)>,
) -> Option<Outcome> {
    if !matches!(
        local.step,
        VotingStep::AwaitingProposal | VotingStep::Prevoted
    ) {
        return None;
    }
    // A proof at or above the active round, or one that does not name the offered
    // value, is rejected outright rather than ignored.
    if let Some((round, carried)) = proof
        && (round >= local.round || offered != Some(carried) || !certs.prevoted(round, carried))
    {
        return None;
    }
    let permitted = local.lock.is_none_or(|(held, on)| {
        offered == Some(on) || proof.is_some_and(|(round, _)| round > held)
    });
    Some(Outcome {
        local: Local {
            step: VotingStep::Prevoted,
            ..local
        },
        filled: Some(Filled {
            round: local.round,
            phase: VotePhase::Prevote,
            value: offered.filter(|_| permitted),
        }),
    })
}

/// `LocalBft::precommit`, which is the only rule that sets a durable lock.
fn fire_precommit(local: Local, certs: Certs, value: u32) -> Option<Outcome> {
    if !matches!(local.step, VotingStep::Prevoted | VotingStep::Precommitted) {
        return None;
    }
    if !certs.prevoted(local.round, value) {
        return None;
    }
    Some(Outcome {
        local: Local {
            step: VotingStep::Precommitted,
            lock: Some((local.round, value)),
            ..local
        },
        filled: Some(Filled {
            round: local.round,
            phase: VotePhase::Precommit,
            value: Some(value),
        }),
    })
}

/// `LocalBft::finalize` on an independently verified finality certificate.
fn fire_finalize(local: Local, certs: Certs, value: u32) -> Option<Outcome> {
    if !certs
        .shape
        .window()
        .any(|round| certs.precommitted(round, value))
    {
        return None;
    }
    if local.decided.is_some_and(|other| other != value) {
        return None;
    }
    Some(Outcome {
        local: Local {
            step: VotingStep::Finalized,
            decided: Some(value),
            ..local
        },
        filled: None,
    })
}

/// Nil vote in the current round, which retains the durable lock.
fn nil_vote(local: Local, phase: VotePhase, step: VotingStep) -> Outcome {
    Outcome {
        local: Local { step, ..local },
        filled: Some(Filled {
            round: local.round,
            phase,
            value: None,
        }),
    }
}

/// Clause bit: a held lock is backed by a prevote certificate at its own round.
const CLAUSE_LOCK_CERTIFIED: u32 = 1;
/// Clause bit: the lock round never exceeds the active round.
const CLAUSE_LOCK_PLACED: u32 = 2;
/// Clause bit: at most one value is certified in any one slot.
const CLAUSE_ONE_VALUE: u32 = 4;
/// Clause bit: a finality certificate forbids every later conflicting prevote
/// certificate, which is the clause that implies agreement.
const CLAUSE_DECISION_LOCK: u32 = 8;
/// Clause bit: an adopted decision is backed by a finality certificate.
const CLAUSE_DECISION_CERTIFIED: u32 = 16;
/// Clause bit: a lock in the active round is held only after a precommit in that
/// round, because `LocalBft::precommit` is the only rule that sets a lock and it
/// also moves the step to `Precommitted`.
const CLAUSE_LOCK_PHASE: u32 = 32;
/// Every clause bit of the inductive safety invariant.
const ALL_CLAUSES: [u32; 6] = [
    CLAUSE_LOCK_CERTIFIED,
    CLAUSE_LOCK_PLACED,
    CLAUSE_ONE_VALUE,
    CLAUSE_DECISION_LOCK,
    CLAUSE_DECISION_CERTIFIED,
    CLAUSE_LOCK_PHASE,
];

/// Failed clauses of the inductive safety invariant, as a bitmask.
///
/// The invariant is the conjunction of six clauses: a held lock is backed by a
/// prevote certificate at its own round, the lock round never exceeds the active
/// round, a lock in the active round implies a precommit in it, at most one value
/// is certified per slot, a finality certificate forbids every later conflicting
/// prevote certificate, and an adopted decision is backed by a finality
/// certificate. The fourth and fifth clauses together imply agreement, which Lemma
/// 3b checks as an implication rather than restating.
fn violations(local: Local, certs: Certs) -> u32 {
    let mut failed = 0;
    if let Some((held, on)) = local.lock {
        if !certs.prevoted(held, on) {
            failed |= CLAUSE_LOCK_CERTIFIED;
        }
        if held > local.round {
            failed |= CLAUSE_LOCK_PLACED;
        }
        if held == local.round
            && matches!(
                local.step,
                VotingStep::AwaitingProposal | VotingStep::Prevoted
            )
        {
            failed |= CLAUSE_LOCK_PHASE;
        }
    }
    failed |= certificate_violations(certs);
    if local
        .decided
        .is_some_and(|value| !certs.shape.window().any(|r| certs.precommitted(r, value)))
    {
        failed |= CLAUSE_DECISION_CERTIFIED;
    }
    failed
}

/// Clauses of the invariant that read only the certificate map.
fn certificate_violations(certs: Certs) -> u32 {
    let mut failed = 0;
    for round in certs.shape.window() {
        for value in certs.shape.choices() {
            for other in certs.shape.choices().filter(|other| *other != value) {
                if certs.prevoted(round, value) && certs.prevoted(round, other) {
                    failed |= CLAUSE_ONE_VALUE;
                }
                if certs.precommitted(round, value) && certs.precommitted(round, other) {
                    failed |= CLAUSE_ONE_VALUE;
                }
            }
            if !certs.precommitted(round, value) {
                continue;
            }
            for later in certs.shape.window().filter(|later| *later >= round) {
                for other in certs.shape.choices().filter(|other| *other != value) {
                    if certs.prevoted(later, other) {
                        failed |= CLAUSE_DECISION_LOCK;
                    }
                }
            }
        }
    }
    failed
}

/// Every symbolic local state over one window.
fn all_locals(shape: Shape) -> Vec<Local> {
    let steps = [
        VotingStep::AwaitingProposal,
        VotingStep::Prevoted,
        VotingStep::Precommitted,
        VotingStep::Finalized,
    ];
    let mut locks: Vec<Option<(u32, u32)>> = vec![None];
    locks.extend(shape.proofs().into_iter().map(Some));
    let mut decided: Vec<Option<u32>> = vec![None];
    decided.extend(shape.choices().map(Some));
    let mut out = Vec::new();
    for round in shape.window() {
        for step in steps {
            for lock in &locks {
                for value in &decided {
                    out.push(Local {
                        round,
                        step,
                        lock: *lock,
                        decided: *value,
                    });
                }
            }
        }
    }
    out
}

/// Every certificate map over one window with at most one certified value per slot.
///
/// Built by mixed-radix counting over the `2 * rounds` slots rather than by
/// filtering the full power set, so the enumeration stays exact at larger windows.
fn legal_certs(shape: Shape) -> Vec<Certs> {
    let radix = u64::from(shape.values) + 1;
    let slots = 2 * shape.rounds;
    let mut out = Vec::new();
    for code in 0..radix.pow(slots) {
        let mut digits = code;
        let mut certs = Certs {
            shape,
            prevote: 0,
            precommit: 0,
        };
        for round in shape.window() {
            for phase in [VotePhase::Prevote, VotePhase::Precommit] {
                let digit = u32::try_from(digits % radix).unwrap();
                digits /= radix;
                if digit == 0 {
                    continue;
                }
                let value = digit - 1;
                certs = match phase {
                    VotePhase::Prevote => certs.with_prevote(round, value),
                    VotePhase::Precommit => certs.with_precommit(round, value),
                };
            }
        }
        out.push(certs);
    }
    out
}

/// Every rule instance over one window.
fn all_rules(shape: Shape) -> Vec<Rule> {
    let mut proofs: Vec<Option<(u32, u32)>> = vec![None];
    proofs.extend(shape.proofs().into_iter().map(Some));
    let mut out = vec![
        Rule::TimeoutProposal,
        Rule::TimeoutPrevote,
        Rule::TimeoutPrecommit,
    ];
    for value in shape.choices() {
        out.push(Rule::Precommit { value });
        out.push(Rule::Finalize { value });
        for proof in &proofs {
            out.push(Rule::Propose {
                value,
                proof: *proof,
            });
        }
    }
    let mut offers: Vec<Option<u32>> = vec![None];
    offers.extend(shape.choices().map(Some));
    for offered in offers {
        for proof in &proofs {
            out.push(Rule::Prevote {
                offered,
                proof: *proof,
            });
        }
    }
    out
}

/// Measured outcome of one preservation enumeration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Preservation {
    /// Configurations enumerated, before the invariant filter.
    configurations: u64,
    /// Pre-states that satisfy every clause of the invariant.
    states: u64,
    /// Enabled transitions discharged from those pre-states.
    obligations: u64,
    /// Obligations in which the transition also completed a certificate.
    completing: u64,
    /// Completing obligations excluded by the single-certificate weight lemma.
    deferred_one_value: u64,
    /// Completing obligations excluded by the crux lemma with quorum intersection.
    deferred_decision_lock: u64,
}

/// Discharges `invariant and guard implies invariant` over the whole case space.
///
/// The case space is the product of one honest local state, the certificate map
/// over the window, and the rule instance. Neither the seat count nor the absolute
/// round index appears in it, which is what makes the obligation finite.
fn preservation_obligations(shape: Shape) -> Preservation {
    let mut report = Preservation::default();
    let locals = all_locals(shape);
    let rules = all_rules(shape);
    let deferred = CLAUSE_ONE_VALUE | CLAUSE_DECISION_LOCK;
    for certs in legal_certs(shape) {
        for local in &locals {
            report.configurations += 1;
            if violations(*local, certs) != 0 {
                continue;
            }
            report.states += 1;
            for rule in &rules {
                let Some(outcome) = fire(*local, certs, *rule) else {
                    continue;
                };
                report.obligations += 1;
                assert_eq!(
                    violations(outcome.local, certs),
                    0,
                    "{rule:?} from {local:?} with {certs:?} broke the invariant without adding a certificate"
                );
                let Some(value) = outcome.filled.and_then(|filled| filled.value) else {
                    continue;
                };
                let filled = outcome.filled.unwrap();
                let next = match filled.phase {
                    VotePhase::Prevote => certs.with_prevote(filled.round, value),
                    VotePhase::Precommit => certs.with_precommit(filled.round, value),
                };
                report.completing += 1;
                let failed = violations(outcome.local, next);
                report.deferred_one_value += u64::from(failed & CLAUSE_ONE_VALUE != 0);
                report.deferred_decision_lock += u64::from(failed & CLAUSE_DECISION_LOCK != 0);
                assert_eq!(
                    failed & !deferred,
                    0,
                    "{rule:?} from {local:?} with {certs:?} broke clause {} once its vote completed a certificate",
                    failed & !deferred
                );
            }
        }
    }
    report
}

/// Unique temporary directory holding one protected journal.
struct Fixture(PathBuf);

impl Fixture {
    /// Creates a process-unique directory inside the system temporary directory.
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-unbounded-model-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    /// Journal path for one seat.
    fn path(&self, seat: usize) -> PathBuf {
        self.0.join(format!("seat-{seat}.bin"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        fs::remove_dir_all(path).unwrap();
    }
}

/// Lemma 3a (base case). The initial configuration satisfies every clause of the
/// invariant at every window base, and the real `LocalBft` resumed from a fresh
/// protected journal is exactly that configuration. The bounded model in
/// `formal_model.rs` checks properties only on newly inserted successors, so its
/// initial state is never property-checked; this obligation covers it explicitly.
#[test]
fn the_initial_configuration_satisfies_every_clause_of_the_safety_invariant() {
    let mut bases = 0u64;
    for base in [0u32, 1, 7, 1_000_000, u32::MAX - 3] {
        let shape = Shape {
            base,
            rounds: 3,
            values: 2,
        };
        let certs = Certs {
            shape,
            prevote: 0,
            precommit: 0,
        };
        let local = Local {
            round: base,
            step: VotingStep::AwaitingProposal,
            lock: None,
            decided: None,
        };
        assert_eq!(
            violations(local, certs),
            0,
            "base {base}: the initial configuration broke the invariant"
        );
        bases += 1;
    }
    let journals = Fixture::new();
    let context = SigningContext {
        chain_id: CHAIN,
        genesis: Hash256([8; 32]),
    };
    let weights = vec![1u128, 1, 1, 1];
    let signer = DurableSigner::create_protected(journals.path(0), context, seed(0)).unwrap();
    let voter = LocalBft::new(authenticated(&weights), signer, context.genesis).unwrap();
    assert_eq!(voter.round(), 0, "a fresh voter must start at round zero");
    assert_eq!(
        voter.step(),
        VotingStep::AwaitingProposal,
        "a fresh voter must await a proposal"
    );
    assert!(voter.locked().is_none(), "a fresh voter must hold no lock");
    assert!(
        voter.finalized_block().is_none(),
        "a fresh voter must hold no decision"
    );
    println!(
        "lemma 3a base case: {bases} window bases checked, production LocalBft initial state matched"
    );
}

/// Lemma 3b (the invariant implies agreement). Over every certificate map in the
/// window, if the single-value and decision-lock clauses hold then no two
/// different values carry a finality certificate, provided a finality certificate
/// at a round implies a prevote certificate for the same value at that round. That
/// implication is the weight fact that a precommit quorum contains honest weight
/// above the quorum complement, each unit of which precommitted only after a
/// current-round prevote certificate, so it is discharged by Lemma 1c and the
/// precommit rule rather than restated here.
#[test]
fn the_invariant_implies_agreement_over_every_certificate_map_in_the_window() {
    let mut maps = 0u64;
    let mut sound = 0u64;
    let mut decided = 0u64;
    for rounds in 2..=4u32 {
        let shape = Shape {
            base: 0,
            rounds,
            values: 3,
        };
        for certs in legal_certs(shape) {
            maps += 1;
            if certificate_violations(certs) != 0 {
                continue;
            }
            sound += 1;
            // A finality certificate implies a prevote certificate at its round.
            let supported = shape.window().all(|round| {
                shape
                    .choices()
                    .all(|value| !certs.precommitted(round, value) || certs.prevoted(round, value))
            });
            if !supported {
                continue;
            }
            let mut committed: Option<(u32, u32)> = None;
            for round in shape.window() {
                for value in shape.choices() {
                    if !certs.precommitted(round, value) {
                        continue;
                    }
                    if let Some((earlier, other)) = committed {
                        assert_eq!(
                            other, value,
                            "value {value} at round {round} and value {other} at round {earlier} both committed under the invariant"
                        );
                    }
                    committed = Some((round, value));
                }
            }
            decided += u64::from(committed.is_some());
        }
    }
    println!(
        "lemma 3b agreement: {maps} certificate maps over windows of 2 to 4 rounds and 3 values, {sound} satisfy the certificate clauses, {decided} carry a decision"
    );
}

/// Lemma 3c (preservation). For every honest rule, every local state, every
/// certificate map over the window and every proof the rule accepts, the invariant
/// is preserved. Two clauses of the successor are deferred by hypothesis: a vote
/// that completes a second certificate in one slot is excluded by Lemma 2d, and a
/// prevote certificate that conflicts with an existing decision is excluded by
/// Lemma 3d with Lemma 1c. Both exclusion counts are reported, so nothing is
/// silently skipped.
#[test]
fn every_transition_rule_preserves_the_safety_invariant_over_the_whole_case_space() {
    let shape = Shape {
        base: 0,
        rounds: 3,
        values: 2,
    };
    let report = preservation_obligations(shape);
    assert!(
        report.states > 0 && report.obligations > 0,
        "the case space must not be empty, saw {report:?}"
    );
    // The pre-state space is already restricted to certificate maps with at most
    // one certified value per slot, which is Lemma 2d, so that clause is vacuous
    // among pre-states by construction and is exercised only in the successor
    // branch. Every other clause must be violable, or it checks nothing.
    let mut exercised = 0usize;
    for clause in ALL_CLAUSES {
        if clause == CLAUSE_ONE_VALUE {
            assert!(
                report.deferred_one_value > 0,
                "the single-certificate clause was never exercised in a successor"
            );
            exercised += 1;
            continue;
        }
        let witnessed = legal_certs(shape).into_iter().any(|certs| {
            all_locals(shape)
                .into_iter()
                .any(|local| violations(local, certs) & clause != 0)
        });
        assert!(witnessed, "clause {clause} is vacuous over the case space");
        exercised += 1;
    }
    println!(
        "lemma 3c preservation: {} configurations, {} invariant pre-states, {} enabled transitions discharged, {} completed a certificate, {} deferred to lemma 2d, {} deferred to lemma 3d, {exercised} clauses non-vacuous",
        report.configurations,
        report.states,
        report.obligations,
        report.completing,
        report.deferred_one_value,
        report.deferred_decision_lock
    );
}

/// Lemma 3d (crux). Let an honest seat hold a durable lock on value `on` from
/// round `held`, and let `current > held` be its active round. If no prevote
/// certificate for any value other than `on` exists at any round strictly between
/// `held` and `current`, then the production prevote rule issues either nil or a
/// vote for `on`, for every offered proposal and every attached proof the rule
/// accepts. This is the step that, composed with the well-founded choice of the
/// least offending round, carries the decision lock across unboundedly many
/// rounds; the composition is prose, the case space here is enumerated.
#[test]
fn a_locked_seat_never_prevotes_a_conflicting_value_without_a_strictly_newer_certificate() {
    let mut obligations = 0u64;
    let mut hypothesis = 0u64;
    let mut nil = 0u64;
    for base in [0u32, 5, u32::MAX - 3] {
        let (seen, held, refused) = crux_obligations(Shape {
            base,
            rounds: 4,
            values: 2,
        });
        obligations += seen;
        hypothesis += held;
        nil += refused;
    }
    assert!(
        hypothesis > 0 && nil > 0,
        "the crux hypothesis must be satisfiable and must force nil votes, saw {hypothesis} and {nil}"
    );
    println!(
        "lemma 3d crux: {obligations} lock-and-round pairs over 3 window bases, {hypothesis} satisfy the hypothesis, {nil} forced nil or the locked value"
    );
}

/// Discharges the crux obligation over one window.
///
/// Returns the lock-and-round pairs enumerated, those satisfying the hypothesis,
/// and the cases in which the rule refused to vote for a conflicting value.
fn crux_obligations(shape: Shape) -> (u64, u64, u64) {
    let mut obligations = 0u64;
    let mut hypothesis = 0u64;
    let mut nil = 0u64;
    let mut proofs: Vec<Option<(u32, u32)>> = vec![None];
    proofs.extend(shape.proofs().into_iter().map(Some));
    let mut offers: Vec<Option<u32>> = vec![None];
    offers.extend(shape.choices().map(Some));
    for certs in legal_certs(shape) {
        for (held, on) in shape.proofs() {
            if !certs.prevoted(held, on) {
                continue;
            }
            for current in shape.window().filter(|current| *current > held) {
                obligations += 1;
                let clean = (held + 1..current).all(|between| {
                    shape
                        .choices()
                        .all(|other| other == on || !certs.prevoted(between, other))
                });
                if !clean {
                    continue;
                }
                hypothesis += 1;
                nil += crux_cases(shape, certs, (held, on), current, &offers, &proofs);
            }
        }
    }
    (obligations, hypothesis, nil)
}

/// Checks every offered proposal and proof for one crux case, returning the number
/// of cases in which the rule refused to vote for a conflicting value.
fn crux_cases(
    shape: Shape,
    certs: Certs,
    lock: (u32, u32),
    current: u32,
    offers: &[Option<u32>],
    proofs: &[Option<(u32, u32)>],
) -> u64 {
    let (held, on) = lock;
    let mut refused = 0u64;
    for step in [VotingStep::AwaitingProposal, VotingStep::Prevoted] {
        let local = Local {
            round: current,
            step,
            lock: Some(lock),
            decided: None,
        };
        for offered in offers {
            for proof in proofs {
                let Some(outcome) = fire_prevote(local, certs, *offered, *proof) else {
                    continue;
                };
                let cast = outcome.filled.and_then(|filled| filled.value);
                assert!(
                    cast.is_none_or(|value| value == on),
                    "locked on value {on} from round {held} at round {current}: the rule cast {cast:?} with offered {offered:?} and proof {proof:?} under window {shape:?}"
                );
                refused += u64::from(cast != *offered || offered.is_none());
            }
        }
    }
    refused
}

/// Byzantine-contributed message pool over one symbolic window.
///
/// Certificate planes are the facts a coalition can complete by signing, and the
/// proposal plane names the values it can offer while leading a round. Honest local
/// state is not part of the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pool {
    /// Window the pool covers.
    shape: Shape,
    /// Certificate facts available to the honest rules.
    certs: Certs,
    /// Proposal facts, one per round and value.
    proposal: u32,
}

impl Pool {
    /// Decodes one pool from a bitmask over the three planes.
    fn decode(shape: Shape, bits: u32) -> Self {
        let plane = shape.plane();
        Self {
            shape,
            certs: Certs {
                shape,
                prevote: bits & ((1 << plane) - 1),
                precommit: bits >> plane & ((1 << plane) - 1),
            },
            proposal: bits >> (2 * plane) & ((1 << plane) - 1),
        }
    }

    /// Whether a designated proposal for this round and value is available.
    fn proposed(self, round: u32, value: u32) -> bool {
        self.certs
            .index(round, value)
            .is_some_and(|bit| self.proposal >> bit & 1 == 1)
    }
}

/// Honest enabling conditions against one pool, as a bitmask of satisfied guards.
///
/// A non-nil prevote additionally requires the proposal to be present, because an
/// honest seat prevotes a value only against a designated proposal it received.
fn enabling(local: Local, pool: Pool, proofs: &[Option<(u32, u32)>]) -> u64 {
    let mut bits = 0u64;
    let mut next = 0u32;
    let mut set = |enabled: bool, next: &mut u32| {
        bits |= u64::from(enabled) << *next;
        *next += 1;
    };
    for value in pool.shape.choices() {
        set(
            fire_precommit(local, pool.certs, value).is_some(),
            &mut next,
        );
        set(fire_finalize(local, pool.certs, value).is_some(), &mut next);
        for proof in proofs {
            set(
                fire_propose(local, pool.certs, value, *proof).is_some()
                    && pool.proposed(local.round, value),
                &mut next,
            );
        }
        for proof in proofs {
            set(
                cast_prevote(local, pool, value, *proof) == Some(value),
                &mut next,
            );
        }
    }
    assert!(next <= 64, "the guard list must fit one u64, needed {next}");
    bits
}

/// Value an honest prevote carries against one pool, or `None` for nil.
fn cast_prevote(local: Local, pool: Pool, value: u32, proof: Option<(u32, u32)>) -> Option<u32> {
    if !pool.proposed(local.round, value) {
        return None;
    }
    fire_prevote(local, pool.certs, Some(value), proof)
        .and_then(|outcome| outcome.filled)
        .and_then(|filled| filled.value)
}

/// Whether an honest prevote in the current round would be nil against this pool.
///
/// Nil is the one honest outcome that is anti-monotone in the pool, so it is
/// classified separately instead of being folded into `enabling`.
fn nil_prevote(local: Local, pool: Pool, proofs: &[Option<(u32, u32)>]) -> bool {
    pool.shape.choices().all(|value| {
        proofs
            .iter()
            .all(|proof| cast_prevote(local, pool, value, *proof) != Some(value))
    })
}

/// Precomputed honest outcome for one pool and one representative local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Enabled {
    /// Bitmask of satisfied enabling conditions.
    guards: u64,
    /// Whether every honest prevote in the current round would be nil.
    nil: bool,
}

/// Local states the monotonicity obligation is evaluated on.
///
/// The pool lattice is the quantified dimension here, so the local dimension is a
/// representative set rather than the full product: every step, and the lock
/// absent, at the window base, and one round above it.
fn representative_locals(shape: Shape) -> Vec<Local> {
    let steps = [
        VotingStep::AwaitingProposal,
        VotingStep::Prevoted,
        VotingStep::Precommitted,
        VotingStep::Finalized,
    ];
    let mut out = Vec::new();
    for step in steps {
        for lock in [None, Some((shape.base, 0)), Some((shape.base, 1))] {
            for round in [shape.base, shape.base + shape.rounds - 1] {
                let local = Local {
                    round,
                    step,
                    lock,
                    decided: None,
                };
                if lock.is_some_and(|(held, _)| held == round)
                    && matches!(step, VotingStep::AwaitingProposal | VotingStep::Prevoted)
                {
                    continue;
                }
                out.push(local);
            }
        }
    }
    out
}

/// Precomputes the honest outcome for every pool and every representative local.
fn enabling_table(shape: Shape, locals: &[Local]) -> Vec<Enabled> {
    let planes = 3 * shape.plane();
    let mut proofs: Vec<Option<(u32, u32)>> = vec![None];
    proofs.extend(shape.proofs().into_iter().map(Some));
    let mut table = Vec::with_capacity((1usize << planes) * locals.len());
    for bits in 0..1u32 << planes {
        let pool = Pool::decode(shape, bits);
        for local in locals {
            table.push(Enabled {
                guards: enabling(*local, pool, &proofs),
                nil: nil_prevote(*local, pool, &proofs),
            });
        }
    }
    table
}

/// Lemma 3e (monotonicity). Every honest enabling condition that issues a non-nil
/// vote, sets a lock or adopts a decision is monotone in the Byzantine message
/// pool: adding a message never disables it. The subset lattice is generated by
/// single-message additions, so checking every one-message extension discharges
/// monotonicity over every superset, and the full subset-pair enumeration is run
/// as well. Folding the Byzantine weight into a constant maximal pool, as
/// `formal_model.rs` does in prose, is sound exactly for these guards. The
/// nil-vote outcome is anti-monotone and is reported as such, which is why the
/// bounded model can only claim the monotone over-approximation on its
/// asynchronous bounds, where every timeout is unconditionally enabled.
#[test]
fn honest_enabling_conditions_are_monotone_in_the_byzantine_message_pool() {
    let shape = Shape {
        base: 0,
        rounds: 2,
        values: 2,
    };
    let locals = representative_locals(shape);
    let table = enabling_table(shape, &locals);
    let (extensions, broken) = monotone_extensions(shape, &locals, &table);
    let pairs = monotone_subset_pairs(shape, &locals, &table);
    assert!(extensions > 0 && pairs > 0, "no pool pair was checked");
    assert!(
        broken > 0,
        "the nil outcome must be shown anti-monotone, not assumed"
    );
    println!(
        "lemma 3e monotonicity: {} representative local states over a {}-round {}-value pool lattice, {extensions} single-message extensions, {broken} of them turn a nil prevote non-nil, {pairs} full subset pairs",
        locals.len(),
        shape.rounds,
        shape.values
    );
}

/// Checks monotonicity over every single-message pool extension.
///
/// Returns the number of extensions checked and the number that turn a nil prevote
/// into a non-nil one, which is the anti-monotone direction.
fn monotone_extensions(shape: Shape, locals: &[Local], table: &[Enabled]) -> (u64, u64) {
    let planes = 3 * shape.plane();
    let mut extensions = 0u64;
    let mut broken = 0u64;
    for bits in 0..1u32 << planes {
        for added in 0..planes {
            if bits >> added & 1 == 1 {
                continue;
            }
            let upper = bits | 1 << added;
            for (slot, local) in locals.iter().enumerate() {
                let before = table[bits as usize * locals.len() + slot];
                let after = table[upper as usize * locals.len() + slot];
                assert_eq!(
                    before.guards & !after.guards,
                    0,
                    "{local:?}: adding message {added} to pool {bits:#x} disabled guards {:#x}",
                    before.guards & !after.guards
                );
                broken += u64::from(before.nil && !after.nil);
                extensions += 1;
            }
        }
    }
    (extensions, broken)
}

/// Checks monotonicity over every subset pair of the pool lattice.
fn monotone_subset_pairs(shape: Shape, locals: &[Local], table: &[Enabled]) -> u64 {
    let planes = 3 * shape.plane();
    let mut pairs = 0u64;
    for upper in 0..1u32 << planes {
        let mut lower = upper;
        loop {
            for (slot, local) in locals.iter().enumerate() {
                let below = table[lower as usize * locals.len() + slot];
                let above = table[upper as usize * locals.len() + slot];
                assert_eq!(
                    below.guards & !above.guards,
                    0,
                    "{local:?}: pool {lower:#x} inside {upper:#x} enabled guards {:#x} the larger pool does not",
                    below.guards & !above.guards
                );
                pairs += 1;
            }
            if lower == 0 {
                break;
            }
            lower = (lower - 1) & upper;
        }
    }
    pairs
}

/// Lemma 3f (round-index invariance). The preservation tallies are unchanged when
/// the whole round window is shifted by any offset that keeps the window below the
/// `u32` ceiling, because the rules compare rounds only by order and adjacency and
/// advance them only by one. The finite enumeration at one base therefore
/// discharges the obligation at every such round index. A window whose top round is
/// `u32::MAX` is the one exception, and it is checked separately: every tally except
/// the obligation count is identical, and the obligation count is strictly lower by
/// exactly the round advances `timeout_precommit` refuses at the ceiling, so the
/// exception removes transitions rather than adding any.
#[test]
fn the_preservation_case_space_and_its_verdicts_are_invariant_under_a_round_offset() {
    let mut reports = Vec::new();
    for base in [0u32, 1, 2, 9, 1_000_000, u32::MAX - 3] {
        let shape = Shape {
            base,
            rounds: 3,
            values: 2,
        };
        reports.push((base, preservation_obligations(shape)));
    }
    let (first, expected) = reports[0];
    for (base, report) in &reports[1..] {
        assert_eq!(
            *report, expected,
            "window base {base} produced {report:?} against {expected:?} at base {first}"
        );
    }
    let ceiling = preservation_obligations(Shape {
        base: u32::MAX - 2,
        rounds: 3,
        values: 2,
    });
    assert!(
        ceiling.obligations < expected.obligations,
        "a window ending at u32::MAX must lose the round advances it cannot take, saw {} against {}",
        ceiling.obligations,
        expected.obligations
    );
    assert_eq!(
        Preservation {
            obligations: expected.obligations,
            ..ceiling
        },
        expected,
        "a window ending at u32::MAX changed a tally other than the obligation count: {ceiling:?} against {expected:?}"
    );
    println!(
        "lemma 3f invariance: {} window bases below the ceiling produced identical tallies of {} obligations; a window ending at u32::MAX produced {}, losing {} refused round advances",
        reports.len(),
        expected.obligations,
        ceiling.obligations,
        expected.obligations - ceiling.obligations
    );
}

// Lemma 4: unbounded round liveness from round-robin fairness.

/// Designated seat index for one round, as `round_robin_proposer` computes it.
///
/// Transcribed from `authenticated.rs`: the committed seat order is walked by
/// `(height % count + round % count) % count`, so the leader advances by exactly
/// one seat per round and the weights play no part.
fn designated(height: u64, seats: u64, round: u32) -> u64 {
    (height % seats + u64::from(round) % seats) % seats
}

/// Longest run of faulty seats in the cyclic seat order of one placement.
///
/// Because the leader advances by one seat per round, this is exactly the longest
/// stretch of consecutive rounds that a faulty seat can lead.
fn longest_faulty_run(seats: u32, faulty: &impl Fn(u32) -> bool) -> u32 {
    if (0..seats).all(faulty) {
        return seats;
    }
    let mut longest = 0;
    let mut current = 0;
    for seat in 0..2 * seats {
        if faulty(seat % seats) {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest.min(seats)
}

/// Rounds until an honest seat leads, counting from `base`.
fn honest_leader_delay(
    height: u64,
    seats: u32,
    faulty: &impl Fn(u32) -> bool,
    base: u32,
) -> Option<u32> {
    (0..seats).find(|offset| {
        let round = base + offset;
        let seat = designated(height, u64::from(seats), round);
        !faulty(u32::try_from(seat).unwrap())
    })
}

/// Placement predicate reading one seat out of a bitmask.
fn placed(mask: u64) -> impl Fn(u32) -> bool {
    move |seat: u32| mask >> u64::from(seat) & 1 == 1
}

/// Placement predicate for one contiguous block of faulty seats.
fn contiguous(span: u32) -> impl Fn(u32) -> bool {
    move |seat: u32| seat < span
}

/// Lemma 4a (round-robin fairness). Over any window of `seats` consecutive rounds
/// the designated seat takes every seat index exactly once, at every height, at
/// every seat count and at every window base that fits in `u32`. The transcribed
/// designation is checked against the production
/// `AuthenticatedCommittee::round_robin_proposer` at every seat count a committee
/// can be built for here, including the production ceiling.
#[test]
fn every_seat_leads_exactly_once_in_every_window_of_seat_count_consecutive_rounds() {
    let mut windows = 0u64;
    for seats in 1..=64u32 {
        for height in [0u64, 1, 2, HEIGHT, 1_000_003, u64::MAX - 1, u64::MAX] {
            for base in [0u32, 1, 2, 97, 1_000_000, u32::MAX - seats + 1] {
                let mut seen = vec![false; seats as usize];
                for offset in 0..seats {
                    let seat = designated(height, u64::from(seats), base + offset);
                    let slot = usize::try_from(seat).unwrap();
                    assert!(
                        !seen[slot],
                        "{seats} seats at height {height} base {base}: seat {seat} led twice inside one window"
                    );
                    seen[slot] = true;
                }
                assert!(
                    seen.iter().all(|led| *led),
                    "{seats} seats at height {height} base {base}: some seat never led"
                );
                windows += 1;
            }
        }
    }
    let mut checked = 0u64;
    for seats in [1usize, 2, 3, 4, 7, 16, 64, MAX_COMMITTEE_MEMBERS] {
        let weights: Vec<u128> = (0..seats)
            .map(|index| conformance_weight(1, index))
            .collect();
        let committee = authenticated(&weights);
        let order: Vec<ValidatorId> = (0..seats).map(identity).collect();
        for round in production_rounds(seats) {
            let expected =
                order[usize::try_from(designated(HEIGHT, u64::try_from(seats).unwrap(), round))
                    .unwrap()];
            assert_eq!(
                committee.round_robin_proposer(round),
                expected,
                "{seats} seats at round {round}: the production designation diverged from the transcription"
            );
            checked += 1;
        }
    }
    println!(
        "lemma 4a fairness: {windows} windows over seat counts 1..=64, 7 heights and 6 bases; {checked} production designations agreed up to {MAX_COMMITTEE_MEMBERS} seats"
    );
}

/// Rounds offered to the production designation at one seat count.
fn production_rounds(seats: usize) -> Vec<u32> {
    let span = u32::try_from(seats).unwrap();
    let mut out: Vec<u32> = (0..span.min(256)).collect();
    for base in [1_000_000u32, u32::MAX - span + 1] {
        out.extend((0..span.min(64)).map(|offset| base + offset));
    }
    out.push(u32::MAX);
    out.sort_unstable();
    out.dedup();
    out
}

/// Lemma 4b (leader latency). For every Byzantine seat placement that leaves at
/// least one honest seat, an honest seat leads within `seats` consecutive rounds,
/// and the exact worst case is one more than the longest cyclic run of faulty
/// seats. Every placement is enumerated at the seat counts where the power set is
/// small, and the adversarial placements that maximise consecutive faulty
/// leaders — one contiguous block of the largest size the safety precondition
/// allows — are checked up to the production ceiling.
#[test]
fn an_honest_seat_leads_within_the_longest_faulty_run_plus_one_for_every_placement() {
    let mut placements = 0u64;
    let mut worst = 0u32;
    for seats in 1..=14u32 {
        for mask in 0..1u64 << seats {
            let faulty = placed(mask);
            let run = longest_faulty_run(seats, &faulty);
            if run == seats {
                assert!(
                    honest_leader_delay(HEIGHT, seats, &faulty, 0).is_none(),
                    "{seats} seats, placement {mask:#x}: an honest leader appeared with no honest seat"
                );
                placements += 1;
                continue;
            }
            let mut observed = 0;
            for base in 0..seats {
                let delay =
                    honest_leader_delay(HEIGHT, seats, &faulty, base).unwrap_or_else(|| {
                        panic!("{seats} seats, placement {mask:#x}, base {base}: no honest leader")
                    });
                assert!(
                    delay < seats,
                    "{seats} seats, placement {mask:#x}, base {base}: delay {delay} reached the seat count"
                );
                observed = observed.max(delay);
            }
            assert_eq!(
                observed, run,
                "{seats} seats, placement {mask:#x}: worst delay {observed} against the longest faulty run {run}"
            );
            worst = worst.max(observed);
            placements += 1;
        }
    }
    let mut blocks = 0u64;
    let ceiling = u32::try_from(MAX_COMMITTEE_MEMBERS).unwrap();
    for seats in [16u32, 32, 64, 128, 1024, ceiling] {
        // The largest contiguous block the safety precondition admits over uniform
        // unit weights: one less than the accountability threshold. A contiguous
        // block is the placement that maximises consecutive faulty leaders.
        let span = u32::try_from(threshold(u128::from(seats))).unwrap() - 1;
        let faulty = contiguous(span);
        let run = longest_faulty_run(seats, &faulty);
        assert_eq!(
            run, span,
            "{seats} seats, contiguous block of {span}: the run was {run}"
        );
        for base in (0..seats).chain(std::iter::once(u32::MAX - seats + 1)) {
            let delay = honest_leader_delay(HEIGHT, seats, &faulty, base).unwrap_or_else(|| {
                panic!("{seats} seats, contiguous block of {span}, base {base}: no honest leader")
            });
            assert!(
                delay <= run,
                "{seats} seats, contiguous block of {span}, base {base}: delay {delay} above the run {run}"
            );
        }
        blocks += 1;
    }
    println!(
        "lemma 4b latency: {placements} Byzantine placements over seat counts 1..=14, worst honest-leader delay {worst}; {blocks} maximal contiguous placements up to {MAX_COMMITTEE_MEMBERS} seats checked at every base and at the u32 ceiling"
    );
}

/// Lemma 4c (leader progress). An honest designated leader always has a legal
/// proposal: proposing the value it is locked on needs no evidence, and an
/// unlocked leader may propose anything. The proposer lock rule therefore never
/// blocks an honest leader, at any lock round, any certificate configuration and
/// any round index.
#[test]
fn an_honest_leader_always_has_a_legal_proposal_under_the_proposer_lock_rule() {
    let mut cases = 0u64;
    let mut with_lock = 0u64;
    for base in [0u32, 3, u32::MAX - 3] {
        let shape = Shape {
            base,
            rounds: 3,
            values: 3,
        };
        let proofs = shape.proofs();
        let mut locks: Vec<Option<(u32, u32)>> = vec![None];
        locks.extend(proofs.iter().copied().map(Some));
        for certs in legal_certs(shape) {
            for lock in &locks {
                for round in shape.window() {
                    let local = Local {
                        round,
                        step: VotingStep::AwaitingProposal,
                        lock: *lock,
                        decided: None,
                    };
                    if violations(local, certs) != 0 {
                        continue;
                    }
                    let legal = shape.choices().any(|value| {
                        fire_propose(local, certs, value, None).is_some()
                            || proofs.iter().any(|proof| {
                                fire_propose(local, certs, value, Some(*proof)).is_some()
                            })
                    });
                    assert!(
                        legal,
                        "an honest leader at round {round} with lock {lock:?} and {certs:?} had no legal proposal"
                    );
                    with_lock += u64::from(lock.is_some());
                    cases += 1;
                }
            }
        }
    }
    println!(
        "lemma 4c leader progress: {cases} leader configurations over 3 window bases, {with_lock} of them holding a durable lock"
    );
}

/// Lemma 4d (prevote acceptance). Under the eventual-synchrony delivery
/// hypothesis, a leader that reproposes the highest-round prevote certificate in
/// the window is prevoted by every honest seat whose state satisfies the
/// invariant. The hypothesis is that the leader knows the highest certificate any
/// honest seat holds; it is a delivery assumption and is not established here. The
/// enumeration discharges the rest: because a lock is backed by a certificate at
/// its own round and at most one value is certified per slot, the reproposed round
/// is at or above every honest lock round, and the prevote lock rule permits the
/// value in both the equal and the strictly greater case.
#[test]
fn eventual_synchrony_prevotes_the_reproposed_highest_certificate_in_every_lock_case() {
    let mut cases = 0u64;
    let mut equal_round = 0u64;
    for base in [0u32, u32::MAX - 3] {
        let shape = Shape {
            base,
            rounds: 3,
            values: 3,
        };
        let (seen, equal) = acceptance_obligations(shape);
        cases += seen;
        equal_round += equal;
    }
    assert!(
        equal_round > 0,
        "the case where the lock round equals the reproposed round must occur"
    );
    println!(
        "lemma 4d prevote acceptance: {cases} honest seats accepted the reproposed highest certificate over 2 window bases, {equal_round} with a lock exactly at the reproposed round"
    );
}

/// Discharges the prevote-acceptance obligation over one window.
fn acceptance_obligations(shape: Shape) -> (u64, u64) {
    let mut cases = 0u64;
    let mut equal_round = 0u64;
    let mut locks: Vec<Option<(u32, u32)>> = vec![None];
    locks.extend(shape.proofs().into_iter().map(Some));
    for certs in legal_certs(shape) {
        for round in shape.window() {
            let Some((proof_round, proof_value)) = highest_certificate(shape, certs, round) else {
                continue;
            };
            for lock in &locks {
                for step in [VotingStep::AwaitingProposal, VotingStep::Prevoted] {
                    let local = Local {
                        round,
                        step,
                        lock: *lock,
                        decided: None,
                    };
                    if violations(local, certs) != 0 {
                        continue;
                    }
                    let outcome = fire_prevote(
                        local,
                        certs,
                        Some(proof_value),
                        Some((proof_round, proof_value)),
                    )
                    .unwrap_or_else(|| {
                        panic!(
                            "the reproposal of value {proof_value} from round {proof_round} was rejected at round {round} with lock {lock:?}"
                        )
                    });
                    let cast = outcome.filled.and_then(|filled| filled.value);
                    assert_eq!(
                        cast,
                        Some(proof_value),
                        "round {round}, lock {lock:?}, reproposal of value {proof_value} from round {proof_round}: the honest seat cast {cast:?}"
                    );
                    equal_round += u64::from(lock.is_some_and(|(held, _)| held == proof_round));
                    cases += 1;
                }
            }
        }
    }
    (cases, equal_round)
}

/// Highest-round prevote certificate strictly below `round` in the window.
fn highest_certificate(shape: Shape, certs: Certs, round: u32) -> Option<(u32, u32)> {
    shape
        .window()
        .filter(|earlier| *earlier < round)
        .collect::<Vec<u32>>()
        .into_iter()
        .rev()
        .find_map(|earlier| {
            shape
                .choices()
                .find(|value| certs.prevoted(earlier, *value))
                .map(|value| (earlier, value))
        })
}

/// Lemma 4e (liveness precondition). A certificate can form from honest weight
/// alone exactly when the Byzantine weight is at most the quorum complement
/// `total - quorum`, which is strictly stronger than the safety precondition
/// `faulty < 2 * quorum - total`. The gap is the `Blocking` weight class, which is
/// nonempty exactly when `total % 3 != 1`: at such a total there are Byzantine
/// weights that cannot break safety and can still deny liveness forever. The
/// precondition is required, not assumed away.
#[test]
fn liveness_requires_the_strictly_stronger_honest_quorum_precondition() {
    let mut pairs = 0u64;
    let mut gap_totals = 0u64;
    let mut widest = 0u128;
    for total in arithmetic_totals(4_000) {
        let quorum = quorum_power(total);
        let outside = complement(total);
        let share = threshold(total);
        assert!(
            outside < share,
            "total {total}: the liveness precondition {outside} is not stronger than the safety precondition {share}"
        );
        let gap = share - outside - 1;
        assert_eq!(
            gap > 0,
            total % 3 != 1,
            "total {total}: the safe-but-not-live band is nonempty iff the total is not 1 mod 3"
        );
        // The band is `3 * quorum - 2 * total - 1` wide, which the residue class
        // fixes at two, zero or one unit, so it never grows with the total.
        assert_eq!(
            gap,
            match total % 3 {
                0 => 2,
                1 => 0,
                _ => 1,
            },
            "total {total}: the safe-but-not-live band {gap} diverged from its residue class"
        );
        gap_totals += u64::from(gap > 0);
        widest = widest.max(gap);
        for faulty in bracket_faulty(total, share) {
            assert_eq!(
                total - faulty >= quorum,
                faulty <= outside,
                "total {total}, faulty {faulty}: honest weight reaching the quorum diverged from the precondition"
            );
            assert_eq!(
                mass(total, faulty) <= Mass::Minor,
                faulty <= outside,
                "total {total}, faulty {faulty}: the weight class diverged from the liveness precondition"
            );
            pairs += 1;
        }
    }
    println!(
        "lemma 4e precondition: {pairs} total-and-faulty pairs, {gap_totals} totals with a nonempty safe-but-not-live band, widest band {widest}"
    );
}

/// Lemma 4f (round ceiling). `timeout_precommit` is the only rule that changes the
/// active round, it advances by exactly one, and it fails at `u32::MAX` because it
/// uses checked addition. The unbounded liveness claim therefore holds from any
/// round `base` with `base + seats - 1 <= u32::MAX` and no further; the ceiling is
/// exercised against the real `LocalBft` resumed from a protected journal already
/// positioned at `u32::MAX`.
#[test]
fn the_round_advance_is_the_only_round_changing_rule_and_stops_at_the_u32_ceiling() {
    let mut advances = 0u64;
    let mut steady = 0u64;
    for base in [0u32, 1, 1_000_000, u32::MAX - 2, u32::MAX - 1] {
        let shape = Shape {
            base,
            rounds: 2,
            values: 2,
        };
        for certs in legal_certs(shape) {
            for local in all_locals(shape) {
                for rule in all_rules(shape) {
                    let Some(outcome) = fire(local, certs, rule) else {
                        continue;
                    };
                    if matches!(rule, Rule::TimeoutPrecommit) {
                        assert_eq!(
                            outcome.local.round,
                            local.round + 1,
                            "the round advance must move by exactly one from {local:?}"
                        );
                        advances += 1;
                    } else {
                        assert_eq!(
                            outcome.local.round, local.round,
                            "{rule:?} changed the round from {local:?}"
                        );
                        steady += 1;
                    }
                }
            }
        }
    }
    let ceiling = Local {
        round: u32::MAX,
        step: VotingStep::Precommitted,
        lock: None,
        decided: None,
    };
    let shape = Shape {
        base: u32::MAX,
        rounds: 1,
        values: 1,
    };
    assert!(
        fire(
            ceiling,
            Certs {
                shape,
                prevote: 0,
                precommit: 0
            },
            Rule::TimeoutPrecommit
        )
        .is_none(),
        "the transcribed round advance must fail at the u32 ceiling"
    );
    let (round, refused) = production_round_ceiling();
    assert_eq!(round, u32::MAX, "the resumed voter must sit at the ceiling");
    assert!(
        refused,
        "the production round advance must refuse at the u32 ceiling"
    );
    println!(
        "lemma 4f ceiling: {advances} round advances and {steady} round-preserving transitions over 5 window bases; the production voter refused to advance past round {round}"
    );
}

/// Resumes a real voter from a journal already positioned at the last round and
/// returns its round together with whether the production advance refused.
fn production_round_ceiling() -> (u32, bool) {
    let journals = Fixture::new();
    let context = SigningContext {
        chain_id: CHAIN,
        genesis: Hash256([8; 32]),
    };
    let weights = vec![1u128, 1, 1, 1];
    let committee = authenticated(&weights);
    let root = committee.root();
    let mut signer = DurableSigner::create_protected(journals.path(0), context, seed(0)).unwrap();
    let handle = signer.key_handle();
    // Reserve the last precommit slot of this height directly, which is the state
    // a voter would hold after advancing through every round.
    signer
        .sign_protected(
            &handle,
            SigningPosition {
                height: HEIGHT,
                round: u32::MAX,
                phase: keystore::PRECOMMIT_PHASE,
            },
            Hash256([0x5A; 32]),
            SigningSafety {
                committee_root: root,
                locked: None,
            },
        )
        .unwrap();
    let mut voter = LocalBft::new(committee, signer, context.genesis).unwrap();
    let round = voter.round();
    let refused = voter.timeout_precommit(round).is_err();
    (round, refused)
}

/// Extended campaign: the same obligations at larger windows, denser sweeps and
/// wider conformance sampling. Reported counts come from this run, not from the
/// ordinary suite.
#[test]
#[ignore = "wider enumeration of the same finite obligations; run with --release --ignored. Enumerated obligations, never a mechanized proof"]
fn extended_unbounded_obligation_campaign() {
    let started = std::time::Instant::now();
    campaign_weight_obligations();
    campaign_invariant_obligations();
    campaign_liveness_obligations();
    println!("campaign elapsed {:?}", started.elapsed());
}

/// Wider weight-lemma obligations for the extended campaign.
fn campaign_weight_obligations() {
    let (obligations, realized) = simulation_obligations(96);
    println!(
        "campaign lemma 2b: {obligations} aggregate transitions over totals 1..=96, {realized} abstract triples realized"
    );
    let (pairs, safe) = threshold_obligations(40_000);
    println!("campaign lemma 2d: {pairs} total-and-faulty pairs, {safe} below the threshold");
    println!(
        "campaign lemma 2e: {}",
        conformance_obligations(&[1, 2, 3, 4, 5, 7, 11], &[16, 24, 32], 4, 48)
    );
}

/// Wider invariant obligations for the extended campaign.
fn campaign_invariant_obligations() {
    for shape in [
        Shape {
            base: 0,
            rounds: 4,
            values: 2,
        },
        Shape {
            base: 0,
            rounds: 3,
            values: 3,
        },
        Shape {
            base: u32::MAX - 3,
            rounds: 4,
            values: 2,
        },
    ] {
        let report = preservation_obligations(shape);
        println!(
            "campaign lemma 3c at base {} rounds {} values {}: {} configurations, {} pre-states, {} obligations, {} completing, {} deferred to lemma 2d, {} deferred to lemma 3d",
            shape.base,
            shape.rounds,
            shape.values,
            report.configurations,
            report.states,
            report.obligations,
            report.completing,
            report.deferred_one_value,
            report.deferred_decision_lock
        );
    }
    for shape in [
        Shape {
            base: 0,
            rounds: 5,
            values: 2,
        },
        Shape {
            base: 0,
            rounds: 4,
            values: 3,
        },
    ] {
        let (obligations, hypothesis, nil) = crux_obligations(shape);
        println!(
            "campaign lemma 3d at rounds {} values {}: {obligations} lock-and-round pairs, {hypothesis} satisfy the hypothesis, {nil} forced nil or the locked value",
            shape.rounds, shape.values
        );
    }
    let wide = Shape {
        base: 0,
        rounds: 3,
        values: 2,
    };
    let locals = representative_locals(wide);
    let table = enabling_table(wide, &locals);
    let (extensions, broken) = monotone_extensions(wide, &locals, &table);
    let pairs = monotone_subset_pairs(wide, &locals, &table);
    println!(
        "campaign lemma 3e: {} representative local states over a {}-round {}-value pool lattice, {extensions} single-message extensions, {broken} turn a nil prevote non-nil, {pairs} full subset pairs",
        locals.len(),
        wide.rounds,
        wide.values
    );
}

/// Wider liveness obligations for the extended campaign.
fn campaign_liveness_obligations() {
    for shape in [
        Shape {
            base: 0,
            rounds: 4,
            values: 3,
        },
        Shape {
            base: u32::MAX - 4,
            rounds: 5,
            values: 2,
        },
    ] {
        let (cases, equal) = acceptance_obligations(shape);
        println!(
            "campaign lemma 4d at base {} rounds {} values {}: {cases} honest seats accepted the reproposal, {equal} with a lock exactly at the reproposed round",
            shape.base, shape.rounds, shape.values
        );
    }
    let mut placements = 0u64;
    for seats in 15..=18u32 {
        for mask in 0..1u64 << seats {
            let faulty = placed(mask);
            let run = longest_faulty_run(seats, &faulty);
            if run == seats {
                continue;
            }
            for base in 0..seats {
                let delay = honest_leader_delay(HEIGHT, seats, &faulty, base).unwrap();
                assert!(
                    delay <= run,
                    "{seats} seats, placement {mask:#x}, base {base}: delay {delay} above the run {run}"
                );
            }
            placements += 1;
        }
    }
    println!(
        "campaign lemma 4b: {placements} Byzantine placements over seat counts 15..=18, all within the longest faulty run"
    );
}
