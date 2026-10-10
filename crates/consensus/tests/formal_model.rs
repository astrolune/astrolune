// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded exhaustive model checking of the fixed-height `BFT` voting rules.
//!
//! Property class: agreement, lock safety, weighted accountability, bounded-round
//! decision reachability and proposer validity over every honest interleaving
//! inside explicit validator, round and candidate-value bounds. Quorum arithmetic
//! and proposer designation come from the real `consensus` functions, and the
//! modelled transition relation is conformance-tested against the real
//! `consensus::LocalBft` with protected `keystore::DurableSigner` journals. This
//! is bounded exploration, never a proof; the stated bounds and the open items are
//! recorded in `docs/55-formal-consensus-model.md`.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, Committee, CommitteeMember, FinalityCertificate,
    FinalityEngine, LocalBft, PotbWeight, PrevoteCertificate, Proposal, Vote, VotePhase,
    VotingStep, quorum_power,
};
use keystore::{DurableSigner, SigningContext, SigningLock};
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

/// Chain identifier shared by the model and every conformance fixture.
const CHAIN: u32 = 7;
/// Fixed trusted height; `round_robin_proposer` mixes it with the round.
const HEIGHT: u64 = 42;
/// Largest committee the encoded state supports.
const MAX_VALIDATORS: usize = 5;
/// Largest round bound the encoded state supports.
const MAX_ROUNDS: usize = 4;
/// Largest candidate-value bound the encoded state supports.
const MAX_VALUES: usize = 3;

/// Prevote slot index inside one encoded validator round.
const PREVOTE: usize = 0;
/// Precommit slot index inside one encoded validator round.
const PRECOMMIT: usize = 1;
/// Encoded slot holding no durable vote.
const UNVOTED: u8 = 0;
/// Encoded slot holding a nil vote.
const NIL: u8 = 1;
/// Encoded step before a prevote is durably reserved.
const AWAITING: u8 = 0;
/// Encoded step after a prevote is durably reserved.
const PREVOTED: u8 = 1;
/// Encoded step after a precommit is durably reserved.
const PRECOMMITTED: u8 = 2;
/// First encoded finalized step; the decided value is the offset above it.
const FINALIZED: u8 = 3;

/// Delivery assumption applied to honest validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Regime {
    /// Arbitrary loss, delay, reordering and duplication. Every timeout is always
    /// enabled, and a designated proposer may issue any value its lock permits or
    /// stay silent for the whole round.
    Asynchronous,
    /// No loss inside the bound: every honest message for a round is received
    /// before that round's timers expire, so a timeout only fires once nothing
    /// else is available, and a designated proposer reproposes the highest-round
    /// prevote certificate exactly as `node::network::receive_valid_value` keeps it.
    EventualSynchrony,
}

/// Byzantine contribution to the vote tallies and to the proposal set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Adversary {
    /// Every Byzantine validator votes for every candidate value in every slot and
    /// leads its own rounds by proposing every value in every evidence form. Honest
    /// enabling conditions are monotone in the message pool, so this single maximal
    /// pool over-approximates every concrete Byzantine strategy.
    MaximalEquivocation,
    /// Byzantine validators send nothing, which is the omission-failure worst case.
    Silent,
}

/// One explicit exploration bound.
#[derive(Clone, Copy)]
struct Bound {
    /// Short identifier printed with the measured counts.
    name: &'static str,
    /// Committee seats; seat order fixes `round_robin_proposer`.
    validators: usize,
    /// Trusted voting power per seat; unused seats hold zero.
    weights: [u128; MAX_VALIDATORS],
    /// Seats controlled by the adversary.
    byzantine: [bool; MAX_VALIDATORS],
    /// Candidate block values available to proposers.
    values: usize,
    /// Round bound; rounds `0..rounds` are explored.
    rounds: usize,
    /// Delivery assumption.
    regime: Regime,
    /// Adversary strategy.
    adversary: Adversary,
}

/// Durable precommit lock: the round whose prevote quorum justified it and its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lock {
    /// Round of the justifying prevote quorum.
    round: usize,
    /// Locked candidate value.
    value: usize,
}

/// Reachable global state: honest local state plus the durable message pool.
///
/// Byzantine messages are a constant of the bound, so they are not encoded here.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct State {
    /// `votes[validator][round][PREVOTE | PRECOMMIT]`, encoded by `value_slot`.
    votes: [[[u8; 2]; MAX_ROUNDS]; MAX_VALIDATORS],
    /// `proposals[round][value]`: bit 0 is a fresh proposal, bit `1 + r` is a
    /// reproposal claiming valid round `r`.
    proposals: [[u8; MAX_VALUES]; MAX_ROUNDS],
    /// Active round per validator.
    round: [u8; MAX_VALIDATORS],
    /// Encoded local step per validator.
    step: [u8; MAX_VALIDATORS],
    /// Encoded durable lock per validator, `0` when unlocked.
    locked: [u8; MAX_VALIDATORS],
}

/// One modelled honest transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    /// The designated proposer signs a value, optionally with earlier-round evidence.
    Propose {
        /// Acting validator.
        validator: usize,
        /// Proposed candidate value.
        value: usize,
        /// Round of the attached prevote certificate.
        valid_round: Option<usize>,
    },
    /// A non-nil prevote for a proposed value the lock permits.
    Prevote {
        /// Acting validator.
        validator: usize,
        /// Prevoted candidate value.
        value: usize,
    },
    /// A nil prevote on a matching proposal timeout.
    TimeoutProposal {
        /// Acting validator.
        validator: usize,
    },
    /// A precommit and lock after a current-round prevote quorum.
    Precommit {
        /// Acting validator.
        validator: usize,
        /// Precommitted candidate value.
        value: usize,
    },
    /// A nil precommit on a matching prevote timeout, retaining the lock.
    TimeoutPrevote {
        /// Acting validator.
        validator: usize,
    },
    /// A round advance on a matching precommit timeout, retaining the lock.
    TimeoutPrecommit {
        /// Acting validator.
        validator: usize,
    },
    /// Adoption of an independently verified finality certificate.
    Finalize {
        /// Acting validator.
        validator: usize,
        /// Decided candidate value.
        value: usize,
    },
}

/// Decodes an occupied vote slot into its candidate value index.
fn slot_value(slot: u8) -> Option<usize> {
    if slot < 2 {
        return None;
    }
    Some(usize::from(slot) - 2)
}

/// Encodes a candidate value index as an occupied vote slot.
fn value_slot(value: usize) -> u8 {
    u8::try_from(value + 2).unwrap()
}

/// Decodes a durable lock, or `None` when the validator is unlocked.
fn decode_lock(code: u8) -> Option<Lock> {
    let code = usize::from(code).checked_sub(1)?;
    Some(Lock {
        round: code / MAX_VALUES,
        value: code % MAX_VALUES,
    })
}

/// Encodes a durable lock.
fn encode_lock(held: Lock) -> u8 {
    u8::try_from(1 + held.round * MAX_VALUES + held.value).unwrap()
}

/// Proposal-set bit for a fresh value.
const fn fresh_form() -> u8 {
    1
}

/// Proposal-set bit for a reproposal claiming `valid_round`.
fn repropose_form(valid_round: usize) -> u8 {
    1 << u8::try_from(valid_round + 1).unwrap()
}

/// Deterministic committee seed for one seat.
fn seed(index: usize) -> u8 {
    u8::try_from(index).unwrap() + 1
}

/// Registered public key for one seat.
fn public(index: usize) -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&[seed(index); 32])
}

/// Committee identity for one seat.
fn identity(index: usize) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&public(index)).0)
}

/// Builds the real authenticated committee for one bound.
fn authenticated(bound: &Bound) -> AuthenticatedCommittee {
    let members = (0..bound.validators)
        .map(|index| CommitteeMember {
            id: identity(index),
            power: PotbWeight(bound.weights[index]),
        })
        .collect();
    let keys: Vec<_> = (0..bound.validators).map(public).collect();
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

/// Bound with the real quorum, equivocating weight and proposer designation resolved.
struct Model {
    /// Exploration bound.
    bound: Bound,
    /// Checked total voting power.
    total: u128,
    /// Strict two-thirds quorum from `AuthenticatedCommittee::quorum`.
    quorum: u128,
    /// Total weight the adversary may equivocate with.
    equivocating: u128,
    /// Designated proposer seat per round, from `round_robin_proposer`.
    proposer: [usize; MAX_ROUNDS],
}

impl Model {
    /// Resolves every derived quantity from the real consensus functions.
    fn new(bound: Bound) -> Self {
        assert!(bound.validators <= MAX_VALIDATORS, "validator bound");
        assert!(bound.rounds <= MAX_ROUNDS, "round bound");
        assert!(bound.values <= MAX_VALUES, "value bound");
        let committee = authenticated(&bound);
        let total: u128 = bound.weights[..bound.validators].iter().sum();
        assert_eq!(
            committee.quorum(),
            quorum_power(total),
            "{}: committee quorum diverged from quorum_power({total})",
            bound.name
        );
        let mut proposer = [0; MAX_ROUNDS];
        for (round, seat) in proposer.iter_mut().enumerate().take(bound.rounds) {
            let designated = committee.round_robin_proposer(u32::try_from(round).unwrap());
            *seat = (0..bound.validators)
                .find(|index| identity(*index) == designated)
                .unwrap();
        }
        let equivocating = match bound.adversary {
            Adversary::MaximalEquivocation => (0..bound.validators)
                .filter(|index| bound.byzantine[*index])
                .map(|index| bound.weights[index])
                .sum(),
            Adversary::Silent => 0,
        };
        Self {
            bound,
            total,
            quorum: committee.quorum(),
            equivocating,
            proposer,
        }
    }

    /// Initial state, with the constant maximal Byzantine proposal set pre-applied.
    fn initial(&self) -> State {
        let mut state = State {
            votes: [[[UNVOTED; 2]; MAX_ROUNDS]; MAX_VALIDATORS],
            proposals: [[0; MAX_VALUES]; MAX_ROUNDS],
            round: [0; MAX_VALIDATORS],
            step: [AWAITING; MAX_VALIDATORS],
            locked: [0; MAX_VALIDATORS],
        };
        if self.bound.adversary != Adversary::MaximalEquivocation {
            return state;
        }
        for round in 0..self.bound.rounds {
            if !self.bound.byzantine[self.proposer[round]] {
                continue;
            }
            let mut mask = fresh_form();
            for earlier in 0..round {
                mask |= repropose_form(earlier);
            }
            for value in 0..self.bound.values {
                state.proposals[round][value] = mask;
            }
        }
        state
    }

    /// Authenticated weight supporting one value in one slot of one round.
    fn slot_power(&self, state: &State, round: usize, slot: usize, value: usize) -> u128 {
        let honest: u128 = (0..self.bound.validators)
            .filter(|index| {
                !self.bound.byzantine[*index]
                    && state.votes[*index][round][slot] == value_slot(value)
            })
            .map(|index| self.bound.weights[index])
            .sum();
        honest + self.equivocating
    }

    /// Whether an independently verifiable prevote certificate exists.
    fn prevote_quorum(&self, state: &State, round: usize, value: usize) -> bool {
        self.slot_power(state, round, PREVOTE, value) >= self.quorum
    }

    /// Whether an independently verifiable finality certificate exists.
    fn precommit_quorum(&self, state: &State, round: usize, value: usize) -> bool {
        self.slot_power(state, round, PRECOMMIT, value) >= self.quorum
    }

    /// Every round and value carrying a finality certificate.
    fn decisions(&self, state: &State) -> Vec<(usize, usize)> {
        let mut found = Vec::new();
        for round in 0..self.bound.rounds {
            for value in 0..self.bound.values {
                if self.precommit_quorum(state, round, value) {
                    found.push((round, value));
                }
            }
        }
        found
    }

    /// No designated proposal has been signed for this round yet.
    fn proposal_absent(&self, state: &State, round: usize) -> bool {
        (0..self.bound.values).all(|value| state.proposals[round][value] == 0)
    }

    /// Proposal form that authorizes a non-nil prevote, or `None` for a nil prevote.
    ///
    /// A reproposal is usable only when the claimed earlier-round prevote quorum
    /// really exists, because `verify_valid_round` requires the certificate itself.
    ///
    /// The three cases are distinct and all reachable: `None` means no justified
    /// prevote exists, `Some(None)` means a fresh proposal justifies it, and
    /// `Some(Some(round))` names the reproposed valid round. The inner option is
    /// exactly the shape `LocalBft::prevote_proposal` takes for its proof.
    #[allow(clippy::option_option)]
    fn justifying_form(
        &self,
        state: &State,
        validator: usize,
        value: usize,
    ) -> Option<Option<usize>> {
        let round = usize::from(state.round[validator]);
        let mask = state.proposals[round][value];
        let held = decode_lock(state.locked[validator]);
        if mask & fresh_form() != 0 && held.is_none_or(|lock| lock.value == value) {
            return Some(None);
        }
        for valid_round in 0..round {
            if mask & repropose_form(valid_round) == 0
                || !self.prevote_quorum(state, valid_round, value)
            {
                continue;
            }
            if held.is_none_or(|lock| lock.value == value || valid_round > lock.round) {
                return Some(Some(valid_round));
            }
        }
        None
    }

    /// Highest-round prevote certificate a designated proposer may repropose.
    fn highest_certificate(
        &self,
        state: &State,
        round: usize,
        held: Option<Lock>,
    ) -> Option<(usize, usize)> {
        for valid_round in (0..round).rev() {
            let mut chosen = None;
            for value in 0..self.bound.values {
                if !self.prevote_quorum(state, valid_round, value) {
                    continue;
                }
                let permitted =
                    held.is_none_or(|lock| lock.value == value || valid_round > lock.round);
                if permitted && (chosen.is_none() || held.is_some_and(|lock| lock.value == value)) {
                    chosen = Some(value);
                }
            }
            if let Some(value) = chosen {
                return Some((valid_round, value));
            }
        }
        None
    }
}

/// Enabled honest transitions.
impl Model {
    /// Every enabled transition in a deterministic order.
    fn actions(&self, state: &State) -> Vec<Action> {
        let mut out = Vec::new();
        for validator in 0..self.bound.validators {
            if self.bound.byzantine[validator] || state.step[validator] >= FINALIZED {
                continue;
            }
            for value in 0..self.bound.values {
                if (0..self.bound.rounds).any(|round| self.precommit_quorum(state, round, value)) {
                    out.push(Action::Finalize { validator, value });
                }
            }
            match state.step[validator] {
                AWAITING => self.awaiting_actions(state, validator, &mut out),
                PREVOTED => self.prevoted_actions(state, validator, &mut out),
                _ => self.precommitted_actions(state, validator, &mut out),
            }
        }
        out
    }

    /// Transitions available before a prevote is reserved.
    fn awaiting_actions(&self, state: &State, validator: usize, out: &mut Vec<Action>) {
        let round = usize::from(state.round[validator]);
        if self.proposer[round] == validator && self.proposal_absent(state, round) {
            let before = out.len();
            self.propose_actions(state, validator, round, out);
            // Under eventual synchrony the designated proposer acts before voting,
            // matching `NetworkNode::propose_if_designated`.
            if out.len() > before && self.bound.regime == Regime::EventualSynchrony {
                return;
            }
        }
        for value in 0..self.bound.values {
            if self.justifying_form(state, validator, value).is_some() {
                out.push(Action::Prevote { validator, value });
            }
        }
        if self.may_timeout_proposal(state, validator) {
            out.push(Action::TimeoutProposal { validator });
        }
    }

    /// Proposal transitions permitted by the proposer lock rule.
    fn propose_actions(
        &self,
        state: &State,
        validator: usize,
        round: usize,
        out: &mut Vec<Action>,
    ) {
        let held = decode_lock(state.locked[validator]);
        if self.bound.regime == Regime::EventualSynchrony {
            if let Some((valid_round, value)) = self.highest_certificate(state, round, held) {
                out.push(Action::Propose {
                    validator,
                    value,
                    valid_round: Some(valid_round),
                });
                return;
            }
            for value in 0..self.bound.values {
                out.push(Action::Propose {
                    validator,
                    value,
                    valid_round: None,
                });
            }
            return;
        }
        for value in 0..self.bound.values {
            if held.is_none_or(|lock| lock.value == value) {
                out.push(Action::Propose {
                    validator,
                    value,
                    valid_round: None,
                });
            }
            for valid_round in 0..round {
                if !self.prevote_quorum(state, valid_round, value) {
                    continue;
                }
                if held.is_none_or(|lock| lock.value == value || valid_round > lock.round) {
                    out.push(Action::Propose {
                        validator,
                        value,
                        valid_round: Some(valid_round),
                    });
                }
            }
        }
    }

    /// Transitions available after a prevote is reserved.
    fn prevoted_actions(&self, state: &State, validator: usize, out: &mut Vec<Action>) {
        let round = usize::from(state.round[validator]);
        for value in 0..self.bound.values {
            if state.proposals[round][value] != 0 && self.prevote_quorum(state, round, value) {
                out.push(Action::Precommit { validator, value });
            }
        }
        if self.may_timeout_prevote(state, round) {
            out.push(Action::TimeoutPrevote { validator });
        }
    }

    /// Transitions available after a precommit is reserved.
    fn precommitted_actions(&self, state: &State, validator: usize, out: &mut Vec<Action>) {
        let round = usize::from(state.round[validator]);
        if round + 1 < self.bound.rounds && self.may_timeout_precommit(state, round) {
            out.push(Action::TimeoutPrecommit { validator });
        }
    }

    /// A proposal timeout fires freely under asynchrony, and only when the
    /// designated proposer cannot still act and no proposed value is permitted
    /// under eventual synchrony.
    fn may_timeout_proposal(&self, state: &State, validator: usize) -> bool {
        if self.bound.regime == Regime::Asynchronous {
            return true;
        }
        let round = usize::from(state.round[validator]);
        if self.leader_pending(state, round) {
            return false;
        }
        (0..self.bound.values).all(|value| self.justifying_form(state, validator, value).is_none())
    }

    /// An honest designated proposer that can still sign this round's proposal.
    fn leader_pending(&self, state: &State, round: usize) -> bool {
        let leader = self.proposer[round];
        !self.bound.byzantine[leader]
            && state.step[leader] < FINALIZED
            && usize::from(state.round[leader]) <= round
            && self.proposal_absent(state, round)
    }

    /// A prevote timeout fires only once every honest prevote for the round has
    /// arrived and no prevote certificate exists.
    fn may_timeout_prevote(&self, state: &State, round: usize) -> bool {
        if self.bound.regime == Regime::Asynchronous {
            return true;
        }
        !self.slot_pending(state, round, PREVOTE)
            && (0..self.bound.values).all(|value| !self.prevote_quorum(state, round, value))
    }

    /// A precommit timeout fires only once every honest precommit for the round
    /// has arrived and no finality certificate exists.
    fn may_timeout_precommit(&self, state: &State, round: usize) -> bool {
        if self.bound.regime == Regime::Asynchronous {
            return true;
        }
        !self.slot_pending(state, round, PRECOMMIT)
            && (0..self.bound.values).all(|value| !self.precommit_quorum(state, round, value))
    }

    /// Some honest validator can still fill this slot of this round.
    fn slot_pending(&self, state: &State, round: usize, slot: usize) -> bool {
        (0..self.bound.validators).any(|validator| {
            !self.bound.byzantine[validator]
                && state.step[validator] < FINALIZED
                && usize::from(state.round[validator]) <= round
                && state.votes[validator][round][slot] == UNVOTED
        })
    }

    /// Successor state of one enabled transition.
    ///
    /// The successor depends only on the action, because `actions` already decided
    /// enablement against the bound. Kept as a method for symmetry with `actions`
    /// and `check` so a caller never mixes the two call forms.
    #[allow(clippy::unused_self)]
    fn apply(&self, state: &State, action: Action) -> State {
        let mut next = *state;
        match action {
            Action::Propose {
                validator,
                value,
                valid_round,
            } => {
                let round = usize::from(state.round[validator]);
                next.proposals[round][value] |= valid_round.map_or_else(fresh_form, repropose_form);
            }
            Action::Prevote { validator, value } => {
                let round = usize::from(state.round[validator]);
                next.votes[validator][round][PREVOTE] = value_slot(value);
                next.step[validator] = PREVOTED;
            }
            Action::TimeoutProposal { validator } => {
                let round = usize::from(state.round[validator]);
                next.votes[validator][round][PREVOTE] = NIL;
                next.step[validator] = PREVOTED;
            }
            Action::Precommit { validator, value } => {
                let round = usize::from(state.round[validator]);
                next.votes[validator][round][PRECOMMIT] = value_slot(value);
                next.locked[validator] = encode_lock(Lock { round, value });
                next.step[validator] = PRECOMMITTED;
            }
            Action::TimeoutPrevote { validator } => {
                let round = usize::from(state.round[validator]);
                next.votes[validator][round][PRECOMMIT] = NIL;
                next.step[validator] = PRECOMMITTED;
            }
            Action::TimeoutPrecommit { validator } => {
                next.round[validator] = state.round[validator] + 1;
                next.step[validator] = AWAITING;
            }
            Action::Finalize { validator, value } => {
                next.step[validator] = FINALIZED + u8::try_from(value).unwrap();
            }
        }
        next
    }
}

/// Named state properties.
impl Model {
    /// First violated property in `properties`, if any.
    fn check(&self, state: &State, properties: &[Property]) -> Option<String> {
        properties.iter().find_map(|property| match property {
            Property::Agreement => self.agreement(state),
            Property::LockSafety => self.lock_safety(state),
            Property::QuorumLockSafety => self.quorum_lock_safety(state),
            Property::Validity => self.validity(state),
        })
    }

    /// Agreement: no two distinct values are ever committed at this height.
    fn agreement(&self, state: &State) -> Option<String> {
        let decisions = self.decisions(state);
        for first in &decisions {
            for second in &decisions {
                if first.1 != second.1 {
                    return Some(format!(
                        "agreement: finality certificates for value {} at round {} and value {} at round {}",
                        first.1, first.0, second.1, second.0
                    ));
                }
            }
        }
        let mut decided: Option<usize> = None;
        for validator in 0..self.bound.validators {
            if state.step[validator] < FINALIZED {
                continue;
            }
            let value = usize::from(state.step[validator] - FINALIZED);
            if let Some(other) = decided.filter(|other| *other != value) {
                return Some(format!(
                    "agreement: validator {validator} finalized value {value} against value {other}"
                ));
            }
            decided = Some(value);
        }
        None
    }

    /// Lock safety: the durable lock is exactly the last non-nil precommit, and no
    /// honest validator prevotes a conflicting value without strictly newer evidence.
    fn lock_safety(&self, state: &State) -> Option<String> {
        for validator in 0..self.bound.validators {
            if self.bound.byzantine[validator] {
                continue;
            }
            let derived = self
                .last_precommit(state, validator, self.bound.rounds)
                .map_or(0, encode_lock);
            if derived != state.locked[validator] {
                return Some(format!(
                    "lock safety: validator {validator} holds encoded lock {} against recorded precommits {derived}",
                    state.locked[validator]
                ));
            }
            if let Some(message) = self.prevote_lock_rule(state, validator) {
                return Some(message);
            }
        }
        None
    }

    /// Prevote lock rule re-derived from the recorded votes of one validator.
    fn prevote_lock_rule(&self, state: &State, validator: usize) -> Option<String> {
        for round in 0..self.bound.rounds {
            let Some(value) = slot_value(state.votes[validator][round][PREVOTE]) else {
                continue;
            };
            if state.proposals[round][value] == 0 {
                return Some(format!(
                    "validity: validator {validator} prevoted value {value} at round {round} with no designated proposal"
                ));
            }
            let Some(held) = self.last_precommit(state, validator, round) else {
                continue;
            };
            if held.value == value {
                continue;
            }
            if !(held.round + 1..round).any(|proof| self.prevote_quorum(state, proof, value)) {
                return Some(format!(
                    "lock safety: validator {validator} prevoted value {value} at round {round} while locked on value {} from round {}",
                    held.value, held.round
                ));
            }
        }
        None
    }

    /// Last non-nil precommit strictly below `round`, which is the lock it implies.
    fn last_precommit(&self, state: &State, validator: usize, round: usize) -> Option<Lock> {
        let _ = self;
        (0..round).rev().find_map(|earlier| {
            slot_value(state.votes[validator][earlier][PRECOMMIT]).map(|value| Lock {
                round: earlier,
                value,
            })
        })
    }

    /// Quorum lock safety: a finality certificate is never followed by a conflicting
    /// prevote certificate, which generalizes the hand-written restart test.
    fn quorum_lock_safety(&self, state: &State) -> Option<String> {
        for (round, value) in self.decisions(state) {
            for later in round..self.bound.rounds {
                for other in 0..self.bound.values {
                    if other == value || !self.prevote_quorum(state, later, other) {
                        continue;
                    }
                    return Some(format!(
                        "quorum lock safety: finality certificate for value {value} at round {round} followed by a prevote certificate for value {other} at round {later}"
                    ));
                }
            }
        }
        None
    }

    /// Validity: a committed value was proposed by that round's designated proposer.
    fn validity(&self, state: &State) -> Option<String> {
        for (round, value) in self.decisions(state) {
            if state.proposals[round][value] == 0 {
                return Some(format!(
                    "validity: value {value} committed at round {round} without a proposal from designated seat {}",
                    self.proposer[round]
                ));
            }
        }
        None
    }
}

/// Named state property classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Property {
    /// No two distinct values are ever committed at this height.
    Agreement,
    /// The durable lock survives nil votes and round advances, and no honest
    /// validator prevotes a conflicting value without strictly newer evidence.
    LockSafety,
    /// A finality certificate is never followed by a conflicting prevote certificate.
    QuorumLockSafety,
    /// Every committed value was proposed by that round's designated proposer.
    Validity,
}

/// Every property class, in evaluation order.
const ALL_PROPERTIES: [Property; 4] = [
    Property::Agreement,
    Property::LockSafety,
    Property::QuorumLockSafety,
    Property::Validity,
];

/// Measured outcome of one bounded exploration.
struct Report {
    /// Distinct reachable states visited.
    states: usize,
    /// Transition applications attempted, including repeats into visited states.
    transitions: usize,
    /// Reachable states with no enabled transition.
    terminal: usize,
    /// Highest round carrying a finality certificate anywhere in the explored space.
    decision_round: Option<usize>,
    /// First terminal state reached with no finality certificate.
    undecided: Option<Vec<Action>>,
    /// First violated property with the trace that reaches it.
    violation: Option<(String, Vec<Action>)>,
}

/// Action sequence leading to the state on top of the search stack.
fn trace(frames: &[(State, Vec<Action>, usize)]) -> Vec<Action> {
    frames
        .iter()
        .filter_map(|frame| frame.2.checked_sub(1).map(|index| frame.1[index]))
        .collect()
}

/// Human-readable counterexample trace.
fn describe(trace: &[Action]) -> String {
    let mut text = String::new();
    for (step, action) in trace.iter().enumerate() {
        writeln!(text, "    {step}: {action:?}").unwrap();
    }
    text
}

/// Exhaustive depth-first exploration of every reachable state inside the bound.
///
/// Stops at the first violation of `properties` so the search stack is the
/// counterexample trace. Reachability is traversal independent, so the reported
/// state, transition and terminal counts are exact for a bound that holds.
fn explore(model: &Model, properties: &[Property]) -> Report {
    let initial = model.initial();
    let mut visited = HashSet::new();
    visited.insert(initial);
    let mut report = Report {
        states: 1,
        transitions: 0,
        terminal: 0,
        decision_round: None,
        undecided: None,
        violation: None,
    };
    let mut frames = vec![(initial, model.actions(&initial), 0usize)];
    while !frames.is_empty() {
        let top = frames.len() - 1;
        if frames[top].2 >= frames[top].1.len() {
            frames.pop();
            continue;
        }
        let action = frames[top].1[frames[top].2];
        frames[top].2 += 1;
        let state = model.apply(&frames[top].0, action);
        report.transitions += 1;
        if !visited.insert(state) {
            continue;
        }
        report.states += 1;
        if let Some(name) = model.check(&state, properties) {
            report.violation = Some((name, trace(&frames)));
            break;
        }
        let decisions = model.decisions(&state);
        for (round, _) in &decisions {
            report.decision_round = Some(
                report
                    .decision_round
                    .map_or(*round, |best| best.max(*round)),
            );
        }
        let actions = model.actions(&state);
        if actions.is_empty() {
            report.terminal += 1;
            if decisions.is_empty() && report.undecided.is_none() {
                report.undecided = Some(trace(&frames));
            }
        }
        frames.push((state, actions, 0));
    }
    report
}

/// Panics with the counterexample trace when a property is violated.
fn assert_holds(model: &Model, report: &Report) {
    if let Some((property, path)) = &report.violation {
        panic!(
            "{}: {property}\n  counterexample trace ({} transitions):\n{}",
            model.bound.name,
            path.len(),
            describe(path)
        );
    }
}

/// Prints the measured counts so the bound and the result stay reproducible.
fn record(model: &Model, report: &Report, elapsed: std::time::Duration) {
    println!(
        "{}: {} validators, {} values, {} rounds, {:?}/{:?}, quorum {} of {}, equivocating {} -> {} states, {} transitions, {} terminal, decision round {:?}, {:?}",
        model.bound.name,
        model.bound.validators,
        model.bound.values,
        model.bound.rounds,
        model.bound.regime,
        model.bound.adversary,
        model.quorum,
        model.total,
        model.equivocating,
        report.states,
        report.transitions,
        report.terminal,
        report.decision_round,
        elapsed
    );
}

/// Deterministic walk selection over the enabled transitions of a state.
struct Random(u64);
impl Random {
    /// Xorshift choice inside `limit`, matching the existing simulation fixtures.
    fn choose(&mut self, limit: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(limit).unwrap()).unwrap()
    }
}

/// Unique temporary directory holding one protected journal per honest validator.
struct Fixture(PathBuf);
impl Fixture {
    /// Creates a process-unique directory inside the system temporary directory.
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-formal-model-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    /// Journal path for one seat.
    fn path(&self, validator: usize) -> PathBuf {
        self.0.join(format!("validator-{validator}.bin"))
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

/// Real `LocalBft` instances and real signed evidence for one modelled walk.
///
/// Honest seats run the production API over protected journals. Byzantine seats
/// have no local state at all: their proposals and votes are signed directly with
/// the seat key, which is exactly the authority a Byzantine operator holds.
struct Harness<'a> {
    /// Bound under test.
    model: &'a Model,
    /// Shared signing namespace.
    context: SigningContext,
    /// Independent verification context for certificates.
    committee: AuthenticatedCommittee,
    /// Committee commitment used by headers, votes and proposals.
    root: Hash256,
    /// Production voters, `None` for Byzantine seats.
    locals: Vec<Option<LocalBft>>,
    /// Real prevotes keyed by seat and round.
    prevotes: BTreeMap<(usize, usize), Vote>,
    /// Real precommits keyed by seat and round.
    precommits: BTreeMap<(usize, usize), Vote>,
    /// Signed proposals keyed by round, value and evidence form.
    proposals: BTreeMap<(usize, usize, Option<usize>), Proposal>,
    /// Journals for this walk; dropped with the harness.
    #[allow(dead_code)] // Held only so its Drop removes the walk's journal directory.
    journals: Fixture,
}

impl<'a> Harness<'a> {
    /// Creates fresh protected journals and resumes every honest voter from them.
    fn new(model: &'a Model) -> Self {
        let journals = Fixture::new();
        let context = SigningContext {
            chain_id: CHAIN,
            genesis: Hash256([8; 32]),
        };
        let committee = authenticated(&model.bound);
        let root = committee.root();
        let mut locals = Vec::new();
        for validator in 0..model.bound.validators {
            if model.bound.byzantine[validator] {
                locals.push(None);
                continue;
            }
            let signer = DurableSigner::create_protected(
                journals.path(validator),
                context,
                [seed(validator); 32],
            )
            .unwrap();
            locals.push(Some(
                LocalBft::new(authenticated(&model.bound), signer, context.genesis).unwrap(),
            ));
        }
        Self {
            model,
            context,
            committee,
            root,
            locals,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            proposals: BTreeMap::new(),
            journals,
        }
    }

    /// Canonical header for one candidate value.
    fn header(&self, value: usize) -> BlockHeader {
        BlockHeader {
            height: HEIGHT,
            parent: Hash256([1; 32]),
            transactions_root: Hash256([2; 32]),
            state_root: Hash256([0xA0 + u8::try_from(value).unwrap(); 32]),
            receipts_root: Hash256([4; 32]),
            committee_root: self.root,
            capacity: Resources::ZERO,
        }
    }

    /// Mutable production voter for one honest seat.
    fn local(&mut self, validator: usize) -> &mut LocalBft {
        self.locals[validator].as_mut().unwrap()
    }

    /// Byzantine vote signed directly with the seat key.
    fn forged(&self, validator: usize, round: usize, phase: VotePhase, value: usize) -> Vote {
        let mut vote = Vote {
            chain_id: CHAIN,
            height: HEIGHT,
            committee_root: self.root,
            round: u32::try_from(round).unwrap(),
            phase,
            block: Some(self.header(value).compute_hash()),
            voter: identity(validator),
            signature: [0; 64],
        };
        vote.signature =
            crypto::blake2s::ed25519_sign(&[seed(validator); 32], &vote.signing_hash().0);
        vote
    }

    /// Independently verified prevote certificate the model claims exists.
    fn certificate(&self, round: usize, value: usize) -> PrevoteCertificate {
        let target = self.header(value).compute_hash();
        let mut votes: Vec<Vote> = self
            .prevotes
            .iter()
            .filter(|((_, slot), vote)| *slot == round && vote.block == Some(target))
            .map(|(_, vote)| vote.clone())
            .collect();
        if self.model.bound.adversary == Adversary::MaximalEquivocation {
            for validator in 0..self.model.bound.validators {
                if self.model.bound.byzantine[validator] {
                    votes.push(self.forged(validator, round, VotePhase::Prevote, value));
                }
            }
        }
        votes.sort_by_key(|vote| vote.voter);
        PrevoteCertificate::from_votes(&self.committee, votes).unwrap()
    }

    /// Independently verified finality certificate the model claims exists.
    fn finality(&self, round: usize, value: usize) -> FinalityCertificate {
        let target = self.header(value).compute_hash();
        let mut engine = BftFinalityEngine::for_round(
            authenticated(&self.model.bound),
            u32::try_from(round).unwrap(),
        );
        let mut votes: Vec<Vote> = self
            .precommits
            .iter()
            .filter(|((_, slot), vote)| *slot == round && vote.block == Some(target))
            .map(|(_, vote)| vote.clone())
            .collect();
        if self.model.bound.adversary == Adversary::MaximalEquivocation {
            for validator in 0..self.model.bound.validators {
                if self.model.bound.byzantine[validator] {
                    votes.push(self.forged(validator, round, VotePhase::Precommit, value));
                }
            }
        }
        votes.sort_by_key(|vote| vote.voter);
        for vote in votes {
            if engine.certificate().is_some() {
                break;
            }
            engine.receive_vote(vote).unwrap();
        }
        engine.certificate().unwrap().clone()
    }

    /// Signed proposal for one round, value and evidence form, forging Byzantine ones.
    fn proposal(&mut self, round: usize, value: usize, form: Option<usize>) -> Proposal {
        if let Some(found) = self.proposals.get(&(round, value, form)) {
            return found.clone();
        }
        let leader = self.model.proposer[round];
        assert!(
            self.model.bound.byzantine[leader],
            "no honest proposal recorded for round {round} value {value} form {form:?}"
        );
        let mut proposal = Proposal {
            chain_id: CHAIN,
            genesis: self.context.genesis,
            height: HEIGHT,
            round: u32::try_from(round).unwrap(),
            committee_root: self.root,
            block: self.header(value).compute_hash(),
            proposer: identity(leader),
            valid_round: form.map(|valid| u32::try_from(valid).unwrap()),
            signature: [0; 64],
        };
        proposal.signature =
            crypto::blake2s::ed25519_sign(&[seed(leader); 32], &proposal.signing_hash().0);
        self.proposals
            .insert((round, value, form), proposal.clone());
        proposal
    }

    /// Asserts the production round, step and durable lock equal the modelled ones.
    fn assert_agrees(&self, state: &State) {
        for validator in 0..self.model.bound.validators {
            let Some(local) = self.locals[validator].as_ref() else {
                continue;
            };
            assert_eq!(
                local.round(),
                u32::from(state.round[validator]),
                "{}: validator {validator} round diverged from the model",
                self.model.bound.name
            );
            let step = match state.step[validator] {
                AWAITING => VotingStep::AwaitingProposal,
                PREVOTED => VotingStep::Prevoted,
                PRECOMMITTED => VotingStep::Precommitted,
                _ => VotingStep::Finalized,
            };
            assert_eq!(
                local.step(),
                step,
                "{}: validator {validator} step diverged from the model",
                self.model.bound.name
            );
            let held = decode_lock(state.locked[validator]).map(|lock| SigningLock {
                round: u32::try_from(lock.round).unwrap(),
                block: self.header(lock.value).compute_hash(),
            });
            assert_eq!(
                local.locked(),
                held,
                "{}: validator {validator} durable lock diverged from the model",
                self.model.bound.name
            );
        }
    }
}

/// Permitted transitions: the production API must accept every one of them.
impl Harness<'_> {
    /// Drives one modelled transition through the production API.
    fn apply(&mut self, state: &State, action: Action) {
        match action {
            Action::Propose {
                validator,
                value,
                valid_round,
            } => self.drive_propose(state, validator, value, valid_round),
            Action::Prevote { validator, value } => self.drive_prevote(state, validator, value),
            Action::TimeoutProposal { validator } => self.drive_nil_prevote(state, validator),
            Action::Precommit { validator, value } => self.drive_precommit(state, validator, value),
            Action::TimeoutPrevote { validator } => {
                let round = u32::from(state.round[validator]);
                let vote = self.local(validator).timeout_prevote(round).unwrap();
                assert_eq!(vote.block, None, "nil precommit carried a block");
                self.precommits
                    .insert((validator, usize::from(state.round[validator])), vote);
            }
            Action::TimeoutPrecommit { validator } => {
                let round = u32::from(state.round[validator]);
                self.local(validator).timeout_precommit(round).unwrap();
            }
            Action::Finalize { validator, value } => self.drive_finalize(state, validator, value),
        }
    }

    /// Signs a designated proposal, with real evidence when the model attaches it.
    fn drive_propose(
        &mut self,
        state: &State,
        validator: usize,
        value: usize,
        valid_round: Option<usize>,
    ) {
        let round = usize::from(state.round[validator]);
        let proof = valid_round.map(|valid| self.certificate(valid, value));
        let header = self.header(value);
        let expected = identity(self.model.proposer[round]);
        assert_eq!(expected, identity(validator), "non-designated proposer");
        let proposal = self
            .local(validator)
            .propose(expected, &header, proof.as_ref(), |_| true)
            .unwrap();
        self.proposals.insert((round, value, valid_round), proposal);
    }

    /// Prevotes an authenticated proposal and asserts the non-nil decision.
    fn drive_prevote(&mut self, state: &State, validator: usize, value: usize) {
        let round = usize::from(state.round[validator]);
        let form = self
            .model
            .justifying_form(state, validator, value)
            .expect("model offered an unjustified prevote");
        let proposal = self.proposal(round, value, form);
        let proof = form.map(|valid| self.certificate(valid, value));
        let header = self.header(value);
        let expected = identity(self.model.proposer[round]);
        let vote = self
            .local(validator)
            .prevote_proposal(expected, &proposal, &header, proof.as_ref(), |_| true)
            .unwrap();
        assert_eq!(
            vote.block,
            Some(header.compute_hash()),
            "permitted prevote for value {value} at round {round} returned nil"
        );
        self.prevotes.insert((validator, round), vote);
    }

    /// Issues a nil prevote, preferring a lock-forbidden proposal over the timer so
    /// the production prevote lock rule is exercised rather than merely assumed.
    fn drive_nil_prevote(&mut self, state: &State, validator: usize) {
        let round = usize::from(state.round[validator]);
        let held = decode_lock(state.locked[validator]);
        let forbidden = (0..self.model.bound.values).find(|value| {
            state.proposals[round][*value] & fresh_form() != 0
                && held.is_some_and(|lock| lock.value != *value)
        });
        let vote = if let Some(value) = forbidden {
            let proposal = self.proposal(round, value, None);
            let header = self.header(value);
            let expected = identity(self.model.proposer[round]);
            self.local(validator)
                .prevote_proposal(expected, &proposal, &header, None, |_| true)
                .unwrap()
        } else {
            self.local(validator)
                .timeout_proposal(u32::try_from(round).unwrap())
                .unwrap()
        };
        assert_eq!(
            vote.block, None,
            "validator {validator} issued a non-nil prevote at round {round} against its lock"
        );
        assert_eq!(
            self.locals[validator].as_ref().unwrap().locked(),
            held.map(|lock| SigningLock {
                round: u32::try_from(lock.round).unwrap(),
                block: self.header(lock.value).compute_hash(),
            }),
            "nil prevote released the durable lock"
        );
        self.prevotes.insert((validator, round), vote);
    }

    /// Locks and precommits a value with a real current-round prevote certificate.
    fn drive_precommit(&mut self, state: &State, validator: usize, value: usize) {
        let round = usize::from(state.round[validator]);
        let proof = self.certificate(round, value);
        let header = self.header(value);
        let vote = self
            .local(validator)
            .precommit(&header, &proof, |_| true)
            .unwrap();
        assert_eq!(
            vote.block,
            Some(header.compute_hash()),
            "precommit carried the wrong block"
        );
        self.precommits.insert((validator, round), vote);
    }

    /// Adopts an independently verified finality certificate.
    fn drive_finalize(&mut self, state: &State, validator: usize, value: usize) {
        let (round, _) = self
            .model
            .decisions(state)
            .into_iter()
            .find(|(_, decided)| *decided == value)
            .expect("model offered a decision with no certificate");
        let certificate = self.finality(round, value);
        let header = self.header(value);
        self.local(validator)
            .finalize(&header, &certificate, |_| true)
            .unwrap();
        assert_eq!(
            self.locals[validator].as_ref().unwrap().finalized_block(),
            Some(header.compute_hash()),
            "finalized block diverged from the certificate"
        );
    }
}

/// Uniform weights with one equivocating seat, the baseline safety bound.
const UNIFORM_SAFETY: Bound = Bound {
    name: "uniform-async-v4-f1-k2-r3",
    validators: 4,
    weights: [1, 1, 1, 1, 0],
    byzantine: [false, false, true, false, false],
    values: 2,
    rounds: 3,
    regime: Regime::Asynchronous,
    adversary: Adversary::MaximalEquivocation,
};

/// Non-uniform weights, so quorum overlap is not an artifact of equal seats.
const WEIGHTED_SAFETY: Bound = Bound {
    name: "weighted-async-v4-f1-k2-r3",
    validators: 4,
    weights: [3, 2, 1, 1, 0],
    byzantine: [false, false, true, false, false],
    values: 2,
    rounds: 3,
    regime: Regime::Asynchronous,
    adversary: Adversary::MaximalEquivocation,
};

/// Equivocating weight raised to exactly `2 * quorum - total`.
const ACCOUNTABLE: Bound = Bound {
    name: "uniform-async-v4-f2-k2-r2",
    validators: 4,
    weights: [1, 1, 1, 1, 0],
    byzantine: [false, false, true, true, false],
    values: 2,
    rounds: 2,
    regime: Regime::Asynchronous,
    adversary: Adversary::MaximalEquivocation,
};

/// Eventual synchrony with an omission-faulty seat.
const LIVE_SILENT: Bound = Bound {
    name: "uniform-sync-v4-f1-k2-r3-silent",
    validators: 4,
    weights: [1, 1, 1, 1, 0],
    byzantine: [false, false, true, false, false],
    values: 2,
    rounds: 3,
    regime: Regime::EventualSynchrony,
    adversary: Adversary::Silent,
};

/// Eventual synchrony with an equivocating seat that also leads round zero.
const LIVE_BYZANTINE: Bound = Bound {
    name: "uniform-sync-v4-f1-k2-r3-equivocating",
    validators: 4,
    weights: [1, 1, 1, 1, 0],
    byzantine: [false, false, true, false, false],
    values: 2,
    rounds: 3,
    regime: Regime::EventualSynchrony,
    adversary: Adversary::MaximalEquivocation,
};

/// Non-uniform eventual synchrony, where honest weight alone reaches the quorum.
const LIVE_WEIGHTED: Bound = Bound {
    name: "weighted-sync-v4-f1-k2-r3-silent",
    validators: 4,
    weights: [3, 2, 1, 1, 0],
    byzantine: [false, false, true, false, false],
    values: 2,
    rounds: 3,
    regime: Regime::EventualSynchrony,
    adversary: Adversary::Silent,
};

/// Equivocating weight at which two disjoint quorums can both form.
///
/// A quorum is strictly more than two thirds of the total, so the complement is
/// strictly smaller than the quorum and this subtraction cannot wrap. The
/// algebraically equal `2 * quorum - total` is deliberately not used: doubling
/// a quorum overflows `u128` at and above `3 * 2^126 - 1`, which this form
/// avoids by never producing an intermediate larger than the total.
fn accountability_threshold(model: &Model) -> u128 {
    model.quorum - (model.total - model.quorum)
}

/// Explores one bound and returns its report, recording the measured counts.
fn survey(bound: Bound) -> (Model, Report) {
    let model = Model::new(bound);
    let started = Instant::now();
    let report = explore(&model, &ALL_PROPERTIES);
    record(&model, &report, started.elapsed());
    (model, report)
}

/// Shortens a bound to two rounds for the ordinary suite.
fn shallow(name: &'static str, bound: Bound) -> Bound {
    Bound {
        name,
        rounds: 2,
        ..bound
    }
}

#[test]
fn asynchronous_exploration_preserves_safety_below_the_accountability_threshold() {
    for bound in [
        shallow("uniform-async-v4-f1-k2-r2", UNIFORM_SAFETY),
        shallow("weighted-async-v4-f1-k2-r2", WEIGHTED_SAFETY),
    ] {
        let (model, report) = survey(bound);
        assert!(
            model.equivocating < accountability_threshold(&model),
            "{}: equivocating {} must stay below the threshold {}",
            model.bound.name,
            model.equivocating,
            accountability_threshold(&model)
        );
        assert_holds(&model, &report);
        // Asynchrony admits undecided terminal states; that is the regime, not a defect.
        assert!(
            report.states > 1 && report.terminal > 0,
            "empty exploration"
        );
    }
}

#[test]
fn conflicting_finality_requires_at_least_the_accountability_threshold() {
    let (model, report) = survey(shallow("accountable-async-v4-f2-k2-r2", ACCOUNTABLE));
    assert_eq!(
        model.equivocating,
        accountability_threshold(&model),
        "{}: this bound must sit exactly at the threshold",
        model.bound.name
    );
    // At the threshold two disjoint quorums can both form, so a conflicting
    // certificate must become reachable. Its existence is what makes the offence
    // attributable: every signature in both quorums is authenticated.
    let (property, trace) = report
        .violation
        .as_ref()
        .expect("equivocating weight at the threshold must expose a conflicting certificate");
    assert!(
        property.starts_with("quorum lock safety"),
        "unexpected first violation at the threshold: {property}"
    );
    assert!(!trace.is_empty(), "counterexample trace is empty");
    println!("  attributable counterexample:\n{}", describe(trace));
}

#[test]
fn eventual_synchrony_decides_at_every_terminal_state_within_the_round_bound() {
    for bound in [
        shallow("live-sync-v4-f1-k2-r2-silent", LIVE_SILENT),
        shallow("live-sync-v4-f1-k2-r2-equivocating", LIVE_BYZANTINE),
        shallow("live-sync-weighted-v4-f1-k2-r2", LIVE_WEIGHTED),
    ] {
        let (model, report) = survey(bound);
        assert_holds(&model, &report);
        assert!(
            report.undecided.is_none(),
            "{}: terminal state without a certificate:\n{}",
            model.bound.name,
            describe(report.undecided.as_deref().unwrap_or_default())
        );
        let round = report
            .decision_round
            .expect("eventual synchrony must reach a certificate");
        assert!(
            round < model.bound.rounds,
            "{}: decided at round {round} outside the bound {}",
            model.bound.name,
            model.bound.rounds
        );
    }
}

#[test]
fn modelled_transitions_agree_with_the_production_local_bft() {
    // Walks drive the real LocalBft over protected journals, so each one costs a
    // temporary directory and real Ed25519 signatures; the walk count is bounded.
    for bound in [
        shallow("uniform-async-v4-f1-k2-r2", UNIFORM_SAFETY),
        shallow("weighted-async-v4-f1-k2-r2", WEIGHTED_SAFETY),
        shallow("live-sync-v4-f1-k2-r2-equivocating", LIVE_BYZANTINE),
    ] {
        let model = Model::new(bound);
        let mut checked = 0usize;
        for walk in 0..16u64 {
            let mut random = Random(0x5eed_0000 ^ walk);
            let mut harness = Harness::new(&model);
            let mut state = model.initial();
            harness.assert_agrees(&state);
            loop {
                let actions = model.actions(&state);
                if actions.is_empty() {
                    break;
                }
                let action = actions[random.choose(actions.len())];
                let next = model.apply(&state, action);
                // The production call sees the same pre-state the model transitioned from.
                harness.apply(&state, action);
                state = next;
                harness.assert_agrees(&state);
                checked += 1;
            }
        }
        println!(
            "{}: {checked} production transitions agreed with the model",
            model.bound.name
        );
        assert!(
            checked > 0,
            "{}: no transition was driven",
            model.bound.name
        );
    }
}

#[test]
#[ignore = "deeper bounded exploration; run with --release --ignored. Bounded model checking, never a proof"]
fn extended_formal_model_campaign() {
    for bound in [
        UNIFORM_SAFETY,
        WEIGHTED_SAFETY,
        ACCOUNTABLE,
        LIVE_SILENT,
        LIVE_BYZANTINE,
        LIVE_WEIGHTED,
        Bound {
            name: "uniform-async-v5-f1-k2-r2",
            validators: 5,
            weights: [1, 1, 1, 1, 1],
            rounds: 2,
            ..UNIFORM_SAFETY
        },
        Bound {
            name: "uniform-async-v4-f1-k3-r2",
            values: 3,
            rounds: 2,
            ..UNIFORM_SAFETY
        },
    ] {
        let threshold_reached = {
            let model = Model::new(bound);
            model.equivocating >= accountability_threshold(&model)
        };
        let (model, report) = survey(bound);
        println!(
            "  threshold {}  equivocating {}  violation {:?}  undecided-terminal {}",
            accountability_threshold(&model),
            model.equivocating,
            report.violation.as_ref().map(|(name, _)| name.clone()),
            report.undecided.is_some()
        );
        if threshold_reached {
            assert!(
                report.violation.is_some(),
                "{}: at or above the threshold a conflicting certificate must be reachable",
                model.bound.name
            );
        } else {
            assert_holds(&model, &report);
        }
    }
}
