// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic hostile delivery schedules using real rotating nodes and durable signers.
//!
//! Scenarios cross delivery faults with a validly signing Byzantine coalition, adverse
//! weight concentration and live membership churn. Roster size, partition shape and the
//! queue bound are derived from the profile rather than fixed at four uniform seats.
#![allow(clippy::too_many_lines)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../consensus/tests/support/potb.rs"]
mod support;

use consensus::{
    DoubleVoteEvidence, Vote, VotePhase, potb_transition::PotbConfiguration,
    potb_transition::PotbVerifier, rotation::CommitteeState,
};
use node::{
    network::{NetworkNode, NetworkNodeError, StaticNetwork},
    network_wire::{NetworkMessage, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use types::{Hash256, ValidatorId};

/// Logical ticks of the initial symmetric partition.
const PARTITION_STEPS: u64 = 8;
/// Logical ticks during which exchanges are dropped, shuffled, delayed and duplicated.
const FAULT_STEPS: u64 = 40;
/// Total logical ticks available to every scenario.
const STEPS: u64 = 400;
/// Exclusive upper bound of the delay drawn for a delivered exchange.
const DELAY_CHOICES: usize = 8;
/// Extra copies a single directed route may queue for one logical tick.
const DUPLICATES: usize = 1;
/// Ticks after which an unproductive one-directional blackout is abandoned and reported.
const BLACKOUT_LIMIT: u64 = 80;

/// Uniform starting weights for the baseline rosters.
const UNIFORM: &[u128] = &[10, 10, 10, 10];
/// One validator holds a near-threshold share, so quorum is not a seat count.
const CONCENTRATED: &[u128] = &[10, 10, 10, 29];

/// Which independently supplied trusted configuration a scenario runs against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Authority {
    /// Genesis-v2 VRF rotation with static genesis weights.
    Rotating,
    /// Explicit `PoTB` configuration and immutable policy.
    Potb,
    /// Explicit `PoTB` configuration with the parameter-governance namespace.
    GovernedPotb,
}

/// One complete scenario shape. Every derived bound comes from these fields.
#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    authority: Authority,
    members: &'static [u8],
    weights: &'static [u128],
    seats: usize,
    age_increment: u128,
    candidates: &'static [u8],
    byzantine: &'static [u8],
    conflicts: usize,
    governance: bool,
    exclude: Option<u8>,
    isolated: Option<usize>,
    target: u64,
}

impl Profile {
    const fn base(name: &'static str, authority: Authority) -> Self {
        Self {
            name,
            authority,
            members: &[1, 2, 3, 4],
            weights: UNIFORM,
            seats: 3,
            age_increment: 3,
            candidates: &[],
            byzantine: &[],
            conflicts: 0,
            governance: false,
            exclude: None,
            isolated: None,
            target: 6,
        }
    }

    fn seeds(&self) -> Vec<u8> {
        let mut seeds = self.members.to_vec();
        seeds.extend_from_slice(self.candidates);
        seeds
    }

    fn count(&self) -> usize {
        self.members.len() + self.candidates.len()
    }

    fn potb_profile(&self) -> PotbConfiguration {
        let base = hostile::potb_configuration(
            self.members,
            self.weights[0],
            self.seats,
            self.age_increment,
        );
        if self.authority == Authority::GovernedPotb {
            support::governed(base)
        } else {
            base
        }
    }

    fn network(&self) -> StaticNetwork {
        let keys = hostile::keys(self.members);
        match self.authority {
            Authority::Rotating => StaticNetwork::new(
                hostile::rotating_genesis(self.members, self.weights, self.seats),
                keys,
            )
            .unwrap(),
            Authority::Potb | Authority::GovernedPotb => {
                StaticNetwork::with_potb(self.potb_profile(), keys).unwrap()
            }
        }
    }

    fn churn(&self) -> Churn {
        let mut churn = Churn::default();
        if self.authority != Authority::Rotating {
            churn.trusted = Some(
                PotbVerifier::new(&self.potb_profile(), &hostile::keys(self.members)).unwrap(),
            );
        }
        churn
    }

    fn weight(&self, seed: u8) -> u128 {
        self.members
            .iter()
            .position(|member| *member == seed)
            .map_or(self.weights[0], |index| self.weights[index])
    }

    fn coalition_seed(&self, voter: ValidatorId) -> Option<u8> {
        self.byzantine
            .iter()
            .copied()
            .find(|seed| hostile::identity(*seed) == voter)
    }

    /// Every committee able to seat the whole coalition must still require strictly more
    /// shared weight for two conflicting quorums than the coalition controls.
    fn accountable(&self) -> bool {
        if self.byzantine.is_empty() {
            return true;
        }
        assert!(
            self.authority == Authority::Rotating || self.age_increment == 0,
            "{}: a coalition scenario must freeze weights so its exact share is known",
            self.name
        );
        let seeds = self.seeds();
        let coalition: u128 = self.byzantine.iter().map(|seed| self.weight(*seed)).sum();
        for mask in 0u32..(1 << seeds.len()) {
            if usize::try_from(mask.count_ones()).unwrap() != self.seats {
                continue;
            }
            let seated: Vec<u8> = seeds
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1u32 << index) != 0)
                .map(|(_, seed)| *seed)
                .collect();
            if !self.byzantine.iter().all(|seed| seated.contains(seed)) {
                continue;
            }
            let total: u128 = seated.iter().map(|seed| self.weight(*seed)).sum();
            if coalition >= hostile::accountability_threshold(total) {
                return false;
            }
        }
        true
    }

    /// Directed routes times one original plus `DUPLICATES` copies, retained for the
    /// originating tick plus every tick a drawn delay can still postpone delivery.
    fn queue_bound(&self) -> usize {
        let routes = self.count() * (self.count() - 1);
        routes * (1 + DUPLICATES) * (DELAY_CHOICES + 1)
    }
}

fn rotating() -> Profile {
    Profile::base("rotating", Authority::Rotating)
}

fn potb() -> Profile {
    Profile::base("potb", Authority::Potb)
}

fn equivocating_rotating() -> Profile {
    let mut profile = Profile::base("equivocating-rotating", Authority::Rotating);
    profile.byzantine = &[2];
    profile.conflicts = 3;
    profile
}

fn equivocating_potb() -> Profile {
    let mut profile = Profile::base("equivocating-potb", Authority::Potb);
    profile.age_increment = 0;
    profile.byzantine = &[3];
    profile.conflicts = 3;
    profile
}

fn concentrated() -> Profile {
    let mut profile = Profile::base("concentrated", Authority::Rotating);
    profile.weights = CONCENTRATED;
    profile.byzantine = &[1];
    profile.conflicts = 3;
    profile
}

fn churning() -> Profile {
    let mut profile = Profile::base("churn", Authority::GovernedPotb);
    profile.candidates = &[99];
    profile.governance = true;
    profile.exclude = Some(1);
    profile.isolated = Some(4);
    profile.target = 8;
    profile
}

/// One queued exchange, owned independently of later node changes.
struct Packet {
    destination: usize,
    due: u64,
    bytes: Vec<u8>,
}

/// Exact voting slot shared by every conflicting value one signer can produce.
type Slot = (ValidatorId, u64, u32, VotePhase);

fn slot_of(vote: &Vote) -> Slot {
    (vote.voter, vote.height, vote.round, vote.phase)
}

/// What a forged copy of an honest message changes. Each gossip kind is handled
/// deliberately; there is no catch-all arm that could silently stop attacking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Forgery {
    /// A publicly authenticated field was changed in place.
    Field,
    /// Quorum-bearing certificate gossip exposes no publicly mutable authenticated
    /// field, so the caller mangles the framed body instead. Structural decoding or
    /// certificate verification must reject the result.
    Envelope,
}

// Corrupt authenticated fields without changing framing; no private node state is touched.
fn corrupt(message: &mut NetworkMessage) -> Forgery {
    match message {
        NetworkMessage::Proposal { envelope, .. } => envelope.signature[0] ^= 1,
        NetworkMessage::Vote(vote) => vote.signature[0] ^= 1,
        NetworkMessage::VrfContribution { height, .. } => *height += 100,
        NetworkMessage::Finalized { block, .. } | NetworkMessage::ValidValue { block, .. } => {
            block.header.state_root = Hash256::ZERO;
        }
        NetworkMessage::Transaction(tx) => tx.signature[0] ^= 1,
        NetworkMessage::Governance(_)
        | NetworkMessage::PotbAdmission(_)
        | NetworkMessage::PotbEvidence(_) => return Forgery::Envelope,
    }
    Forgery::Field
}

/// Live membership churn driven from independently replayed finalized handoffs.
#[derive(Default)]
struct Churn {
    trusted: Option<PotbVerifier>,
    roots: Vec<Hash256>,
    past: BTreeMap<u64, CommitteeState>,
    admitted: Option<u64>,
    admissions: usize,
    admission_attempts: usize,
    governed: Option<u64>,
    governance: usize,
    governance_attempts: usize,
    excluded: Option<u64>,
    exclusions: usize,
    exclusion_attempts: usize,
}

impl std::fmt::Debug for Churn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Churn")
            .field("admitted_at", &self.admitted)
            .field("admissions", &self.admissions)
            .field("admission_attempts", &self.admission_attempts)
            .field("governed_at", &self.governed)
            .field("governance", &self.governance)
            .field("governance_attempts", &self.governance_attempts)
            .field("excluded_at", &self.excluded)
            .field("exclusions", &self.exclusions)
            .field("exclusion_attempts", &self.exclusion_attempts)
            // Replayed handoff state is not a counter and is omitted deliberately.
            .finish_non_exhaustive()
    }
}

impl Churn {
    /// Replays every available finalized handoff, retaining one committee root per height.
    fn follow(&mut self, nodes: &[NetworkNode]) {
        let Some(mut trusted) = self.trusted.take() else {
            return;
        };
        loop {
            let height = trusted.current().committee().height();
            let Some(handoff) = nodes
                .iter()
                .find_map(|node| node::handoff::read_potb_handoff(node.storage(), height).unwrap())
            else {
                break;
            };
            self.roots
                .push(trusted.current().committee().context().unwrap().root());
            self.past
                .insert(height, trusted.current().committee().clone());
            trusted.apply(&handoff).unwrap();
        }
        self.trusted = Some(trusted);
    }

    /// Submits admission, exclusion and governance for the exact current parent.
    /// Rejected submissions are expected: a certificate is scoped to one frontier.
    fn drive(&mut self, nodes: &mut [NetworkNode], profile: &Profile, step: u64) {
        let Some(trusted) = self.trusted.take() else {
            return;
        };
        self.submit(&trusted, nodes, profile, step);
        self.trusted = Some(trusted);
    }

    fn submit(
        &mut self,
        trusted: &PotbVerifier,
        nodes: &mut [NetworkNode],
        profile: &Profile,
        step: u64,
    ) {
        let state = trusted.current();
        let height = state.committee().height();
        let Some(index) = nodes
            .iter()
            .position(|node| node.request().height == height && !node.is_standby())
        else {
            return;
        };
        if let Some(candidate) = profile.candidates.first().copied() {
            if state
                .records()
                .any(|(id, _)| id == hostile::identity(candidate))
            {
                self.admitted.get_or_insert(height);
            } else {
                self.admission_attempts += usize::from(step < FAULT_STEPS);
                if nodes[index]
                    .submit_potb_admission(support::admission(state, trusted.parent(), candidate))
                    .is_ok()
                {
                    self.admissions += 1;
                }
            }
        }
        if let Some(accused) = profile.exclude {
            let id = hostile::identity(accused);
            let banned = state
                .records()
                .find(|(voter, _)| *voter == id)
                .is_none_or(|(_, record)| record.disqualification.is_some());
            if banned {
                self.excluded.get_or_insert(height);
            } else if let Some(past) = self.past.get(&1) {
                self.exclusion_attempts += usize::from(step < FAULT_STEPS);
                let evidence = support::evidence(state, past, &self.roots, accused);
                if nodes[index].submit_potb_evidence(evidence).is_ok() {
                    self.exclusions += 1;
                }
            }
        }
        if profile.governance {
            let policy = state.governance().unwrap();
            if policy.active().capacity == hostile::CAPACITY {
                if policy.pending().is_none() {
                    self.governance_attempts += usize::from(step < FAULT_STEPS);
                    if nodes[index]
                        .submit_governance(support::parameters(state, trusted.parent()))
                        .is_ok()
                    {
                        self.governance += 1;
                    }
                }
            } else {
                self.governed.get_or_insert(height);
            }
        }
    }
}

#[derive(Default)]
struct Schedule {
    pending: Vec<Packet>,
    dropped: usize,
    delayed: usize,
    duplicated: usize,
    attacked: usize,
    mangled: usize,
    blinded: usize,
    equivocations: usize,
    seat_changes: usize,
    blackout_commits: u64,
    rounds: u32,
    slots: BTreeMap<Slot, BTreeMap<Option<Hash256>, Vote>>,
    offences: BTreeMap<ValidatorId, BTreeSet<Hash256>>,
    proofs: BTreeMap<Slot, DoubleVoteEvidence>,
    churn: Churn,
}

impl std::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Schedule")
            .field("pending", &self.pending.len())
            .field("dropped", &self.dropped)
            .field("delayed", &self.delayed)
            .field("duplicated", &self.duplicated)
            .field("attacked", &self.attacked)
            .field("mangled", &self.mangled)
            .field("blinded", &self.blinded)
            .field("equivocations", &self.equivocations)
            .field("offences", &self.offences.len())
            .field("proofs", &self.proofs.len())
            .field("seat_changes", &self.seat_changes)
            .field("blackout_commits", &self.blackout_commits)
            .field("rounds", &self.rounds)
            .field("churn", &self.churn)
            // Queued packets and retained proofs are reported by count, not by body.
            .finish_non_exhaustive()
    }
}

impl Schedule {
    fn collect(
        &mut self,
        nodes: &mut [NetworkNode],
        network: &StaticNetwork,
        profile: &Profile,
        random: &mut hostile::Random,
        step: u64,
        blind: Option<usize>,
    ) {
        let count = nodes.len();
        for destination in 0..count {
            if nodes[destination].request().height >= profile.target {
                continue;
            }
            // A one-directional blackout keeps the isolated node publishing its own
            // randomness while it receives nothing, so a handoff can commit without it.
            if blind == Some(destination) {
                self.blinded += count - 1;
                self.dropped += count - 1;
                continue;
            }
            for source in 0..count {
                if source == destination {
                    continue;
                }
                if step < PARTITION_STEPS && source * 2 / count != destination * 2 / count {
                    self.dropped += 1;
                    continue;
                }
                let bytes = nodes[source].respond(nodes[destination].request()).unwrap();
                let mut messages = decode_exchange(network.genesis_hash(), &bytes).unwrap();
                if step < FAULT_STEPS && !messages.is_empty() {
                    if random.choose(5) == 0 {
                        self.dropped += 1;
                        continue;
                    }
                    random.shuffle(&mut messages);
                    let forged = messages[0].clone();
                    self.attack(&mut nodes[destination], network.genesis_hash(), forged);
                }
                // Conflicting values are appended after the honest set, so the honest
                // value is always counted first and no quorum can be hijacked.
                let conflicts = self.equivocate(&messages, profile);
                let mut outgoing = messages;
                outgoing.extend(conflicts);
                let bytes = encode_exchange(network.genesis_hash(), &outgoing).unwrap();
                let delay = if step < FAULT_STEPS {
                    u64::try_from(random.choose(DELAY_CHOICES)).unwrap()
                } else {
                    0
                };
                self.delayed += usize::from(delay != 0);
                if step < FAULT_STEPS && random.choose(4) == 0 {
                    self.pending.push(Packet {
                        destination,
                        due: step + delay + 1,
                        bytes: bytes.clone(),
                    });
                    self.duplicated += 1;
                }
                self.pending.push(Packet {
                    destination,
                    due: step + delay,
                    bytes,
                });
            }
        }
        assert!(
            self.pending.len() <= profile.queue_bound(),
            "{}: queue exceeded its derived bound of {} exchanges",
            profile.name,
            profile.queue_bound()
        );
    }

    fn attack(&mut self, node: &mut NetworkNode, genesis: Hash256, mut message: NetworkMessage) {
        let before = *node.storage().checkpoint().unwrap();
        match corrupt(&mut message) {
            Forgery::Field => {
                node.receive(&encode_exchange(genesis, &[message]).unwrap())
                    .unwrap();
            }
            Forgery::Envelope => {
                let mut bytes = encode_exchange(genesis, &[message]).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                match node.receive(&bytes) {
                    Ok(_) | Err(NetworkNodeError::Input(_)) => {}
                    Err(error) => {
                        panic!("mangled certificate gossip must stay an input error: {error}")
                    }
                }
                self.mangled += 1;
            }
        }
        assert_eq!(
            node.storage().checkpoint(),
            Some(&before),
            "forged input must not change the published checkpoint"
        );
        self.attacked += 1;
    }

    /// Signs additional conflicting values for every observed coalition vote.
    fn equivocate(
        &mut self,
        messages: &[NetworkMessage],
        profile: &Profile,
    ) -> Vec<NetworkMessage> {
        let mut conflicts = Vec::new();
        for message in messages {
            let NetworkMessage::Vote(honest) = message else {
                continue;
            };
            let Some(seed) = profile.coalition_seed(honest.voter) else {
                continue;
            };
            let slot = self.slots.entry(slot_of(honest)).or_default();
            slot.insert(honest.block, honest.clone());
            for index in 0..profile.conflicts {
                let vote = hostile::equivocating_vote(honest, seed, index);
                slot.insert(vote.block, vote.clone());
                conflicts.push(NetworkMessage::Vote(vote));
                self.equivocations += 1;
            }
        }
        conflicts
    }

    fn deliver(
        &mut self,
        nodes: &mut [NetworkNode],
        random: &mut hostile::Random,
        step: u64,
        blind: Option<usize>,
    ) {
        random.shuffle(&mut self.pending);
        let mut waiting = Vec::new();
        for packet in self.pending.drain(..) {
            if blind == Some(packet.destination) {
                self.blinded += 1;
                self.dropped += 1;
                continue;
            }
            if packet.due <= step {
                nodes[packet.destination].receive(&packet.bytes).unwrap();
            } else {
                waiting.push(packet);
            }
        }
        self.pending = waiting;
    }

    /// Records every durably retained proof and refuses any accusation of an honest signer.
    fn observe(&mut self, nodes: &[NetworkNode], profile: &Profile) {
        for (index, node) in nodes.iter().enumerate() {
            let mut accused = BTreeSet::new();
            for proof in node.evidence() {
                assert!(
                    profile.coalition_seed(proof.voter()).is_some(),
                    "{}: node {index} accused non-equivocating signer {}",
                    profile.name,
                    proof.voter()
                );
                assert!(
                    accused.insert(proof.voter()),
                    "{}: node {index} retained two proofs for one signer",
                    profile.name
                );
                let (first, _) = proof.votes();
                self.offences
                    .entry(proof.voter())
                    .or_default()
                    .insert(proof.offence_id());
                self.proofs.insert(slot_of(first), proof.clone());
            }
        }
    }
}

// Compare every newly published prefix, including heights passed by sequential catch-up.
fn check_safety(nodes: &[NetworkNode], checked: &mut [u64], history: &mut BTreeMap<u64, Hash256>) {
    for (index, node) in nodes.iter().enumerate() {
        let checkpoint = node.storage().checkpoint().unwrap();
        assert!(
            checkpoint.height >= checked[index],
            "committed height regressed at node {index}"
        );
        for height in checked[index] + 1..=checkpoint.height {
            let (block, _) = node.storage().read_finalized(height).unwrap().unwrap();
            let hash = block.header.compute_hash();
            if let Some(previous) = history.insert(height, hash) {
                assert_eq!(previous, hash, "conflicting finality at height {height}");
            }
        }
        checked[index] = checkpoint.height;
    }
}

fn highest(nodes: &[NetworkNode], except: usize) -> u64 {
    nodes
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != except)
        .map(|(_, node)| node.request().height)
        .max()
        .unwrap()
}

/// One-directional inbound blackout window around a committed membership handoff.
///
/// The window opens only while the isolated node holds no voting seat. Blinding a
/// seated member of a three-seat committee removes a necessary quorum share and simply
/// halts the height, which tests nothing about authenticated catch-up.
#[derive(Clone, Copy)]
struct Blackout {
    start: u64,
    end: Option<u64>,
    others: u64,
    isolated: u64,
}

fn run(profile: &Profile, seed: u64) -> Schedule {
    assert!(
        profile.accountable(),
        "{}: equivocating weight must stay below the accountability threshold",
        profile.name
    );
    let count = profile.count();
    let fixture = hostile::Fixture::new(profile.network(), &profile.seeds());
    let mut nodes: Vec<_> = (0..count).map(|index| fixture.open(index)).collect();
    let mut random = hostile::Random(seed);
    let mut schedule = Schedule {
        churn: profile.churn(),
        ..Schedule::default()
    };
    let mut history = BTreeMap::new();
    let mut checked = vec![0u64; count];
    let mut seats: Vec<Option<(u64, bool)>> = vec![None; count];
    let mut restarted_after_commit = false;
    let mut restarted_across_transition = false;
    let mut blackout: Option<Blackout> = None;
    let now = Instant::now();
    for step in 0..STEPS {
        if step == 4 {
            fixture.restart(&mut nodes, 2);
        }
        if !restarted_after_commit && nodes[1].request().height >= 3 {
            fixture.restart(&mut nodes, 1);
            restarted_after_commit = true;
        }
        for index in 0..count {
            let height = nodes[index].request().height;
            let standby = nodes[index].is_standby();
            if let Some((last_height, last_standby)) = seats[index]
                && height > last_height
                && standby != last_standby
            {
                schedule.seat_changes += 1;
            }
            seats[index] = Some((height, standby));
        }
        let mut blind = None;
        if let Some(isolated) = profile.isolated {
            match blackout {
                None if nodes[isolated].request().height > 1 && nodes[isolated].is_standby() => {
                    blackout = Some(Blackout {
                        start: step,
                        end: None,
                        others: highest(&nodes, isolated),
                        isolated: nodes[isolated].request().height,
                    });
                    blind = Some(isolated);
                }
                Some(window) if window.end.is_none() => {
                    let after = highest(&nodes, isolated);
                    if after > window.others || step - window.start >= BLACKOUT_LIMIT {
                        schedule.blackout_commits = after - window.others;
                        blackout = Some(Blackout {
                            end: Some(step),
                            ..window
                        });
                        assert!(
                            schedule.blackout_commits > 0,
                            "{}, seed={seed}: a handoff must commit while one node is blind, {schedule:?}",
                            profile.name
                        );
                        assert_eq!(
                            nodes[isolated].request().height,
                            window.isolated,
                            "{}, seed={seed}: a blind node cannot publish",
                            profile.name
                        );
                        // Reopen the stale node before it authenticates the catch-up, so
                        // recovery spans the membership transition it never observed.
                        fixture.restart(&mut nodes, isolated);
                        restarted_across_transition = true;
                    } else {
                        blind = Some(isolated);
                    }
                }
                _ => {}
            }
        }
        schedule.collect(
            &mut nodes,
            &fixture.network,
            profile,
            &mut random,
            step,
            blind,
        );
        schedule.deliver(&mut nodes, &mut random, step, blind);
        let mut order: Vec<usize> = (0..count).collect();
        random.shuffle(&mut order);
        for index in order {
            if nodes[index].request().height < profile.target {
                // Independent monotonic clocks with fixed bounded skew.
                let skew = u64::try_from(index).unwrap() * 3;
                nodes[index]
                    .tick(now + Duration::from_millis(step * 20 + skew))
                    .unwrap();
                schedule.rounds = schedule.rounds.max(nodes[index].round());
            }
        }
        schedule.churn.follow(&nodes);
        schedule.churn.drive(&mut nodes, profile, step);
        schedule.observe(&nodes, profile);
        check_safety(&nodes, &mut checked, &mut history);
        if step < PARTITION_STEPS {
            assert!(
                checked.iter().all(|height| *height == 0),
                "{}: a partition cannot replace missing VRF proofs",
                profile.name
            );
        }
        if nodes
            .iter()
            .all(|node| node.request().height == profile.target)
        {
            break;
        }
    }
    assert!(
        checked.iter().all(|height| *height == profile.target - 1),
        "{}, seed={seed}, {schedule:?}",
        profile.name
    );
    assert!(restarted_after_commit, "{}", profile.name);
    assert!(
        schedule.dropped > 0 && schedule.delayed > 0 && schedule.duplicated > 0,
        "{}, seed={seed}, {schedule:?}",
        profile.name
    );
    assert!(schedule.attacked > 0, "{}, seed={seed}", profile.name);
    assert!(
        schedule.rounds > 0,
        "{}, seed={seed}: the schedule must exercise round recovery",
        profile.name
    );
    check_coalition(profile, seed, &schedule);
    check_churn(profile, seed, &schedule, restarted_across_transition);
    let checkpoint = *nodes[0].storage().checkpoint().unwrap();
    for node in &nodes {
        assert_eq!(node.storage().checkpoint(), Some(&checkpoint));
        fixture.network.verify_storage(node.storage()).unwrap();
    }
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    while observer.request().height < profile.target {
        let response = nodes[0].respond(observer.request()).unwrap();
        observer.receive(&response).unwrap();
    }
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    fixture.network.verify_storage(observer.storage()).unwrap();
    schedule
}

/// A validly signed coalition must be detected, attributed and deduplicated by slot.
fn check_coalition(profile: &Profile, seed: u64, schedule: &Schedule) {
    if profile.byzantine.is_empty() {
        assert!(
            schedule.equivocations == 0 && schedule.proofs.is_empty(),
            "{}, seed={seed}: no equivocation was injected, {schedule:?}",
            profile.name
        );
        return;
    }
    assert!(
        schedule.equivocations > 0,
        "{}, seed={seed}: the coalition must sign conflicting values, {schedule:?}",
        profile.name
    );
    assert!(
        !schedule.proofs.is_empty(),
        "{}, seed={seed}: equivocation must be detected and attributed, {schedule:?}",
        profile.name
    );
    for (slot, proof) in &schedule.proofs {
        let values: Vec<_> = schedule.slots[slot].values().cloned().collect();
        assert!(
            values.len() >= 3,
            "{}, seed={seed}: slot {slot:?} must retain three or more conflicting values",
            profile.name
        );
        let proofs: Vec<_> = [(0, 1), (0, 2), (1, 2)]
            .iter()
            .map(|(first, second)| hostile::proof_from_votes(&values[*first], &values[*second]))
            .collect();
        let ids: BTreeSet<_> = proofs.iter().map(DoubleVoteEvidence::id).collect();
        assert_eq!(
            ids.len(),
            3,
            "{}, seed={seed}: three conflicting values give three distinct proofs",
            profile.name
        );
        let offences: BTreeSet<_> = proofs.iter().map(DoubleVoteEvidence::offence_id).collect();
        assert_eq!(
            offences.len(),
            1,
            "{}, seed={seed}: one signer's conflicting values are one offence",
            profile.name
        );
        assert_eq!(
            offences.into_iter().next(),
            Some(proof.offence_id()),
            "{}, seed={seed}: the retained proof must identify the same offence slot",
            profile.name
        );
    }
}

/// Membership churn crossed with delivery faults must still converge and reauthenticate.
fn check_churn(profile: &Profile, seed: u64, schedule: &Schedule, restarted: bool) {
    if profile.seats < profile.members.len() {
        assert!(
            schedule.seat_changes > 0,
            "{}, seed={seed}: committed seats must change, {schedule:?}",
            profile.name
        );
    }
    if profile.isolated.is_some() {
        assert!(
            restarted && schedule.blinded > 0,
            "{}, seed={seed}: a restart must span a committed transition, {schedule:?}",
            profile.name
        );
    }
    if !profile.candidates.is_empty() {
        assert!(
            schedule.churn.admission_attempts > 0,
            "{}, seed={seed}: admission must be offered while delivery is faulty, {schedule:?}",
            profile.name
        );
        assert!(
            schedule.churn.admitted.is_some(),
            "{}, seed={seed}: the candidate must be registered, {schedule:?}",
            profile.name
        );
    }
    if profile.exclude.is_some() {
        assert!(
            schedule.churn.exclusion_attempts > 0,
            "{}, seed={seed}: exclusion must be offered while delivery is faulty, {schedule:?}",
            profile.name
        );
        assert!(
            schedule.churn.excluded.is_some(),
            "{}, seed={seed}: the offender must be excluded, {schedule:?}",
            profile.name
        );
    }
    if profile.governance {
        assert!(
            schedule.churn.governance_attempts > 0 && schedule.mangled > 0,
            "{}, seed={seed}: certificate gossip must be mangled under fault, {schedule:?}",
            profile.name
        );
        assert!(
            schedule.churn.governed.is_some(),
            "{}, seed={seed}: the parameter change must activate, {schedule:?}",
            profile.name
        );
    }
}

const FIXED: u64 = 0x1234_5678_9abc_def0;

#[test]
fn rotating_profiles_preserve_finality_and_recover_after_hostile_delivery() {
    for profile in [rotating(), potb()] {
        let result = run(&profile, FIXED);
        eprintln!("{}: {result:?}", profile.name);
    }
}

#[test]
fn validly_signed_equivocation_is_attributed_without_conflicting_finality_smoke() {
    let profile = equivocating_rotating();
    let result = run(&profile, FIXED);
    eprintln!("{}: {result:?}", profile.name);
}

#[test]
fn adverse_weight_concentration_keeps_weighted_quorum_above_a_seat_majority_smoke() {
    let profile = concentrated();
    let total: u128 = profile.weights.iter().sum();
    let heavy = *profile.weights.iter().max().unwrap();
    let quorum = consensus::quorum_power(total);
    assert!(
        heavy < quorum && total - heavy < quorum,
        "the heavy seat must be necessary but insufficient: heavy={heavy}, quorum={quorum}"
    );
    let result = run(&profile, FIXED);
    eprintln!("{}: {result:?}", profile.name);
}

#[test]
fn membership_churn_during_delivery_faults_still_converges_and_reauthenticates_smoke() {
    let profile = churning();
    let result = run(&profile, FIXED);
    eprintln!("{}: {result:?}", profile.name);
}

#[test]
#[ignore = "explicit multi-seed delivery-schedule campaign; bounded simulation only, not exhaustive state exploration"]
fn extended_rotating_schedule_campaign() {
    for seed in 1..=12 {
        for profile in [rotating(), potb()] {
            let result = run(&profile, seed);
            eprintln!("{}, seed={seed}: {result:?}", profile.name);
        }
    }
}

#[test]
#[ignore = "explicit multi-seed Byzantine equivocation campaign; bounded coalitions only, no formal safety proof"]
fn extended_byzantine_equivocation_campaign() {
    for seed in 1..=8 {
        for profile in [equivocating_rotating(), equivocating_potb(), concentrated()] {
            let result = run(&profile, seed);
            eprintln!("{}, seed={seed}: {result:?}", profile.name);
        }
    }
}

#[test]
#[ignore = "explicit multi-seed membership-churn campaign; bounded churn schedules only, no disk-failure model"]
fn extended_membership_churn_campaign() {
    for seed in 1..=6 {
        let profile = churning();
        let result = run(&profile, seed);
        eprintln!("{}, seed={seed}: {result:?}", profile.name);
    }
}
