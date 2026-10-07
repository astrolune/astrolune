// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Conservative `PoTB` policy workbench over authenticated finalized history.
//!
//! These scores are NOT active consensus weights. Evidence ordering/inclusion,
//! admission and committee handoff must be finalized by a future protocol before
//! any score may change voting authority. Certificate omission is not downtime.

use crate::{
    AuthenticatedCommittee, ConsensusError, DoubleVoteEvidence, FinalityCertificate,
    MAX_COMMITTEE_MEMBERS, PotbWeight,
};
use std::collections::BTreeMap;
use types::{BlockHeader, Hash256, ValidatorId};

/// Explicit experimental constants, with integer-only bounded maturation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PotbPolicy {
    /// Finalized committee-eligible blocks constituting one age epoch.
    pub epoch_blocks: u64,
    /// Starting score of an enrolled identity.
    pub initial_weight: u128,
    /// Additional score per completed eligible epoch.
    pub age_increment: u128,
    /// Per-identity cap; this is not an ownership/Sybil cap.
    pub maximum_weight: u128,
}
impl PotbPolicy {
    /// Rejects zero periods/initial weights or a cap below the initial weight.
    pub fn validate(self) -> Result<(), ConsensusError> {
        if self.epoch_blocks == 0
            || self.initial_weight == 0
            || self.initial_weight > self.maximum_weight
        {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(())
    }

    /// Computes the capped score without intermediate overflow, even at `u128::MAX`.
    /// A verified double vote makes this identity ineligible in this reference policy.
    pub fn score(
        self,
        eligible_blocks: u64,
        disqualified: bool,
    ) -> Result<PotbWeight, ConsensusError> {
        self.validate()?;
        if disqualified {
            return Ok(PotbWeight(0));
        }
        let epochs = u128::from(eligible_blocks / self.epoch_blocks);
        let room = self.maximum_weight - self.initial_weight;
        let growth = if self.age_increment == 0 {
            0
        } else if epochs > room / self.age_increment {
            room
        } else {
            epochs * self.age_increment
        };
        Ok(PotbWeight(self.initial_weight + growth))
    }
}

/// Observations for one enrolled identity. No social-trust input is accepted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ValidatorBehavior {
    /// Finalized heights at which the validator belonged to the trusted committee.
    /// This measures membership age, NOT uptime or work delivered.
    pub eligible_blocks: u64,
    /// Number of verified precommit certificates containing this validator.
    /// Diagnostic only: a valid certificate can omit an honest validator.
    pub certificate_mentions: u64,
    /// Minimum observed offence ID; a permanent exclusion in the experimental policy.
    /// This is a local observation, not an on-chain ban.
    pub disqualification: Option<Hash256>,
}

/// Replays contiguous authenticated headers from a caller-supplied trusted anchor.
/// It retains a bounded roster, two counters and at most one offence ID per member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbTracker {
    chain_id: u32,
    height: u64,
    block: Hash256,
    policy: PotbPolicy,
    validators: BTreeMap<ValidatorId, ValidatorBehavior>,
}
impl PotbTracker {
    /// Creates a workbench at a trusted block/height. Roster is explicit, unique,
    /// nonzero and bounded; new identities cannot arrive through peer observations.
    pub fn new(
        chain_id: u32,
        height: u64,
        block: Hash256,
        policy: PotbPolicy,
        roster: &[ValidatorId],
    ) -> Result<Self, ConsensusError> {
        policy.validate()?;
        if chain_id == 0
            || block == Hash256::ZERO
            || roster.is_empty()
            || roster.len() > MAX_COMMITTEE_MEMBERS
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut validators = BTreeMap::new();
        for id in roster {
            if *id == ValidatorId::ZERO
                || validators
                    .insert(*id, ValidatorBehavior::default())
                    .is_some()
            {
                return Err(ConsensusError::InvalidCommittee);
            }
        }
        Ok(Self {
            chain_id,
            height,
            block,
            policy,
            validators,
        })
    }

    /// Authenticates exact parent/height, committee and quorum before changing any
    /// counter. Context MUST come from independently trusted finalized membership.
    /// This verifies finality only; it does not replace block execution/state checks.
    pub fn observe_finalized(
        &mut self,
        context: &AuthenticatedCommittee,
        header: &BlockHeader,
        certificate: &FinalityCertificate,
    ) -> Result<(), ConsensusError> {
        if context.chain_id() != self.chain_id
            || header.parent != self.block
            || self.height.checked_add(1) != Some(header.height)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        context.verify_certificate(certificate, header)?;
        let mut updates = Vec::new();
        for id in context.members() {
            let mut next = *self
                .validators
                .get(&id)
                .ok_or(ConsensusError::UnknownVoter)?;
            next.eligible_blocks = next
                .eligible_blocks
                .checked_add(1)
                .ok_or(ConsensusError::InvalidTransition)?;
            if certificate
                .signatures
                .binary_search_by_key(&id, |entry| entry.voter)
                .is_ok()
            {
                next.certificate_mentions = next
                    .certificate_mentions
                    .checked_add(1)
                    .ok_or(ConsensusError::InvalidTransition)?;
            }
            updates.push((id, next));
        }
        for (id, next) in updates {
            self.validators.insert(id, next);
        }
        self.height = header.height;
        self.block = header.compute_hash();
        Ok(())
    }

    /// Records a verified historical offence at/below the replayed finalized head.
    /// Order and duplicate proofs cannot stack penalties or increase state size.
    /// Returns true only when the retained observation changes. Future/untrusted
    /// committee contexts must not be passed in by the caller.
    pub fn observe_evidence(
        &mut self,
        context: &AuthenticatedCommittee,
        evidence: &DoubleVoteEvidence,
    ) -> Result<bool, ConsensusError> {
        if context.chain_id() != self.chain_id || evidence.height() > self.height {
            return Err(ConsensusError::InvalidTransition);
        }
        evidence.verify(context)?;
        let record = self
            .validators
            .get_mut(&evidence.voter())
            .ok_or(ConsensusError::UnknownVoter)?;
        let id = evidence.offence_id();
        let previous = record.disqualification;
        record.disqualification = Some(previous.map_or(id, |old| old.min(id)));
        Ok(previous != record.disqualification)
    }

    /// Current authenticated head of this workbench.
    #[must_use]
    pub const fn head(&self) -> (u64, Hash256) {
        (self.height, self.block)
    }

    /// Sorted immutable observations.
    pub fn records(&self) -> impl Iterator<Item = (ValidatorId, ValidatorBehavior)> + '_ {
        self.validators.iter().map(|(id, record)| (*id, *record))
    }

    /// Proposed policy score, not authority to vote or change committee membership.
    pub fn candidate_weight(&self, id: ValidatorId) -> Result<PotbWeight, ConsensusError> {
        let record = self
            .validators
            .get(&id)
            .ok_or(ConsensusError::UnknownVoter)?;
        self.policy
            .score(record.eligible_blocks, record.disqualification.is_some())
    }
}
