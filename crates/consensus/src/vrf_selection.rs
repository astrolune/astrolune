// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Verified, integer-only weighted draws over a complete finalized VRF batch.

use std::collections::{BTreeMap, BTreeSet};

use crypto::{Blake2sProvider, CryptoProvider, VrfInput, VrfRole};
use types::{Hash256, ValidatorId, hash::domain_hash};

use crate::{
    Candidate, Committee, CommitteeMember, ConsensusError, MAX_COMMITTEE_MEMBERS, PotbWeight,
};

/// Eligibility and weight obtained from trusted finalized state, never a proof sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VrfValidator {
    /// Registered Ed25519 public key.
    pub public_key: [u8; 32],
    /// Positive finalized weight after admission, bans, and policy caps.
    pub weight: PotbWeight,
}

/// Complete, authenticated VRF batch with canonical contribution order.
///
/// The caller must finalize the roster and input before proofs are revealed.
/// Every roster member must contribute: omitting a proof is an error, not an
/// alternative lottery. Collection/availability and activation are separate
/// consensus steps. This API never silently drops unavailable validators.
pub struct VerifiedVrfSampler {
    input: VrfInput,
    members: Vec<CommitteeMember>,
    randomness: Hash256,
}

impl VerifiedVrfSampler {
    /// Checks the full bounded roster, trusted weights, and every VRF proof.
    pub fn new(
        input: VrfInput,
        roster: &[VrfValidator],
        candidates: &[Candidate],
    ) -> Result<Self, ConsensusError> {
        if roster.is_empty()
            || roster.len() > MAX_COMMITTEE_MEMBERS
            || candidates.len() != roster.len()
            || input.genesis == Hash256::ZERO
            || input.height == 0
            || (input.role == VrfRole::Committee && input.round != 0)
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut provider = Blake2sProvider::new();
        let mut weights = BTreeMap::new();
        let mut total = 0u128;
        for member in roster {
            let id = provider
                .register_validator(member.public_key)
                .map_err(|_| ConsensusError::InvalidProof)?;
            if member.weight.0 == 0 || weights.insert(id, member.weight).is_some() {
                return Err(ConsensusError::InvalidCommittee);
            }
            total = total
                .checked_add(member.weight.0)
                .ok_or(ConsensusError::InvalidCommittee)?;
        }
        let seed = input.seed();
        let mut proofs = BTreeMap::new();
        for candidate in candidates {
            if weights.get(&candidate.id) != Some(&candidate.weight)
                || proofs
                    .insert(candidate.id, candidate.vrf.randomness)
                    .is_some()
            {
                return Err(ConsensusError::InvalidCommittee);
            }
            if !provider.verify_vrf(candidate.id, seed, &candidate.vrf) {
                return Err(ConsensusError::InvalidProof);
            }
        }
        let mut transcript = Vec::with_capacity(32 + 80 * roster.len());
        transcript.extend_from_slice(&seed.0);
        let mut members = Vec::with_capacity(roster.len());
        for (id, weight) in weights {
            transcript.extend_from_slice(&id.0);
            transcript.extend_from_slice(&weight.0.to_le_bytes());
            transcript.extend_from_slice(&proofs[&id].0);
            members.push(CommitteeMember { id, power: weight });
        }
        Ok(Self {
            input,
            members,
            randomness: domain_hash(b"astrolune.vrf.batch.v1", &transcript),
        })
    }

    /// Commitment to the complete authenticated contribution transcript.
    #[must_use]
    pub const fn randomness(&self) -> Hash256 {
        self.randomness
    }

    /// Samples unique seats with probability weight / remaining total at each draw.
    pub fn select(&self, size: usize) -> Result<Committee, ConsensusError> {
        if self.input.role != VrfRole::Committee || size == 0 || size > self.members.len() {
            return Err(ConsensusError::InvalidCommittee);
        }
        Ok(Committee {
            height: self.input.height,
            members: self.draw(self.members.clone(), size)?,
        })
    }

    /// Retains the newest seats and replaces exactly the oldest `count` seats.
    /// Removed/ineligible members cannot be retained. Outgoing members may win
    /// a new seat; selection is without replacement within the resulting committee.
    pub fn rotate(&self, current: &Committee, count: usize) -> Result<Committee, ConsensusError> {
        current.total_power()?;
        if self.input.role != VrfRole::Committee
            || current.height.checked_add(1) != Some(self.input.height)
            || count > current.members.len()
        {
            return Err(ConsensusError::InvalidTransition);
        }
        let weights: BTreeMap<_, _> = self.members.iter().map(|m| (m.id, m.power)).collect();
        let mut retained = Vec::with_capacity(current.members.len());
        for member in &current.members[count..] {
            let power = *weights
                .get(&member.id)
                .ok_or(ConsensusError::InvalidCommittee)?;
            retained.push(CommitteeMember {
                id: member.id,
                power,
            });
        }
        let retained_ids: BTreeSet<_> = retained.iter().map(|m| m.id).collect();
        let eligible = self
            .members
            .iter()
            .filter(|m| !retained_ids.contains(&m.id))
            .copied()
            .collect();
        retained.extend(self.draw(eligible, count)?);
        let committee = Committee {
            height: self.input.height,
            members: retained,
        };
        committee.total_power()?;
        Ok(committee)
    }

    /// Draws a producer after checking exact active membership and voting weights.
    pub fn producer(&self, committee: &Committee) -> Result<ValidatorId, ConsensusError> {
        committee.total_power()?;
        let mut members = committee.members.clone();
        members.sort_by_key(|m| m.id);
        if self.input.role != VrfRole::Producer
            || committee.height != self.input.height
            || members != self.members
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        Ok(self.draw(members, 1)?[0].id)
    }

    /// Draws within a selected subset using entropy from the complete eligible roster.
    /// Every selected identity and weight must match the already verified roster.
    /// Unselected contributors still participate in the transcript and cannot be omitted.
    pub fn producer_for_subset(
        &self,
        committee: &Committee,
    ) -> Result<ValidatorId, ConsensusError> {
        committee.total_power()?;
        if self.input.role != VrfRole::Producer
            || committee.height != self.input.height
            || committee
                .members
                .iter()
                .any(|member| !self.members.contains(member))
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut members = committee.members.clone();
        members.sort_by_key(|member| member.id);
        Ok(self.draw(members, 1)?[0].id)
    }

    fn draw(
        &self,
        mut pool: Vec<CommitteeMember>,
        count: usize,
    ) -> Result<Vec<CommitteeMember>, ConsensusError> {
        if count > pool.len() {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut selected = Vec::with_capacity(count);
        for seat in 0..count {
            let total = pool
                .iter()
                .try_fold(0u128, |sum, m| sum.checked_add(m.power.0))
                .ok_or(ConsensusError::InvalidCommittee)?;
            let ticket = draw_ticket(self.randomness, seat as u64, total)?;
            let mut upper = 0u128;
            let index = pool
                .iter()
                .position(|m| {
                    upper += m.power.0;
                    ticket < upper
                })
                .ok_or(ConsensusError::InvalidCommittee)?;
            selected.push(pool.remove(index));
        }
        Ok(selected)
    }

    /// Only the `PoTB` transition may reweight a subset of a fully verified roster.
    /// Keeping the original randomness prevents evidence/admission inclusion from
    /// offering a choice of VRF entropy transcripts to the proposer.
    pub(crate) fn with_policy_weights(
        mut self,
        roster: &[VrfValidator],
    ) -> Result<Self, ConsensusError> {
        let known: BTreeSet<_> = self.members.iter().map(|m| m.id).collect();
        let mut members = BTreeMap::new();
        let mut total = 0u128;
        for validator in roster {
            let id = ValidatorId(crypto::blake2s_hash(&validator.public_key).0);
            if !known.contains(&id)
                || validator.weight.0 == 0
                || members.insert(id, validator.weight).is_some()
            {
                return Err(ConsensusError::InvalidCommittee);
            }
            total = total
                .checked_add(validator.weight.0)
                .ok_or(ConsensusError::InvalidCommittee)?;
        }
        if members.is_empty() {
            return Err(ConsensusError::InvalidCommittee);
        }
        self.members = members
            .into_iter()
            .map(|(id, power)| CommitteeMember { id, power })
            .collect();
        Ok(self)
    }

    pub(crate) fn rotate_eligible(
        &self,
        current: &Committee,
        target: usize,
        count: usize,
    ) -> Result<Committee, ConsensusError> {
        current.total_power()?;
        if self.input.role != VrfRole::Committee
            || current.height.checked_add(1) != Some(self.input.height)
            || target == 0
            || target > self.members.len()
            || count > target
        {
            return Err(ConsensusError::InvalidTransition);
        }
        if current.members.len() != target {
            return self.select(target);
        }
        let mut retained: Vec<_> = current.members[count..]
            .iter()
            .filter_map(|old| self.members.iter().find(|m| m.id == old.id).copied())
            .collect();
        let pool = self
            .members
            .iter()
            .filter(|m| !retained.iter().any(|r| r.id == m.id))
            .copied()
            .collect();
        retained.extend(self.draw(pool, target - retained.len())?);
        Ok(Committee {
            height: self.input.height,
            members: retained,
        })
    }
}

fn draw_ticket(seed: Hash256, seat: u64, total: u128) -> Result<u128, ConsensusError> {
    if total == 0 {
        return Err(ConsensusError::InvalidCommittee);
    }
    // Reject the first 2^128 mod total integers, leaving an exact multiple of
    // total possible values. The bounded retry count fails closed, without bias.
    let threshold = total.wrapping_neg() % total;
    let mut bytes = [0u8; 44];
    bytes[..32].copy_from_slice(&seed.0);
    bytes[32..40].copy_from_slice(&seat.to_le_bytes());
    for attempt in 0..256u32 {
        bytes[40..].copy_from_slice(&attempt.to_le_bytes());
        let hash = domain_hash(b"astrolune.vrf.draw.v1", &bytes);
        let mut value = [0; 16];
        value.copy_from_slice(&hash.0[..16]);
        let value = u128::from_be_bytes(value);
        if value >= threshold {
            return Ok(value % total);
        }
    }
    Err(ConsensusError::InvalidProof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tickets_cover_weighted_intervals_and_full_width_bounds() {
        let mut counts = [0; 4];
        for seat in 0..4096 {
            let ticket = draw_ticket(Hash256([7; 32]), seat, 4).unwrap();
            counts[usize::try_from(ticket).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|count| (850..1200).contains(count)),
            "{counts:?}"
        );
        for total in [1, 2, 3, (1u128 << 127) + 1, u128::MAX] {
            for seat in 0..64 {
                assert!(draw_ticket(Hash256([8; 32]), seat, total).unwrap() < total);
            }
        }
        assert!(draw_ticket(Hash256::ZERO, 0, 0).is_err());
    }
}
