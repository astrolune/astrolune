// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Complete VRF collection and sequential, old-quorum-authenticated handoffs.
//!
//! These explicit APIs do not activate rotation in a version-1 daemon. A caller
//! must commit the next state under [`committee_state_key`] and retain the full
//! contribution batch. Decoding state alone never establishes its authority.

mod contribution;
mod encoding;
mod handoff;
mod potb;

pub use contribution::{ContributionPool, VrfBatch, VrfContribution};
pub use handoff::{CommitteeHandoff, HandoffVerifier};

use std::collections::{BTreeMap, BTreeSet};

use crypto::{Blake2sProvider, VrfInput, VrfRole};
use genesis::Genesis;
use types::{Hash256, Resources, StateKey, ValidatorId, hash::domain_hash};

use crate::{
    AuthenticatedCommittee, Candidate, Committee, CommitteeMember, ConsensusError, PotbWeight,
    VerifiedVrfSampler, VrfValidator,
};

/// Maximum eligible roster for the bounded private-network handoff format.
pub const MAX_ROTATION_VALIDATORS: usize = 32;

/// Reserved finalized state location for the committee of the following height.
#[must_use]
pub fn committee_state_key() -> StateKey {
    StateKey(types::domain::COMMITTEE_STATE_KEY.to_vec())
}

/// Validated immutable committee state. Authority comes from genesis or a handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeState {
    chain_id: u32,
    genesis: Hash256,
    height: u64,
    randomness: Hash256,
    capacity: Resources,
    target_size: usize,
    rotation_count: usize,
    roster: Vec<VrfValidator>,
    members: Vec<ValidatorId>,
    producer: ValidatorId,
}

impl CommitteeState {
    /// Bootstraps height one with the entire trusted genesis roster.
    /// A smaller target is sampled at the first transition; otherwise partial
    /// rotation replaces the oldest `rotation_count` seats. Keys must exactly
    /// match genesis identities. This constructor does not change genesis state.
    pub fn from_genesis(genesis: &Genesis, keys: &[[u8; 32]]) -> Result<Self, ConsensusError> {
        let hash = genesis
            .commitment()
            .map_err(|_| ConsensusError::InvalidCommittee)?;
        if keys.len() != genesis.validators.len() || keys.len() > MAX_ROTATION_VALIDATORS {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut provider = Blake2sProvider::new();
        let mut registry = BTreeMap::new();
        for key in keys {
            let id = provider
                .register_validator(*key)
                .map_err(|_| ConsensusError::InvalidProof)?;
            if registry.insert(id, *key).is_some() {
                return Err(ConsensusError::InvalidCommittee);
            }
        }
        let roster = genesis
            .validators
            .iter()
            .map(|validator| {
                Ok(VrfValidator {
                    public_key: *registry
                        .get(&validator.id)
                        .ok_or(ConsensusError::InvalidCommittee)?,
                    weight: PotbWeight(validator.weight),
                })
            })
            .collect::<Result<Vec<_>, ConsensusError>>()?;
        let members: Vec<_> = genesis
            .validators
            .iter()
            .map(|validator| validator.id)
            .collect();
        let producer = members[1 % members.len()];
        let result = Self {
            chain_id: genesis.chain_id,
            genesis: hash,
            height: 1,
            randomness: domain_hash(b"astrolune.rotation.genesis.v1", &hash.0),
            capacity: genesis.capacity,
            target_size: genesis.committee_size,
            rotation_count: genesis.rotation_count,
            roster,
            members,
            producer,
        };
        result.validate()?;
        Ok(result)
    }

    /// Exact height for which this committee is authoritative.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Independently trusted genesis commitment.
    #[must_use]
    pub const fn genesis(&self) -> Hash256 {
        self.genesis
    }

    /// Chain identifier bound into contributions and finality signatures.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Fixed capacity authenticated by genesis in this handoff format.
    #[must_use]
    pub const fn capacity(&self) -> Resources {
        self.capacity
    }

    /// Finalized randomness of the preceding complete batch, or genesis anchor.
    #[must_use]
    pub const fn randomness(&self) -> Hash256 {
        self.randomness
    }

    /// Complete registered roster, sorted by derived validator identity.
    #[must_use]
    pub fn roster(&self) -> &[VrfValidator] {
        &self.roster
    }

    /// Ordered active membership with trusted weights, suitable for certificate checks.
    #[must_use]
    pub fn committee(&self) -> Committee {
        let weights: BTreeMap<_, _> = self
            .roster
            .iter()
            .map(|v| (identity(v), v.weight))
            .collect();
        Committee {
            height: self.height,
            members: self
                .members
                .iter()
                .map(|id| CommitteeMember {
                    id: *id,
                    power: weights[id],
                })
                .collect(),
        }
    }

    /// Builds a fixed-height signature verification context from the active seats only.
    pub fn context(&self) -> Result<AuthenticatedCommittee, ConsensusError> {
        let keys: Vec<_> = self
            .roster
            .iter()
            .filter(|v| self.members.contains(&identity(v)))
            .map(|v| v.public_key)
            .collect();
        AuthenticatedCommittee::new(self.chain_id, &self.committee(), &keys)
    }

    /// Weighted VRF producer at round zero, followed by deterministic seat rotation.
    /// Timeout rounds cannot request another VRF lottery.
    ///
    /// # Panics
    /// Panics if internal validated membership invariants are violated.
    #[must_use]
    pub fn proposer(&self, round: u32) -> ValidatorId {
        let initial = self
            .members
            .iter()
            .position(|id| *id == self.producer)
            .expect("validated producer is a member");
        let offset = u64::from(round) % self.members.len() as u64;
        let offset = usize::try_from(offset).expect("at most 32 seats");
        self.members[(initial + offset) % self.members.len()]
    }

    /// Finalized context for the next transition. Both roles use round zero.
    /// Parent randomness comes from the previous full batch, not transaction data
    /// or a caller-supplied block hash that a proposer could vary.
    pub fn input(&self, role: VrfRole) -> Result<VrfInput, ConsensusError> {
        let height = self
            .height
            .checked_add(1)
            .ok_or(ConsensusError::InvalidTransition)?;
        Ok(VrfInput {
            chain_id: self.chain_id,
            genesis: self.genesis,
            epoch: height,
            height,
            parent_randomness: self.randomness,
            round: 0,
            role,
        })
    }

    /// Computes a private candidate next state after checking every contribution.
    /// Missing or invalid proofs abort the transition without modifying this state.
    pub fn transition(&self, batch: &VrfBatch) -> Result<Self, ConsensusError> {
        batch
            .validate_shape()
            .map_err(|_| ConsensusError::InvalidProof)?;
        let committee = self.sampler(batch, VrfRole::Committee)?;
        let producer = self.sampler(batch, VrfRole::Producer)?;
        let selected = if self.members.len() == self.target_size {
            committee.rotate(&self.committee(), self.rotation_count)?
        } else {
            committee.select(self.target_size)?
        };
        let mut transcript = [0; 64];
        transcript[..32].copy_from_slice(&committee.randomness().0);
        transcript[32..].copy_from_slice(&producer.randomness().0);
        let result = Self {
            height: selected.height,
            randomness: domain_hash(b"astrolune.rotation.randomness.v1", &transcript),
            producer: producer.producer_for_subset(&selected)?,
            members: selected.members.iter().map(|member| member.id).collect(),
            ..self.clone()
        };
        result.validate()?;
        Ok(result)
    }

    fn sampler(
        &self,
        batch: &VrfBatch,
        role: VrfRole,
    ) -> Result<VerifiedVrfSampler, ConsensusError> {
        if batch.entries.len() != self.roster.len() {
            return Err(ConsensusError::InvalidCommittee);
        }
        let candidates = self
            .roster
            .iter()
            .zip(&batch.entries)
            .map(|(v, proof)| {
                if identity(v) != proof.validator {
                    return Err(ConsensusError::UnknownVoter);
                }
                Ok(Candidate {
                    id: proof.validator,
                    weight: v.weight,
                    vrf: match role {
                        VrfRole::Committee => &proof.committee,
                        VrfRole::Producer => &proof.producer,
                    }
                    .clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        VerifiedVrfSampler::new(self.input(role)?, &self.roster, &candidates)
    }

    fn validate(&self) -> Result<(), ConsensusError> {
        if self.chain_id == 0
            || self.genesis == Hash256::ZERO
            || self.height == 0
            || self.roster.is_empty()
            || self.roster.len() > MAX_ROTATION_VALIDATORS
            || self.target_size == 0
            || self.target_size > self.roster.len()
            || self.rotation_count > self.target_size
            || self.members.is_empty()
            || self.members.len() > self.roster.len()
            || (self.members.len() != self.target_size && self.height != 1)
            || (self.height == 1 && self.members.len() != self.roster.len())
            || !self.members.contains(&self.producer)
            || [
                self.capacity.compute,
                self.capacity.memory,
                self.capacity.io,
                self.capacity.bandwidth,
            ]
            .contains(&0)
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut provider = Blake2sProvider::new();
        let mut previous = None;
        let mut total = 0u128;
        let mut ids = BTreeSet::new();
        for validator in &self.roster {
            let id = provider
                .register_validator(validator.public_key)
                .map_err(|_| ConsensusError::InvalidProof)?;
            if validator.weight.0 == 0 || previous.is_some_and(|last| last >= id) {
                return Err(ConsensusError::InvalidCommittee);
            }
            total = total
                .checked_add(validator.weight.0)
                .ok_or(ConsensusError::InvalidCommittee)?;
            previous = Some(id);
            ids.insert(id);
        }
        for member in &self.members {
            if !ids.remove(member) {
                return Err(ConsensusError::InvalidCommittee);
            }
        }
        Ok(())
    }
}

fn identity(validator: &VrfValidator) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&validator.public_key).0)
}
