// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Internal bridge for the explicitly separate `PoTB` transition profile.

use super::{CommitteeState, VrfBatch, identity};
use crate::{ConsensusError, VrfValidator};
use crypto::VrfRole;
use types::{Hash256, hash::domain_hash};

impl CommitteeState {
    pub(crate) fn with_potb_capacity(
        mut self,
        capacity: types::Resources,
    ) -> Result<Self, ConsensusError> {
        self.capacity = capacity;
        self.validate()?;
        Ok(self)
    }
    pub(crate) fn bind_potb_namespace(mut self, genesis: Hash256) -> Self {
        self.genesis = genesis;
        self.randomness = domain_hash(b"astrolune.potb.randomness.genesis.v1", &genesis.0);
        self
    }

    /// Contributions and entropy always cover the complete parent roster. Policy
    /// changes affect eligible seats/weights, never the entropy transcript. New
    /// admissions wait one transition before contributing or winning a seat.
    pub(crate) fn transition_potb(
        &self,
        batch: &VrfBatch,
        roster: Vec<VrfValidator>,
    ) -> Result<Self, ConsensusError> {
        batch
            .validate_shape()
            .map_err(|_| ConsensusError::InvalidProof)?;
        let committee = self.sampler(batch, VrfRole::Committee)?;
        let producer = self.sampler(batch, VrfRole::Producer)?;
        let mut transcript = [0; 64];
        transcript[..32].copy_from_slice(&committee.randomness().0);
        transcript[32..].copy_from_slice(&producer.randomness().0);
        let eligible: Vec<_> = roster
            .iter()
            .filter(|v| self.roster.iter().any(|old| identity(old) == identity(v)))
            .copied()
            .collect();
        let committee = committee.with_policy_weights(&eligible)?;
        let producer = producer.with_policy_weights(&eligible)?;
        let selected =
            committee.rotate_eligible(&self.committee(), self.target_size, self.rotation_count)?;
        let result = Self {
            height: selected.height,
            randomness: domain_hash(b"astrolune.potb.randomness.v1", &transcript),
            producer: producer.producer_for_subset(&selected)?,
            members: selected.members.iter().map(|m| m.id).collect(),
            roster,
            ..self.clone()
        };
        result.validate()?;
        Ok(result)
    }
}
