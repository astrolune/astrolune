// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit `PoTB` transition profile: committed evidence, age, admission and handoff.
//!
//! This library profile has its own configuration commitment. Genesis-v1/v2
//! daemons do not opt into it. Staging is not publication: callers must execute
//! application state, verify old-quorum finality and durably commit together.

mod batch;
mod configuration;
mod encoding;
mod handoff;

pub use batch::PotbBatch;
pub use configuration::PotbConfiguration;
pub use handoff::{PotbHandoff, PotbVerifier};

use crate::{
    ConsensusError, VrfValidator,
    history::CommitteeHistory,
    potb::PotbPolicy,
    rotation::{CommitteeState, MAX_ROTATION_VALIDATORS},
};
use std::collections::BTreeMap;
use types::{Hash256, StateKey, ValidatorId};

/// Reserved location of the complete next `PoTB` authority and history frontier.
#[must_use]
pub fn potb_state_key() -> StateKey {
    StateKey(types::domain::POTB_STATE_KEY.to_vec())
}

/// A permanent bounded identity record; excluded keys cannot reset their age or ban.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PotbRecord {
    /// Strong canonical Ed25519 public key.
    pub public_key: [u8; 32],
    /// Inclusion height of admission; zero for initial members.
    pub admitted_at: u64,
    /// Finalized active-committee membership, independent of certificate omissions.
    pub eligible_blocks: u64,
    /// First canonically included offence, permanently excluding this identity.
    pub disqualification: Option<Hash256>,
}

/// Bounded immutable authority for one height. Deserialization establishes no trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbState {
    committee: CommitteeState,
    policy: PotbPolicy,
    history: CommitteeHistory,
    records: BTreeMap<ValidatorId, PotbRecord>,
    last_batch: Hash256,
    governance: Option<crate::governance::GovernanceState>,
}

impl PotbState {
    /// Bootstraps only from an explicitly supplied `PoTB` configuration and exact keys.
    pub fn from_configuration(
        config: &PotbConfiguration,
        keys: &[[u8; 32]],
    ) -> Result<Self, ConsensusError> {
        let committee = CommitteeState::from_genesis(config.genesis(), keys)?
            .bind_potb_namespace(config.commitment());
        let records = committee
            .roster()
            .iter()
            .map(|v| {
                (
                    identity(&v.public_key),
                    PotbRecord {
                        public_key: v.public_key,
                        admitted_at: 0,
                        eligible_blocks: 0,
                        disqualification: None,
                    },
                )
            })
            .collect();
        let result = Self {
            history: CommitteeHistory::new(committee.chain_id(), committee.genesis())?,
            committee,
            policy: config.policy(),
            records,
            last_batch: Hash256::ZERO,
            governance: config
                .governance()
                .map(|policy| {
                    crate::governance::GovernanceState::new(
                        policy,
                        crate::governance::NetworkParameters {
                            capacity: config.genesis().capacity,
                            prices: types::Resources {
                                compute: 1,
                                ..types::Resources::ZERO
                            },
                        },
                    )
                })
                .transpose()?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Current fixed-height committee, roster, VRF input and admission signing context.
    #[must_use]
    pub const fn committee(&self) -> &CommitteeState {
        &self.committee
    }

    /// Current parameters and any authenticated next-epoch update.
    #[must_use]
    pub const fn governance(&self) -> Option<&crate::governance::GovernanceState> {
        self.governance.as_ref()
    }

    /// Format-specific resource bound; legacy charging stays byte-for-byte unchanged.
    #[must_use]
    pub const fn encoded_bound(&self) -> usize {
        if self.governance.is_some() {
            Self::MAX_BYTES
        } else {
            Self::LEGACY_MAX_BYTES
        }
    }

    /// History of outgoing committees committed in the preceding finalized state.
    #[must_use]
    pub const fn history(&self) -> &CommitteeHistory {
        &self.history
    }

    /// Exact policy selected by the independently trusted configuration.
    #[must_use]
    pub const fn policy(&self) -> PotbPolicy {
        self.policy
    }

    /// Permanent records in increasing derived-identity order.
    pub fn records(&self) -> impl Iterator<Item = (ValidatorId, PotbRecord)> + '_ {
        self.records.iter().map(|(id, record)| (*id, *record))
    }

    /// Canonical batch committed by the last transition; zero only at bootstrap.
    #[must_use]
    pub const fn last_batch(&self) -> Hash256 {
        self.last_batch
    }

    /// Stages a complete transition against the caller's independently trusted parent.
    /// Evidence is authenticated by the parent history, approvals by the unchanged
    /// incumbent committee. Failure cannot mutate this state. The returned candidate
    /// is not authority until execution and old-quorum finality commit it together.
    pub fn stage(&self, parent: Hash256, batch: &PotbBatch) -> Result<Self, ConsensusError> {
        if parent == Hash256::ZERO {
            return Err(ConsensusError::InvalidTransition);
        }
        let batch_id = batch
            .commitment()
            .map_err(|_| ConsensusError::InvalidProof)?;
        if self
            .records
            .len()
            .checked_add(batch.admissions().len())
            .is_none_or(|n| n > MAX_ROTATION_VALIDATORS)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        let mut records = self.records.clone();
        for id in self.committee.context()?.members() {
            let record = records.get_mut(&id).ok_or(ConsensusError::UnknownVoter)?;
            record.eligible_blocks = record
                .eligible_blocks
                .checked_add(1)
                .ok_or(ConsensusError::InvalidTransition)?;
        }
        for bundle in batch.evidence() {
            bundle.verify(&self.history)?;
            let evidence = bundle.evidence();
            let record = records
                .get_mut(&evidence.voter())
                .ok_or(ConsensusError::UnknownVoter)?;
            if record.disqualification.is_some() || evidence.height() <= record.admitted_at {
                return Err(ConsensusError::InvalidTransition);
            }
            record.disqualification = Some(evidence.offence_id());
        }
        for certificate in batch.admissions() {
            certificate.verify(&self.committee, parent)?;
            let request = certificate.request();
            if records
                .insert(
                    request.candidate(),
                    PotbRecord {
                        public_key: request.intent().public_key,
                        admitted_at: self.committee.height(),
                        eligible_blocks: 0,
                        disqualification: None,
                    },
                )
                .is_some()
            {
                return Err(ConsensusError::InvalidTransition);
            }
        }
        let roster = weighted_roster(self.policy, &records)?;
        let mut committee = self
            .committee
            .transition_potb(batch.contributions(), roster)?;
        let governance = match &self.governance {
            Some(current) => Some(current.stage(&self.committee, parent, batch.governance())?),
            None if batch.governance().is_some() => return Err(ConsensusError::InvalidTransition),
            None => None,
        };
        if let Some(parameters) = &governance {
            committee = committee.with_potb_capacity(parameters.active().capacity)?;
        }
        let mut history = self.history.clone();
        history.append(&self.committee.context()?)?;
        let result = Self {
            committee,
            policy: self.policy,
            history,
            records,
            last_batch: batch_id,
            governance,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), ConsensusError> {
        configuration::validate_policy(self.policy)?;
        let height = self.committee.height();
        if let Some(governance) = &self.governance {
            governance.validate(height)?;
            if governance.active().capacity != self.committee.capacity() {
                return Err(ConsensusError::InvalidTransition);
            }
        }
        if self.records.is_empty()
            || self.records.len() > MAX_ROTATION_VALIDATORS
            || self.history.entries().checked_add(1) != Some(height)
            || self.history.chain_id() != self.committee.chain_id()
            || self.history.genesis() != self.committee.genesis()
            || (self.last_batch == Hash256::ZERO) != (height == 1)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        let mut provider = crypto::Blake2sProvider::new();
        for (id, record) in &self.records {
            if provider
                .register_validator(record.public_key)
                .map_err(|_| ConsensusError::InvalidProof)?
                != *id
                || record.admitted_at >= height
                || record.eligible_blocks > height - 1 - record.admitted_at
                || record.disqualification == Some(Hash256::ZERO)
                || (height == 1 && record.disqualification.is_some())
            {
                return Err(ConsensusError::InvalidTransition);
            }
        }
        if weighted_roster(self.policy, &self.records)? != self.committee.roster() {
            return Err(ConsensusError::InvalidCommittee);
        }
        Ok(())
    }
}

fn weighted_roster(
    policy: PotbPolicy,
    records: &BTreeMap<ValidatorId, PotbRecord>,
) -> Result<Vec<VrfValidator>, ConsensusError> {
    records
        .values()
        .filter(|record| record.disqualification.is_none())
        .map(|record| {
            Ok(VrfValidator {
                public_key: record.public_key,
                weight: policy.score(record.eligible_blocks, false)?,
            })
        })
        .collect()
}

fn identity(key: &[u8; 32]) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(key).0)
}
