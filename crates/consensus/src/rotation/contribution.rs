// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded, context-bound contribution collection with no partial-roster fallback.

use std::collections::BTreeMap;

use codec::{DecodeError, Decoder};
use crypto::{VrfOutput, VrfRole};
use types::ValidatorId;

use super::{CommitteeState, MAX_ROTATION_VALIDATORS, identity};
use crate::ConsensusError;

/// Both independent role proofs from one registered validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VrfContribution {
    /// Identity derived from a trusted registered public key.
    pub validator: ValidatorId,
    /// Proof for the next committee draw.
    pub committee: VrfOutput,
    /// Proof for the next producer draw.
    pub producer: VrfOutput,
}

impl VrfContribution {
    /// Exact canonical encoded size.
    pub const BYTES: usize = 280;

    /// Encodes both canonical VRF envelopes; does not establish their authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        let mut bytes = b"ALVRFC01".to_vec();
        bytes.extend_from_slice(&self.validator.0);
        bytes.extend_from_slice(
            &self
                .committee
                .encode()
                .map_err(|_| DecodeError::NonCanonical)?,
        );
        bytes.extend_from_slice(
            &self
                .producer
                .encode()
                .map_err(|_| DecodeError::NonCanonical)?,
        );
        Ok(bytes)
    }

    /// Decodes exact bytes without tolerating alternate proof encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::NonCanonical);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALVRFC01" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            validator: ValidatorId(decoder.read_fixed()?),
            committee: VrfOutput::decode(decoder.read_exact(120)?)
                .map_err(|_| DecodeError::NonCanonical)?,
            producer: VrfOutput::decode(decoder.read_exact(120)?)
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        decoder.finish()?;
        Ok(result)
    }

    /// Verifies both role proofs against exactly one immutable transition context.
    pub fn verify(&self, current: &CommitteeState) -> Result<(), ConsensusError> {
        let validator = current
            .roster
            .iter()
            .find(|v| identity(v) == self.validator)
            .ok_or(ConsensusError::UnknownVoter)?;
        for (role, proof) in [
            (VrfRole::Committee, &self.committee),
            (VrfRole::Producer, &self.producer),
        ] {
            crypto::vrf::verify_vrf(&validator.public_key, current.input(role)?.seed(), proof)
                .map_err(|_| ConsensusError::InvalidProof)?;
        }
        Ok(())
    }
}

/// Canonically ordered contribution batch; completeness requires a trusted roster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VrfBatch {
    pub(super) entries: Vec<VrfContribution>,
}

impl VrfBatch {
    /// Maximum encoded size, checked before any decoder allocation.
    pub const MAX_BYTES: usize = 9 + VrfContribution::BYTES * MAX_ROTATION_VALIDATORS;

    /// Canonicalizes arrival order and rejects empty, duplicate or oversized input.
    pub fn new(mut entries: Vec<VrfContribution>) -> Result<Self, DecodeError> {
        if entries.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        entries.sort_by_key(|entry| entry.validator);
        let result = Self { entries };
        result.validate_shape()?;
        Ok(result)
    }

    /// Immutable canonical contribution order.
    #[must_use]
    pub fn entries(&self) -> &[VrfContribution] {
        &self.entries
    }

    pub(super) fn validate_shape(&self) -> Result<(), DecodeError> {
        if self.entries.is_empty() || self.entries.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].validator >= pair[1].validator)
            || self.entries.iter().any(|entry| {
                entry.committee.proof.len() != crypto::vrf::VRF_PROOF_BYTES
                    || entry.producer.proof.len() != crypto::vrf::VRF_PROOF_BYTES
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Encodes canonical proofs and identity order with fixed-width count framing.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let mut bytes = b"ALVRFB01".to_vec();
        bytes.push(u8::try_from(self.entries.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes()?);
        }
        Ok(bytes)
    }

    /// Rejects noncanonical ordering and validates all lengths before allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALVRFB01" {
            return Err(DecodeError::Unsupported);
        }
        let count = usize::from(decoder.read_u8()?);
        if count == 0 || count > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        let entries = decoder.read_exact(count * VrfContribution::BYTES)?;
        decoder.finish()?;
        let result = Self {
            entries: entries
                .as_chunks::<{ VrfContribution::BYTES }>()
                .0
                .iter()
                .map(|chunk| VrfContribution::from_bytes(chunk))
                .collect::<Result<_, _>>()?,
        };
        result.validate_shape()?;
        Ok(result)
    }
}

/// At most 32 verified contributions for one finalized context.
/// This volatile collector must be recreated after a height change; callers may
/// persist its canonical entries and reinsert them with full verification.
pub struct ContributionPool {
    current: CommitteeState,
    entries: BTreeMap<ValidatorId, VrfContribution>,
}

impl ContributionPool {
    /// Starts an empty pool from an independently authenticated committee state.
    #[must_use]
    pub fn new(current: CommitteeState) -> Self {
        Self {
            current,
            entries: BTreeMap::new(),
        }
    }

    /// Inserts only after both proofs verify. Identical replay is idempotent.
    /// An invalid replacement cannot evict an earlier valid contribution.
    pub fn insert(&mut self, entry: VrfContribution) -> Result<bool, ConsensusError> {
        if self.entries.get(&entry.validator) == Some(&entry) {
            return Ok(false);
        }
        entry.verify(&self.current)?;
        if self.entries.contains_key(&entry.validator) {
            return Err(ConsensusError::InvalidProof);
        }
        self.entries.insert(entry.validator, entry);
        Ok(true)
    }

    /// Verified entries for bounded gossip; order is canonical and duplicates are absent.
    pub fn entries(&self) -> impl Iterator<Item = &VrfContribution> {
        self.entries.values()
    }

    /// Registered validators whose proofs are still unavailable, in identity order.
    #[must_use]
    pub fn missing(&self) -> Vec<ValidatorId> {
        self.current
            .roster
            .iter()
            .map(identity)
            .filter(|id| !self.entries.contains_key(id))
            .collect()
    }

    /// Returns the full batch only; never creates a lottery from an available subset.
    pub fn complete(&self) -> Result<VrfBatch, ConsensusError> {
        if self.entries.len() != self.current.roster.len() {
            return Err(ConsensusError::InvalidCommittee);
        }
        VrfBatch::new(self.entries.values().cloned().collect())
            .map_err(|_| ConsensusError::InvalidProof)
    }
}
