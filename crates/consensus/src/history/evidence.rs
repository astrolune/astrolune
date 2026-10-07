// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! A bounded offence plus an independently anchored historical membership witness.

use super::{CommitteeHistory, CommitteeHistoryProof};
use crate::{
    AuthenticatedCommittee, Committee, CommitteeMember, ConsensusError, DoubleVoteEvidence,
    PotbWeight, VrfValidator,
};
use codec::{DecodeError, Decoder};
use types::ValidatorId;

/// A canonical double vote and its exact historical committee, including public keys.
/// Verifying this bundle proves an offence; policy activation decides its effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalEvidence {
    members: Vec<VrfValidator>,
    history: CommitteeHistoryProof,
    evidence: DoubleVoteEvidence,
}
impl HistoricalEvidence {
    /// Maximum seats in the private-network evidence format.
    pub const MAX_MEMBERS: usize = 32;
    /// Maximum complete bundle, checked before any allocation.
    pub const MAX_BYTES: usize = 13
        + Self::MAX_MEMBERS * 48
        + CommitteeHistoryProof::MAX_BYTES
        + DoubleVoteEvidence::ENCODED_LEN;

    /// Constructs a verified bundle. Keys must be the exact active historical set;
    /// committee seat order is preserved because it is part of its commitment.
    pub fn new(
        trusted: &CommitteeHistory,
        committee: &Committee,
        keys: &[[u8; 32]],
        history: CommitteeHistoryProof,
        evidence: DoubleVoteEvidence,
    ) -> Result<Self, ConsensusError> {
        if committee.members.is_empty()
            || committee.members.len() > Self::MAX_MEMBERS
            || committee.height != history.height()
            || keys.len() != committee.members.len()
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let context = AuthenticatedCommittee::new(trusted.chain_id, committee, keys)?;
        history.verify(trusted, &context)?;
        evidence.verify(&context)?;
        let members = committee
            .members
            .iter()
            .map(|member| {
                let key = keys
                    .iter()
                    .find(|key| identity(key) == member.id)
                    .ok_or(ConsensusError::UnknownVoter)?;
                Ok(VrfValidator {
                    public_key: *key,
                    weight: member.power,
                })
            })
            .collect::<Result<Vec<_>, ConsensusError>>()?;
        Ok(Self {
            members,
            history,
            evidence,
        })
    }

    /// Verifies membership against caller-authenticated history, then both signatures.
    /// Peer-supplied membership and decoded frontier bytes cannot bootstrap trust.
    pub fn verify(&self, trusted: &CommitteeHistory) -> Result<(), ConsensusError> {
        let context = self.context()?;
        self.history.verify(trusted, &context)?;
        self.evidence.verify(&context)
    }

    /// The portable offence. Its economic meaning is defined by the activated policy.
    #[must_use]
    pub const fn evidence(&self) -> &DoubleVoteEvidence {
        &self.evidence
    }

    fn context(&self) -> Result<AuthenticatedCommittee, ConsensusError> {
        if self.members.is_empty()
            || self.members.len() > Self::MAX_MEMBERS
            || self.history.height() != self.evidence.height()
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        let committee = Committee {
            height: self.history.height(),
            members: self
                .members
                .iter()
                .map(|member| CommitteeMember {
                    id: identity(&member.public_key),
                    power: member.weight,
                })
                .collect(),
        };
        let keys: Vec<_> = self.members.iter().map(|m| m.public_key).collect();
        AuthenticatedCommittee::new(self.evidence.votes().0.chain_id, &committee, &keys)
    }

    /// Exact framing with historical seat order; signatures still need verification.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.context().map_err(|_| DecodeError::NonCanonical)?;
        let proof = self.history.to_bytes()?;
        let mut bytes = b"ALHDEV01".to_vec();
        bytes.push(u8::try_from(self.members.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for member in &self.members {
            bytes.extend_from_slice(&member.public_key);
            bytes.extend_from_slice(&member.weight.0.to_le_bytes());
        }
        bytes.extend_from_slice(
            &u32::try_from(proof.len())
                .map_err(|_| DecodeError::LimitExceeded)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&proof);
        bytes.extend_from_slice(&self.evidence.encode());
        Ok(bytes)
    }

    /// Preflights complete sizes, keys, weights, path shape and exact offence framing.
    /// Successful decoding is not evidence authentication.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALHDEV01" {
            return Err(DecodeError::Unsupported);
        }
        let count = usize::from(decoder.read_u8()?);
        if count == 0 || count > Self::MAX_MEMBERS {
            return Err(DecodeError::LimitExceeded);
        }
        let member_bytes = decoder.read_exact(count * 48)?;
        let length =
            usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::LengthOverflow)?;
        if length > CommitteeHistoryProof::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let proof_bytes = decoder.read_exact(length)?;
        let evidence_bytes = decoder.read_exact(DoubleVoteEvidence::ENCODED_LEN)?;
        decoder.finish()?;
        let mut records = Decoder::new(member_bytes);
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(VrfValidator {
                public_key: records.read_fixed()?,
                weight: PotbWeight(u128::from_le_bytes(records.read_fixed()?)),
            });
        }
        let result = Self {
            members,
            history: CommitteeHistoryProof::from_bytes(proof_bytes)?,
            evidence: DoubleVoteEvidence::decode(evidence_bytes)?,
        };
        result.context().map_err(|_| DecodeError::NonCanonical)?;
        Ok(result)
    }
}
fn identity(key: &[u8; 32]) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(key).0)
}
