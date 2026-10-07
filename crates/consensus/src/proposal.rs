// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Signed proposal metadata; block bodies and verified prevote evidence travel separately.

use crate::{AuthenticatedCommittee, ConsensusError, PrevoteCertificate};
use codec::{DecodeError, Decoder};
use types::{Hash256, ValidatorId};

/// Authenticated proposer statement for one block and round.
///
/// Decoding establishes canonical shape only. Membership, designation, signature,
/// block execution, and any claimed valid-round evidence must also be verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    /// Chain identifier.
    pub chain_id: u32,
    /// Independently trusted genesis commitment.
    pub genesis: Hash256,
    /// Proposed height.
    pub height: u64,
    /// Proposal round.
    pub round: u32,
    /// Active committee commitment.
    pub committee_root: Hash256,
    /// Exact canonical block header hash.
    pub block: Hash256,
    /// Designated committee member.
    pub proposer: ValidatorId,
    /// Earlier round with a verified prevote quorum, when reproposing a value.
    pub valid_round: Option<u32>,
    /// Ed25519 signature over the domain-separated signing digest.
    pub signature: [u8; 64],
}

impl Proposal {
    /// Canonical metadata covered by the signature.
    #[must_use]
    pub fn signing_bytes(&self) -> [u8; 157] {
        let mut bytes = [0; 157];
        bytes[..4].copy_from_slice(b"ALPR");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.chain_id.to_le_bytes());
        bytes[12..44].copy_from_slice(&self.genesis.0);
        bytes[44..52].copy_from_slice(&self.height.to_le_bytes());
        bytes[52..56].copy_from_slice(&self.round.to_le_bytes());
        bytes[56..88].copy_from_slice(&self.committee_root.0);
        bytes[88..120].copy_from_slice(&self.block.0);
        bytes[120..152].copy_from_slice(&self.proposer.0);
        if let Some(round) = self.valid_round {
            bytes[152] = 1;
            bytes[153..].copy_from_slice(&round.to_le_bytes());
        }
        bytes
    }

    /// Digest signed by the protected proposal journal phase.
    #[must_use]
    pub fn signing_hash(&self) -> Hash256 {
        types::hash::domain_hash(types::domain::CONSENSUS_PROPOSAL, &self.signing_bytes())
    }

    /// Fixed-width version-1 envelope; no proof or block allocation is needed.
    #[must_use]
    pub fn encode(&self) -> [u8; 221] {
        let mut bytes = [0; 221];
        bytes[..157].copy_from_slice(&self.signing_bytes());
        bytes[157..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decodes exactly one canonical envelope, rejecting unsupported or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_fixed::<4>()? != *b"ALPR" || decoder.read_u32()? != 1 {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;
        let genesis = Hash256(decoder.read_fixed()?);
        let height = decoder.read_u64()?;
        let round = decoder.read_u32()?;
        let committee_root = Hash256(decoder.read_fixed()?);
        let block = Hash256(decoder.read_fixed()?);
        let proposer = ValidatorId(decoder.read_fixed()?);
        let flag = decoder.read_u8()?;
        let value = decoder.read_u32()?;
        let valid_round = match flag {
            0 if value == 0 => None,
            1 if value < round => Some(value),
            _ => return Err(DecodeError::NonCanonical),
        };
        let signature = decoder.read_fixed()?;
        decoder.finish()?;
        Ok(Self {
            chain_id,
            genesis,
            height,
            round,
            committee_root,
            block,
            proposer,
            valid_round,
            signature,
        })
    }

    /// Checks that the attached verified proof exactly supports the signed claim.
    /// The signature commits to the round/value, not a particular quorum subset.
    pub fn verify_valid_round(
        &self,
        committee: &AuthenticatedCommittee,
        proof: Option<&PrevoteCertificate>,
    ) -> Result<(), ConsensusError> {
        match (self.valid_round, proof) {
            (None, None) => Ok(()),
            (Some(round), Some(proof))
                if round < self.round && round == proof.round() && self.block == proof.block() =>
            {
                proof.verify_context(committee)
            }
            _ => Err(ConsensusError::InvalidCertificate),
        }
    }
}
