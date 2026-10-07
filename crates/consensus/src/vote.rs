// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! BFT vote types and voting phases.

use codec::{DecodeError, Decoder};
use types::{Hash256, ValidatorId};

/// The two voting phases used by fast `BFT` finality.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VotePhase {
    /// A validator considers the proposal valid for the round.
    Prevote,
    /// A validator locks and commits after observing a prevote quorum.
    Precommit,
}

/// A signed `BFT` vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vote {
    /// Chain identity protected against cross-chain replay.
    pub chain_id: u32,
    /// Commitment to the active height and ordered weighted committee.
    pub committee_root: Hash256,
    /// Target height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Voting phase.
    pub phase: VotePhase,
    /// Proposed block, or `None` for a nil vote.
    pub block: Option<Hash256>,
    /// Committee member that produced the vote.
    pub voter: ValidatorId,
    /// Canonical signature bytes.
    pub signature: [u8; 64],
}

impl Vote {
    /// Signs this exact vote using chain-bound durable signing coordinates.
    ///
    /// The caller must first apply the consensus proposal and locking rules.
    /// The signature is changed only after the signer durably accepts the decision.
    pub fn sign_with(
        &mut self,
        signer: &mut impl keystore::ChainSigner,
        handle: &keystore::KeyHandle,
    ) -> Result<(), keystore::KeystoreError> {
        if self.chain_id != signer.signing_context().chain_id
            || self.voter != signer.validator_id(handle)?
        {
            return Err(keystore::KeystoreError::ContextMismatch);
        }
        let phase = match self.phase {
            VotePhase::Prevote => keystore::PREVOTE_PHASE,
            VotePhase::Precommit => keystore::PRECOMMIT_PHASE,
        };
        self.signature = signer.sign_consensus(
            handle,
            keystore::SigningPosition {
                height: self.height,
                round: self.round,
                phase,
            },
            self.signing_hash(),
        )?;
        Ok(())
    }
    /// Returns the version-1 signing bytes, including explicit nil and phase tags.
    #[must_use]
    pub fn signing_bytes(&self) -> [u8; 122] {
        let mut bytes = [0; 122];
        bytes[..4].copy_from_slice(b"ALVT");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.chain_id.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.round.to_le_bytes());
        bytes[24] = match self.phase {
            VotePhase::Prevote => 0,
            VotePhase::Precommit => 1,
        };
        if let Some(block) = self.block {
            bytes[25] = 1;
            bytes[26..58].copy_from_slice(&block.0);
        }
        bytes[58..90].copy_from_slice(&self.committee_root.0);
        bytes[90..122].copy_from_slice(&self.voter.0);
        bytes
    }

    /// Digest signed with strict Ed25519; the signature itself is excluded.
    #[must_use]
    pub fn signing_hash(&self) -> Hash256 {
        types::hash::domain_hash(types::domain::CONSENSUS_VOTE, &self.signing_bytes())
    }

    /// Fixed-width canonical vote envelope.
    #[must_use]
    pub fn encode(&self) -> [u8; 186] {
        let mut bytes = [0; 186];
        bytes[..122].copy_from_slice(&self.signing_bytes());
        bytes[122..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decodes exactly one envelope, rejecting unknown tags and nonzero nil bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_fixed::<4>()? != *b"ALVT" || decoder.read_u32()? != 1 {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;
        let height = decoder.read_u64()?;
        let round = decoder.read_u32()?;
        let phase = match decoder.read_u8()? {
            0 => VotePhase::Prevote,
            1 => VotePhase::Precommit,
            _ => return Err(DecodeError::Unsupported),
        };
        let present = decoder.read_u8()?;
        let hash = Hash256(decoder.read_fixed()?);
        let block = match present {
            0 if hash == Hash256::ZERO => None,
            1 => Some(hash),
            _ => return Err(DecodeError::NonCanonical),
        };
        let committee_root = Hash256(decoder.read_fixed()?);
        let voter = ValidatorId(decoder.read_fixed()?);
        let signature = decoder.read_fixed()?;
        decoder.finish()?;
        Ok(Self {
            chain_id,
            committee_root,
            height,
            round,
            phase,
            block,
            voter,
            signature,
        })
    }
}
