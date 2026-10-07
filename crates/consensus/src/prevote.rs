// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independently verified evidence of a non-nil prevote quorum.

use crate::{AuthenticatedCommittee, ConsensusError, MAX_COMMITTEE_MEMBERS, Vote, VotePhase};
use types::Hash256;

/// Verified, canonical prevotes for one block and round; never a finality proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrevoteCertificate {
    votes: Vec<Vote>,
}

impl PrevoteCertificate {
    /// Verifies every signature and the strict weighted quorum. Input is sorted by voter.
    pub fn from_votes(
        context: &AuthenticatedCommittee,
        votes: Vec<Vote>,
    ) -> Result<Self, ConsensusError> {
        if votes.is_empty()
            || votes.len() > MAX_COMMITTEE_MEMBERS
            || votes.windows(2).any(|pair| pair[0].voter >= pair[1].voter)
        {
            return Err(ConsensusError::InvalidCertificate);
        }
        let first = &votes[0];
        if first.block.is_none() {
            return Err(ConsensusError::InvalidCertificate);
        }
        let mut total = 0u128;
        for vote in &votes {
            if vote.phase != VotePhase::Prevote
                || vote.round != first.round
                || vote.block != first.block
            {
                return Err(ConsensusError::InvalidCertificate);
            }
            total = total
                .checked_add(context.verify_vote(vote)?)
                .ok_or(ConsensusError::InvalidCertificate)?;
        }
        if total < context.quorum() {
            return Err(ConsensusError::InvalidCertificate);
        }
        Ok(Self { votes })
    }

    /// Exact round whose prevotes establish this proof.
    #[must_use]
    pub fn round(&self) -> u32 {
        self.votes[0].round
    }

    /// Block hash supported by the quorum.
    #[must_use]
    pub fn block(&self) -> Hash256 {
        self.votes[0].block.unwrap_or(Hash256::ZERO)
    }

    /// Confirms the proof belongs to this immutable chain, height, and committee.
    pub fn verify_context(&self, context: &AuthenticatedCommittee) -> Result<(), ConsensusError> {
        let first = &self.votes[0];
        if first.chain_id != context.chain_id()
            || first.height != context.height()
            || first.committee_root != context.root()
        {
            return Err(ConsensusError::InvalidCertificate);
        }
        Ok(())
    }

    /// Version-1 bounded proof: magic/version/count, followed by exact vote envelopes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.votes.len() * 186);
        bytes.extend_from_slice(b"ALPV");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(self.votes.len()).unwrap_or(0).to_le_bytes());
        for vote in &self.votes {
            bytes.extend_from_slice(&vote.encode());
        }
        bytes
    }

    /// Decodes and authenticates the entire proof before exposing a trusted value.
    pub fn decode(context: &AuthenticatedCommittee, bytes: &[u8]) -> Result<Self, ConsensusError> {
        let parse = || -> Result<Vec<Vote>, codec::DecodeError> {
            if bytes.len() > 12 + 186 * MAX_COMMITTEE_MEMBERS {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let mut decoder = codec::Decoder::new(bytes);
            if decoder.read_fixed::<4>()? != *b"ALPV" || decoder.read_u32()? != 1 {
                return Err(codec::DecodeError::Unsupported);
            }
            let count = usize::try_from(decoder.read_u32()?)
                .map_err(|_| codec::DecodeError::LimitExceeded)?;
            if count == 0 || count > MAX_COMMITTEE_MEMBERS || decoder.remaining() != 186 * count {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let mut votes = Vec::with_capacity(count);
            for _ in 0..count {
                votes.push(Vote::decode(decoder.read_exact(186)?)?);
            }
            decoder.finish()?;
            Ok(votes)
        };
        Self::from_votes(
            context,
            parse().map_err(|_| ConsensusError::InvalidCertificate)?,
        )
    }
}
