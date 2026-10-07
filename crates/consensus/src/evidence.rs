// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Portable, independently verifiable double-vote evidence. No economic penalty
//! or committee change is inferred from observing a proof locally.

use crate::{AuthenticatedCommittee, ConsensusError, Vote};
use codec::DecodeError;
use types::{Hash256, ValidatorId};

/// Two distinct, canonically ordered values signed in one exact voting slot.
/// Decoding validates structure only; always verify against trusted membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVoteEvidence {
    first: Vote,
    second: Vote,
}

impl DoubleVoteEvidence {
    /// Fixed-width version-1 evidence size: 8-byte tag/version and two votes.
    pub const ENCODED_LEN: usize = 380;

    /// Authenticates both votes and normalizes their order. A duplicate, nil/nil,
    /// different round/phase, or signature failure is not double-vote evidence.
    pub fn from_votes(
        context: &AuthenticatedCommittee,
        first: Vote,
        second: Vote,
    ) -> Result<Self, ConsensusError> {
        let (first, second) = if first.block < second.block {
            (first, second)
        } else {
            (second, first)
        };
        let proof = Self { first, second };
        proof.verify(context)?;
        Ok(proof)
    }

    fn same_slot(&self) -> bool {
        self.first.chain_id == self.second.chain_id
            && self.first.height == self.second.height
            && self.first.committee_root == self.second.committee_root
            && self.first.round == self.second.round
            && self.first.phase == self.second.phase
            && self.first.voter == self.second.voter
            && self.first.block < self.second.block
    }

    /// Checks both strict Ed25519 signatures and the exact historical committee.
    /// Never obtain that committee's membership/weights from the accused peer.
    pub fn verify(&self, context: &AuthenticatedCommittee) -> Result<(), ConsensusError> {
        if !self.same_slot() {
            return Err(ConsensusError::InvalidTransition);
        }
        context.verify_vote(&self.first)?;
        context.verify_vote(&self.second)?;
        Ok(())
    }

    /// Accused validator. This is untrusted until verification succeeds.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.first.voter
    }

    /// Height whose independently trusted committee must authenticate this proof.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.first.height
    }

    /// Both canonical votes, for inspection or export.
    #[must_use]
    pub const fn votes(&self) -> (&Vote, &Vote) {
        (&self.first, &self.second)
    }

    /// Exact canonical proof. The two signatures are included in its identity.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(b"ALDV");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..194].copy_from_slice(&self.first.encode());
        bytes[194..].copy_from_slice(&self.second.encode());
        bytes
    }

    /// Rejects truncation, trailing bytes, unsupported versions, mismatched
    /// slots and reversed/equal values. Signatures require a separate verify call.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(DecodeError::NonCanonical);
        }
        if &bytes[..8] != b"ALDV\x01\0\0\0" {
            return Err(DecodeError::Unsupported);
        }
        let proof = Self {
            first: Vote::decode(&bytes[8..194])?,
            second: Vote::decode(&bytes[194..])?,
        };
        if !proof.same_slot() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(proof)
    }

    /// Stable identity for the exact proof; invariant under input vote order.
    #[must_use]
    pub fn id(&self) -> Hash256 {
        types::hash::domain_hash(b"astrolune.potb.double-vote.v1", &self.encode())
    }

    /// Identifies the offence slot independently of which conflicting pair proves it.
    /// Useful for deduplicating three or more conflicting values from one signer.
    #[must_use]
    pub fn offence_id(&self) -> Hash256 {
        let mut slot = self.first.clone();
        slot.block = None;
        types::hash::domain_hash(b"astrolune.potb.offence-slot.v1", &slot.signing_bytes())
    }
}
