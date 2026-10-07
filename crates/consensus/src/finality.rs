// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticated, bounded vote aggregation for one fixed committee and height.

use crate::{
    AuthenticatedCommittee, CertificateSignature, ConsensusError, FinalityCertificate, Vote,
    VotePhase,
};
use std::collections::BTreeMap;
use types::{Hash256, ValidatorId};

/// Verification and collection of votes; local voting/locking policy is separate.
pub trait FinalityEngine {
    /// Authenticates a vote before changing quorum accounting.
    fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError>;
    /// Returns a block only after an authenticated precommit quorum exists.
    fn finalized_block(&self) -> Option<Hash256>;
}

/// Collects at most two votes per member in the active round.
///
/// This is a certificate collector, not the local proposal/lock/timeout protocol.
/// An external round controller must implement safe voting and durable signing.
pub struct BftFinalityEngine {
    context: AuthenticatedCommittee,
    round: u32,
    votes: BTreeMap<(ValidatorId, VotePhase), Vote>,
    power: BTreeMap<(VotePhase, Option<Hash256>), u128>,
    certificate: Option<FinalityCertificate>,
    evidence: BTreeMap<ValidatorId, crate::DoubleVoteEvidence>,
}

impl BftFinalityEngine {
    /// Extracts independently verifiable prevote evidence for the active round.
    pub fn prevote_certificate(
        &self,
        block: Hash256,
    ) -> Result<crate::PrevoteCertificate, ConsensusError> {
        let votes = self
            .votes
            .values()
            .filter(|vote| vote.phase == VotePhase::Prevote && vote.block == Some(block))
            .cloned()
            .collect();
        crate::PrevoteCertificate::from_votes(&self.context, votes)
    }
    /// Starts round zero using a validated immutable verification context.
    #[must_use]
    pub fn new(context: AuthenticatedCommittee) -> Self {
        Self::for_round(context, 0)
    }

    /// Starts empty collection at a round restored by a separate durable voter.
    /// No vote history, lock, or authority to advance local voting is inferred.
    #[must_use]
    pub fn for_round(context: AuthenticatedCommittee, round: u32) -> Self {
        Self {
            context,
            round,
            votes: BTreeMap::new(),
            power: BTreeMap::new(),
            certificate: None,
            evidence: BTreeMap::new(),
        }
    }

    /// Trusted verification context for this height.
    #[must_use]
    pub const fn committee(&self) -> &AuthenticatedCommittee {
        &self.context
    }

    /// Current round; votes for other rounds are rejected without retaining them.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Advances one round and releases old vote accounting. Does not unlock a voter.
    pub fn advance_round(&mut self) -> Result<(), ConsensusError> {
        if self.certificate.is_some() {
            return Err(ConsensusError::InvalidTransition);
        }
        let next = self
            .round
            .checked_add(1)
            .ok_or(ConsensusError::InvalidTransition)?;
        self.round = next;
        self.votes.clear();
        self.power.clear();
        Ok(())
    }

    /// First observed quorum, with signatures in canonical validator order.
    #[must_use]
    pub const fn certificate(&self) -> Option<&FinalityCertificate> {
        self.certificate.as_ref()
    }

    /// At most one authenticated double-vote proof per committee member, retained
    /// across round changes in this collector. Callers must export/persist proofs
    /// if they need them beyond this collector's lifetime.
    pub fn evidence(&self) -> impl Iterator<Item = &crate::DoubleVoteEvidence> {
        self.evidence.values()
    }
}

impl FinalityEngine for BftFinalityEngine {
    fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError> {
        if vote.round != self.round {
            return Err(ConsensusError::InvalidTransition);
        }
        let power = self.context.verify_vote(&vote)?;
        let key = (vote.voter, vote.phase);
        if let Some(previous) = self.votes.get(&key) {
            if previous.block != vote.block && !self.evidence.contains_key(&vote.voter) {
                let proof = crate::DoubleVoteEvidence::from_votes(
                    &self.context,
                    previous.clone(),
                    vote.clone(),
                )?;
                self.evidence.insert(vote.voter, proof);
            }
            return Err(if previous.block == vote.block {
                ConsensusError::DuplicateVote
            } else {
                ConsensusError::Equivocation
            });
        }
        if self.certificate.is_some() {
            return Err(ConsensusError::InvalidTransition);
        }
        let power_key = (vote.phase, vote.block);
        let total = self
            .power
            .get(&power_key)
            .copied()
            .unwrap_or(0)
            .checked_add(power)
            .ok_or(ConsensusError::InvalidCommittee)?;
        self.power.insert(power_key, total);
        let phase = vote.phase;
        let block = vote.block;
        self.votes.insert(key, vote);
        if phase == VotePhase::Precommit
            && total >= self.context.quorum()
            && let Some(block) = block
        {
            self.certificate = Some(FinalityCertificate {
                chain_id: self.context.chain_id(),
                height: self.context.height(),
                round: self.round,
                committee_root: self.context.root(),
                block,
                signatures: self
                    .votes
                    .values()
                    .filter(|vote| vote.phase == VotePhase::Precommit && vote.block == Some(block))
                    .map(|vote| CertificateSignature {
                        voter: vote.voter,
                        signature: vote.signature,
                    })
                    .collect(),
            });
        }
        Ok(())
    }

    fn finalized_block(&self) -> Option<Hash256> {
        self.certificate.as_ref().map(|value| value.block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Committee, CommitteeMember, PotbWeight};

    #[test]
    fn round_exhaustion_does_not_wrap_or_clear_votes() {
        let key = crypto::blake2s::ed25519_public_key(&[1; 32]);
        let id = ValidatorId(crypto::blake2s_hash(&key).0);
        let committee = Committee {
            height: 0,
            members: vec![CommitteeMember {
                id,
                power: PotbWeight(1),
            }],
        };
        let mut engine =
            BftFinalityEngine::new(AuthenticatedCommittee::new(7, &committee, &[key]).unwrap());
        engine.round = u32::MAX;
        let mut vote = Vote {
            chain_id: 7,
            committee_root: engine.committee().root(),
            height: 0,
            round: u32::MAX,
            phase: VotePhase::Prevote,
            block: None,
            voter: id,
            signature: [0; 64],
        };
        vote.signature = crypto::blake2s::ed25519_sign(&[1; 32], &vote.signing_hash().0);
        engine.receive_vote(vote.clone()).unwrap();
        assert_eq!(
            engine.advance_round(),
            Err(ConsensusError::InvalidTransition)
        );
        assert_eq!(engine.round(), u32::MAX);
        assert_eq!(
            engine.receive_vote(vote),
            Err(ConsensusError::DuplicateVote)
        );
    }
}
