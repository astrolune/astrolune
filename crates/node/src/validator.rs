// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit reference round-robin participant; transport and timer scheduling are external.

use crate::{BlockProducer, BlockProposal, ProducerError};
use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, ConsensusError, FinalityCertificate, FinalityEngine,
    LocalBft, LocalBftError, PrevoteCertificate, Proposal, Vote, VotingStep,
};
use storage::{Checkpoint, NodeStorage};
use types::{Transaction, ValidatorId};

/// Full locally available proposal with its signature and optional verified evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlockProposal {
    /// Canonical signed consensus metadata.
    pub envelope: Proposal,
    /// Body and execution commitments checked before voting.
    pub proposal: BlockProposal,
    /// Evidence matching the signed valid-round claim.
    pub valid_round: Option<PrevoteCertificate>,
}

/// Snapshot identifying the only timeout this participant may currently accept.
/// Timer duration, monotonic clock handling, and quorum-based scheduling are external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutEvent {
    /// Height prevents delayed timers from affecting a later participant.
    pub height: u64,
    /// Round prevents delayed timers from affecting a later round.
    pub round: u32,
    /// Step prevents a proposal timeout from being interpreted as a prevote timeout.
    pub step: VotingStep,
}

/// Failures preserve the durable signing rules and existing atomic commit contract.
#[derive(Debug)]
pub enum ValidatorError {
    /// Consensus, proof, or durable signing failure.
    Voting(LocalBftError),
    /// Execution, admission, or storage failure.
    Production(ProducerError),
}
impl std::fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Voting(error) => write!(f, "{error}"),
            Self::Production(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for ValidatorError {}
impl From<LocalBftError> for ValidatorError {
    fn from(error: LocalBftError) -> Self {
        Self::Voting(error)
    }
}
impl From<ConsensusError> for ValidatorError {
    fn from(error: ConsensusError) -> Self {
        Self::Voting(error.into())
    }
}
impl From<ProducerError> for ValidatorError {
    fn from(error: ProducerError) -> Self {
        Self::Production(error)
    }
}

/// One-height participant coordinating execution, durable voting, evidence, and commit.
///
/// Construction explicitly opts into reference round-robin designation over committed
/// seat order. This is not the planned weighted VRF policy and is not used implicitly
/// by the daemon. Outgoing proposals/votes are returned to the caller for delivery;
/// local outgoing votes are already counted. At most one proposal and one round's
/// votes are retained. Recovery restores local safety, not peer messages or an outbox.
pub struct RoundRobinValidator {
    producer: BlockProducer,
    local: LocalBft,
    collector: BftFinalityEngine,
    proposal: Option<SignedBlockProposal>,
    committed: bool,
}

impl RoundRobinValidator {
    /// Verified double-vote proofs retained by this height's vote collector.
    pub fn evidence(&self) -> impl Iterator<Item = &consensus::DoubleVoteEvidence> {
        self.collector.evidence()
    }
    /// Binds a recovered signer, execution state, and independently trusted committee.
    /// The caller authenticates the checkpoint/genesis before constructing the producer.
    pub fn new(
        producer: BlockProducer,
        local: LocalBft,
        committee: AuthenticatedCommittee,
    ) -> Result<Self, ValidatorError> {
        if producer.height() != committee.height()
            || producer.chain_id() != committee.chain_id()
            || local.committee().chain_id() != committee.chain_id()
            || local.committee().root() != committee.root()
            || local.committee().height() != committee.height()
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let collector = BftFinalityEngine::for_round(committee, local.round());
        Ok(Self {
            producer,
            local,
            collector,
            proposal: None,
            committed: false,
        })
    }

    /// Read-only execution and committed-state view.
    #[must_use]
    pub const fn producer(&self) -> &BlockProducer {
        &self.producer
    }

    /// Local round/lock/step view without exposing mutable signing state.
    #[must_use]
    pub const fn local(&self) -> &LocalBft {
        &self.local
    }

    /// Returns the shared reference designation for the current round.
    #[must_use]
    pub fn proposer(&self) -> ValidatorId {
        self.producer.active_committee_state().map_or_else(
            || {
                self.local
                    .committee()
                    .round_robin_proposer(self.local.round())
            },
            |current| current.proposer(self.local.round()),
        )
    }

    pub(crate) fn producer_mut(&mut self) -> &mut BlockProducer {
        &mut self.producer
    }

    /// Admits a transaction against committed execution state.
    pub fn submit_transaction(&mut self, transaction: Transaction) -> Result<(), ValidatorError> {
        if self.committed {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.producer.submit_transaction(transaction)?;
        Ok(())
    }

    /// Prepares and durably signs a fresh value if this validator is designated.
    /// The returned message must also be passed to `accept_proposal` to prevote.
    pub fn propose(&mut self) -> Result<SignedBlockProposal, ValidatorError> {
        self.ensure_voting()?;
        let proposal = self
            .producer
            .produce_block_for_committee(self.local.committee())?;
        self.sign_proposal(proposal, None)
    }

    /// Reproposes an available, revalidated value with earlier-round prevote evidence.
    pub fn repropose(
        &mut self,
        proposal: BlockProposal,
        proof: PrevoteCertificate,
    ) -> Result<SignedBlockProposal, ValidatorError> {
        self.sign_proposal(proposal, Some(proof))
    }

    fn sign_proposal(
        &mut self,
        proposal: BlockProposal,
        proof: Option<PrevoteCertificate>,
    ) -> Result<SignedBlockProposal, ValidatorError> {
        self.ensure_voting()?;
        let expected = self.proposer();
        let producer = &self.producer;
        let envelope =
            self.local
                .propose(expected, &proposal.block.header, proof.as_ref(), |_| {
                    producer.validate_proposal(&proposal).is_ok()
                })?;
        Ok(SignedBlockProposal {
            envelope,
            proposal,
            valid_round: proof,
        })
    }

    /// Authenticates designation/evidence, validates execution, and returns a durable vote.
    /// An invalid transition votes nil; invalid authentication consumes no signing slot.
    pub fn accept_proposal(
        &mut self,
        proposal: &SignedBlockProposal,
    ) -> Result<Vote, ValidatorError> {
        self.ensure_voting()?;
        let expected = self.proposer();
        let producer = &self.producer;
        let mut valid = false;
        let vote = self.local.prevote_proposal(
            expected,
            &proposal.envelope,
            &proposal.proposal.block.header,
            proposal.valid_round.as_ref(),
            |_| {
                valid = producer.validate_proposal(&proposal.proposal).is_ok();
                valid
            },
        )?;
        self.record_outgoing(vote.clone())?;
        if valid {
            self.proposal = Some(proposal.clone());
        }
        Ok(vote)
    }

    /// Restores an authenticated, re-executed body after a durable vote and restart.
    /// This emits no vote; precommit retries still require recollecting verified prevotes.
    pub fn restore_proposal(
        &mut self,
        proposal: &SignedBlockProposal,
    ) -> Result<(), ValidatorError> {
        if !matches!(
            self.local.step(),
            VotingStep::Prevoted | VotingStep::Precommitted
        ) {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.local.verify_proposal(
            self.proposer(),
            &proposal.envelope,
            &proposal.proposal.block.header,
            proposal.valid_round.as_ref(),
        )?;
        self.producer.validate_proposal(&proposal.proposal)?;
        if self.proposal.as_ref().is_some_and(|previous| {
            previous.envelope.signing_hash() != proposal.envelope.signing_hash()
        }) {
            return Err(ConsensusError::Equivocation.into());
        }
        self.proposal = Some(proposal.clone());
        Ok(())
    }

    /// Authenticates a peer vote before retaining it in the bounded current-round collector.
    pub fn receive_vote(&mut self, vote: Vote) -> Result<(), ValidatorError> {
        if self.committed {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.collector.receive_vote(vote)?;
        Ok(())
    }

    fn record_outgoing(&mut self, vote: Vote) -> Result<(), ValidatorError> {
        match self.collector.receive_vote(vote) {
            Ok(()) | Err(ConsensusError::DuplicateVote) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_voting(&self) -> Result<(), ValidatorError> {
        if self.committed
            || self.local.step() == VotingStep::Finalized
            || self.collector.certificate().is_some()
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        Ok(())
    }

    /// Extracts current evidence for an available proposal; never implies finality.
    pub fn prevote_certificate(&self) -> Result<PrevoteCertificate, ValidatorError> {
        let proposal = self
            .proposal
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?;
        Ok(self
            .collector
            .prevote_certificate(proposal.envelope.block)?)
    }

    /// Locks and precommits only after a verified quorum and another execution check.
    pub fn precommit(&mut self) -> Result<Vote, ValidatorError> {
        self.ensure_voting()?;
        let proof = self.prevote_certificate()?;
        let proposal = self
            .proposal
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?;
        let producer = &self.producer;
        let vote = self
            .local
            .precommit(&proposal.proposal.block.header, &proof, |_| {
                producer.validate_proposal(&proposal.proposal).is_ok()
            })?;
        self.record_outgoing(vote.clone())?;
        Ok(vote)
    }

    /// Current round's verified finality, if available.
    #[must_use]
    pub fn certificate(&self) -> Option<&FinalityCertificate> {
        self.collector.certificate()
    }

    /// Publishes the available proposal after local collection reaches finality.
    pub fn commit<S: NodeStorage>(
        &mut self,
        storage: &mut S,
    ) -> Result<Checkpoint, ValidatorError> {
        let proposal = self
            .proposal
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?
            .proposal
            .clone();
        let certificate = self
            .collector
            .certificate()
            .ok_or(ConsensusError::InvalidTransition)?
            .clone();
        self.commit_finalized(&proposal, &certificate, storage)
    }

    /// Accepts independently verifiable finality even if local peer votes were lost on restart.
    /// Failed storage publication can be retried with the same proposal/certificate.
    pub fn commit_finalized<S: NodeStorage>(
        &mut self,
        proposal: &BlockProposal,
        certificate: &FinalityCertificate,
        storage: &mut S,
    ) -> Result<Checkpoint, ValidatorError> {
        if self.committed {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let producer = &self.producer;
        self.local
            .finalize(&proposal.block.header, certificate, |_| {
                producer.validate_proposal(proposal).is_ok()
            })?;
        let checkpoint = self.producer.commit_certified_block(
            proposal,
            certificate,
            self.local.committee(),
            storage,
        )?;
        self.committed = true;
        Ok(checkpoint)
    }

    /// Identifies the current timeout; returns none once finality is observed.
    #[must_use]
    pub fn timeout_event(&self) -> Option<TimeoutEvent> {
        if self.local.step() == VotingStep::Finalized || self.collector.certificate().is_some() {
            return None;
        }
        Some(TimeoutEvent {
            height: self.local.committee().height(),
            round: self.local.round(),
            step: self.local.step(),
        })
    }

    /// Handles one externally scheduled timeout without retaining delayed/future events.
    pub fn timeout(&mut self, event: TimeoutEvent) -> Result<Option<Vote>, ValidatorError> {
        if self.timeout_event() != Some(event) {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let vote = match event.step {
            VotingStep::AwaitingProposal => self.local.timeout_proposal(event.round)?,
            VotingStep::Prevoted => self.local.timeout_prevote(event.round)?,
            VotingStep::Precommitted => {
                self.local.timeout_precommit(event.round)?;
                self.collector.advance_round()?;
                self.proposal = None;
                return Ok(None);
            }
            VotingStep::Finalized => return Err(ConsensusError::InvalidTransition.into()),
        };
        self.record_outgoing(vote.clone())?;
        Ok(Some(vote))
    }

    /// Transfers execution state and the protected signer owner after shutdown or commit.
    #[must_use]
    pub fn into_parts(self) -> (BlockProducer, LocalBft) {
        (self.producer, self.local)
    }
}
