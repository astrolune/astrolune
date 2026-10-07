// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fixed-height local voting rules with atomically durable vote/lock decisions.

use crate::{
    AuthenticatedCommittee, ConsensusError, FinalityCertificate, PrevoteCertificate, Proposal,
    Vote, VotePhase,
};
use keystore::{
    ChainSigner, DurableSigner, KeyHandle, KeystoreError, Signer, SigningLock, SigningPosition,
    SigningSafety,
};
use types::{BlockHeader, Hash256, ValidatorId};

/// Local signing phase; timer scheduling and network delivery are external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VotingStep {
    /// No prevote has been issued in this round.
    AwaitingProposal,
    /// A prevote is durably reserved; wait for a quorum or timeout.
    Prevoted,
    /// A precommit is durably reserved; wait for finality or the next round.
    Precommitted,
    /// An independently verified certificate and proposal were accepted.
    Finalized,
}

/// Protocol or durable signing failure; neither authorizes a conflicting retry.
#[derive(Debug, Eq, PartialEq)]
pub enum LocalBftError {
    /// Proposal, proof, context, or step is invalid.
    Consensus(ConsensusError),
    /// Durable signing failed or rejected the decision.
    Signing(KeystoreError),
}
impl std::fmt::Display for LocalBftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Consensus(error) => write!(f, "consensus: {error}"),
            Self::Signing(error) => write!(f, "signing: {error}"),
        }
    }
}
impl std::error::Error for LocalBftError {}
impl From<ConsensusError> for LocalBftError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<KeystoreError> for LocalBftError {
    fn from(error: KeystoreError) -> Self {
        Self::Signing(error)
    }
}

/// Local prevote/precommit guard for one independently trusted committee and height.
///
/// Owns a protected signer so lock state and each outgoing vote are synchronized
/// together. The low-level `prevote` callback must authenticate the designated
/// proposer; `prevote_proposal` performs that check against trusted designation.
/// Callbacks validate availability, parent linkage, capacity, and deterministic
/// execution. Networking, timer policy, and committee handoff are external.
/// A valid quorum never substitutes for proposal validation.
pub struct LocalBft {
    committee: AuthenticatedCommittee,
    signer: DurableSigner,
    handle: KeyHandle,
    voter: ValidatorId,
    round: u32,
    step: VotingStep,
    locked: Option<SigningLock>,
    finalized: Option<Hash256>,
}

impl LocalBft {
    /// Produces a VRF contribution through the non-exporting protected signer.
    pub fn prove_vrf(&self, input: crypto::VrfInput) -> Result<crypto::VrfOutput, LocalBftError> {
        self.signer.prove_vrf(input).map_err(Into::into)
    }

    /// Starts or resumes voting from a protected journal and trusted chain context.
    ///
    /// Restores the last signed round/step/lock at this height. A later trusted
    /// height begins at round zero; callers establish finality before advancing it.
    pub fn new(
        committee: AuthenticatedCommittee,
        signer: DurableSigner,
        genesis: Hash256,
    ) -> Result<Self, LocalBftError> {
        if !signer.is_protected() {
            return Err(KeystoreError::InvalidSafety.into());
        }
        if signer.signing_context().chain_id != committee.chain_id()
            || signer.signing_context().genesis != genesis
        {
            return Err(KeystoreError::ContextMismatch.into());
        }
        let handle = signer.key_handle();
        let voter = signer.validator_id(&handle)?;
        if committee.voting_power(voter).is_none() {
            return Err(ConsensusError::UnknownVoter.into());
        }
        let mut round = 0;
        let mut step = VotingStep::AwaitingProposal;
        let mut locked = None;
        if let Some(position) = signer.last_position() {
            if position.height > committee.height() {
                return Err(KeystoreError::StalePosition.into());
            }
            if position.height == committee.height() {
                let safety = signer.safety().ok_or(KeystoreError::InvalidSafety)?;
                if safety.committee_root != committee.root() {
                    return Err(KeystoreError::ContextMismatch.into());
                }
                round = position.round;
                step = match position.phase {
                    keystore::PROPOSAL_PHASE => VotingStep::AwaitingProposal,
                    keystore::PREVOTE_PHASE => VotingStep::Prevoted,
                    keystore::PRECOMMIT_PHASE => VotingStep::Precommitted,
                    _ => return Err(KeystoreError::InvalidPosition.into()),
                };
                locked = safety.locked;
            }
        }
        Ok(Self {
            committee,
            signer,
            handle,
            voter,
            round,
            step,
            locked,
            finalized: None,
        })
    }

    /// Immutable membership used by proposals and proof checks.
    #[must_use]
    pub const fn committee(&self) -> &AuthenticatedCommittee {
        &self.committee
    }
    /// Active round; timeout events must carry this value to reject stale timers.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.round
    }
    /// Current local signing phase.
    #[must_use]
    pub const fn step(&self) -> VotingStep {
        self.step
    }
    /// Last durably reserved non-nil precommit lock.
    #[must_use]
    pub const fn locked(&self) -> Option<SigningLock> {
        self.locked
    }
    /// Accepted finality, which the caller still must publish through atomic storage.
    #[must_use]
    pub const fn finalized_block(&self) -> Option<Hash256> {
        self.finalized
    }
    /// Transfers the signer to the next independently verified height or shutdown.
    #[must_use]
    pub fn into_signer(self) -> DurableSigner {
        self.signer
    }

    /// Signs a validated proposal in journal phase zero, preserving the current lock.
    /// The designation comes from trusted policy shared by all participants.
    pub fn propose(
        &mut self,
        expected_proposer: ValidatorId,
        header: &BlockHeader,
        valid_round: Option<&PrevoteCertificate>,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> Result<Proposal, LocalBftError> {
        if self.step != VotingStep::AwaitingProposal
            || self.voter != expected_proposer
            || !self.valid_header(header, validate)
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let mut proposal = Proposal {
            chain_id: self.committee.chain_id(),
            genesis: self.signer.signing_context().genesis,
            height: self.committee.height(),
            round: self.round,
            committee_root: self.committee.root(),
            block: header.compute_hash(),
            proposer: self.voter,
            valid_round: valid_round.map(PrevoteCertificate::round),
            signature: [0; 64],
        };
        proposal.verify_valid_round(&self.committee, valid_round)?;
        // A locked proposer must not issue a fresh conflicting value without evidence.
        if self.locked.is_some_and(|locked| {
            locked.block != proposal.block
                && valid_round.is_none_or(|proof| proof.round() <= locked.round)
        }) {
            return Err(ConsensusError::InvalidTransition.into());
        }
        proposal.signature = self.signer.sign_protected(
            &self.handle,
            SigningPosition {
                height: proposal.height,
                round: self.round,
                phase: keystore::PROPOSAL_PHASE,
            },
            proposal.signing_hash(),
            SigningSafety {
                committee_root: proposal.committee_root,
                locked: self.locked,
            },
        )?;
        Ok(proposal)
    }

    /// Authenticates an exact current-round proposal and its proof before prevoting.
    /// The callback only needs to check block availability and deterministic execution.
    pub fn prevote_proposal(
        &mut self,
        expected_proposer: ValidatorId,
        proposal: &Proposal,
        header: &BlockHeader,
        valid_round: Option<&PrevoteCertificate>,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> Result<Vote, LocalBftError> {
        self.verify_proposal(expected_proposer, proposal, header, valid_round)?;
        self.prevote(Some(header), valid_round, validate)
    }

    /// Verifies current-round designation, context, signature, and attached evidence.
    /// This read-only check permits restoring an available body after a signed precommit.
    pub fn verify_proposal(
        &self,
        expected_proposer: ValidatorId,
        proposal: &Proposal,
        header: &BlockHeader,
        valid_round: Option<&PrevoteCertificate>,
    ) -> Result<(), LocalBftError> {
        if proposal.round != self.round {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.committee.verify_proposal(
            proposal,
            header,
            expected_proposer,
            self.signer.signing_context().genesis,
        )?;
        proposal.verify_valid_round(&self.committee, valid_round)?;
        Ok(())
    }

    fn valid_header(
        &self,
        header: &BlockHeader,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> bool {
        header.height == self.committee.height()
            && header.committee_root == self.committee.root()
            && validate(header)
    }

    /// Votes for a validated proposal if unlocked, already locked on it, or supplied
    /// with a strictly newer prevote proof from an earlier round. Otherwise votes nil.
    /// Identical retries are allowed; the journal rejects alternate values in a slot.
    pub fn prevote(
        &mut self,
        header: Option<&BlockHeader>,
        valid_round: Option<&PrevoteCertificate>,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> Result<Vote, LocalBftError> {
        if !matches!(
            self.step,
            VotingStep::AwaitingProposal | VotingStep::Prevoted
        ) {
            return Err(ConsensusError::InvalidTransition.into());
        }
        if let Some(proof) = valid_round {
            proof.verify_context(&self.committee)?;
            if proof.round() >= self.round
                || header.is_none_or(|header| header.compute_hash() != proof.block())
            {
                return Err(ConsensusError::InvalidCertificate.into());
            }
        }
        let block = header
            .filter(|header| self.valid_header(header, validate))
            .map(BlockHeader::compute_hash);
        let permitted = self.locked.is_none_or(|locked| {
            block == Some(locked.block)
                || valid_round.is_some_and(|proof| proof.round() > locked.round)
        });
        self.issue(VotePhase::Prevote, block.filter(|_| permitted), self.locked)
    }

    /// Locks and precommits a validated proposal after a current-round prevote quorum.
    pub fn precommit(
        &mut self,
        header: &BlockHeader,
        proof: &PrevoteCertificate,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> Result<Vote, LocalBftError> {
        if !matches!(self.step, VotingStep::Prevoted | VotingStep::Precommitted) {
            return Err(ConsensusError::InvalidTransition.into());
        }
        proof.verify_context(&self.committee)?;
        if proof.round() != self.round
            || proof.block() != header.compute_hash()
            || !self.valid_header(header, validate)
        {
            return Err(ConsensusError::InvalidCertificate.into());
        }
        self.issue(
            VotePhase::Precommit,
            Some(proof.block()),
            Some(SigningLock {
                round: self.round,
                block: proof.block(),
            }),
        )
    }

    /// Issues a nil prevote on a matching proposal timeout without releasing the lock.
    pub fn timeout_proposal(&mut self, round: u32) -> Result<Vote, LocalBftError> {
        if round != self.round || self.step != VotingStep::AwaitingProposal {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.issue(VotePhase::Prevote, None, self.locked)
    }

    /// Issues a nil precommit on a matching prevote timeout without releasing the lock.
    pub fn timeout_prevote(&mut self, round: u32) -> Result<Vote, LocalBftError> {
        if round != self.round || self.step != VotingStep::Prevoted {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.issue(VotePhase::Precommit, None, self.locked)
    }

    /// Advances after a matching precommit timeout, preserving the durable lock.
    /// Timer duration/quorum scheduling is the caller's responsibility.
    pub fn timeout_precommit(&mut self, round: u32) -> Result<(), LocalBftError> {
        if round != self.round || self.step != VotingStep::Precommitted {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let next = self
            .round
            .checked_add(1)
            .ok_or(ConsensusError::InvalidTransition)?;
        self.round = next;
        self.step = VotingStep::AwaitingProposal;
        Ok(())
    }

    /// Accepts an independently verified certificate only after proposal validation.
    pub fn finalize(
        &mut self,
        header: &BlockHeader,
        certificate: &FinalityCertificate,
        validate: impl FnOnce(&BlockHeader) -> bool,
    ) -> Result<(), LocalBftError> {
        self.committee.verify_certificate(certificate, header)?;
        if !self.valid_header(header, validate)
            || self.finalized.is_some_and(|hash| hash != certificate.block)
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        self.finalized = Some(certificate.block);
        self.step = VotingStep::Finalized;
        Ok(())
    }

    fn issue(
        &mut self,
        phase: VotePhase,
        block: Option<Hash256>,
        locked: Option<SigningLock>,
    ) -> Result<Vote, LocalBftError> {
        let mut vote = Vote {
            chain_id: self.committee.chain_id(),
            height: self.committee.height(),
            committee_root: self.committee.root(),
            round: self.round,
            phase,
            block,
            voter: self.voter,
            signature: [0; 64],
        };
        let (phase, step) = match phase {
            VotePhase::Prevote => (keystore::PREVOTE_PHASE, VotingStep::Prevoted),
            VotePhase::Precommit => (keystore::PRECOMMIT_PHASE, VotingStep::Precommitted),
        };
        vote.signature = self.signer.sign_protected(
            &self.handle,
            SigningPosition {
                height: vote.height,
                round: vote.round,
                phase,
            },
            vote.signing_hash(),
            SigningSafety {
                committee_root: vote.committee_root,
                locked,
            },
        )?;
        self.locked = locked;
        self.step = step;
        Ok(vote)
    }
}
