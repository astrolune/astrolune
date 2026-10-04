// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Incumbent-quorum parameter updates with delayed epoch activation.

mod encoding;
mod state;
use crate::{
    ConsensusError,
    rotation::{CommitteeState, MAX_ROTATION_VALIDATORS},
};
use crypto::blake2s::ed25519_verify;
pub use keystore::governance::GovernanceIntent;
pub use state::{GovernancePolicy, GovernanceState, NetworkParameters};
use types::{Hash256, ValidatorId};

/// Explicit operator approval of a typed parameter request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceApproval {
    request: Hash256,
    voter: ValidatorId,
    signature: [u8; 64],
}
impl GovernanceApproval {
    /// Authenticates the incumbent context and policy before signing.
    pub fn sign(
        request: &GovernanceIntent,
        current: &CommitteeState,
        parent: Hash256,
        policy: &GovernanceState,
        signer: &keystore::DurableSigner,
    ) -> Result<Self, ConsensusError> {
        policy.verify_request(current, parent, request)?;
        let voter = ValidatorId(crypto::blake2s_hash(&signer.public_key()).0);
        current
            .context()?
            .voting_power(voter)
            .ok_or(ConsensusError::UnknownVoter)?;
        let signature = signer
            .approve_governance(request)
            .map_err(|_| ConsensusError::InvalidProof)?;
        Ok(Self {
            request: request.id(),
            voter,
            signature,
        })
    }

    /// Approving validator identity.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.voter
    }

    fn verify(
        &self,
        request: &GovernanceIntent,
        current: &CommitteeState,
    ) -> Result<u128, ConsensusError> {
        if self.request != request.id() {
            return Err(ConsensusError::InvalidTransition);
        }
        let power = current
            .context()?
            .voting_power(self.voter)
            .ok_or(ConsensusError::UnknownVoter)?;
        let key = current
            .roster()
            .iter()
            .find(|member| ValidatorId(crypto::blake2s_hash(&member.public_key).0) == self.voter)
            .ok_or(ConsensusError::UnknownVoter)?
            .public_key;
        if !ed25519_verify(&key, &request.approval_hash(self.voter).0, &self.signature) {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(power)
    }
}

/// Strictly more than two thirds of current voting weight approving one exact update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceCertificate {
    request: GovernanceIntent,
    approvals: Vec<GovernanceApproval>,
}
impl GovernanceCertificate {
    /// Canonicalizes signatures and authenticates all of them, including after quorum.
    pub fn assemble(
        request: GovernanceIntent,
        mut approvals: Vec<GovernanceApproval>,
        current: &CommitteeState,
        parent: Hash256,
        policy: &GovernanceState,
    ) -> Result<Self, ConsensusError> {
        approvals.sort_by_key(|approval| approval.voter);
        let result = Self { request, approvals };
        result.verify(current, parent, policy)?;
        Ok(result)
    }

    /// Checks exact parent/height, configured bounds, epoch boundary and incumbent quorum.
    pub fn verify(
        &self,
        current: &CommitteeState,
        parent: Hash256,
        policy: &GovernanceState,
    ) -> Result<(), ConsensusError> {
        self.validate_shape()
            .map_err(|_| ConsensusError::InvalidCertificate)?;
        policy.verify_request(current, parent, &self.request)?;
        let power = self.approvals.iter().try_fold(0u128, |power, approval| {
            power
                .checked_add(approval.verify(&self.request, current)?)
                .ok_or(ConsensusError::InvalidCertificate)
        })?;
        if power < current.context()?.quorum() {
            return Err(ConsensusError::InvalidCertificate);
        }
        Ok(())
    }

    /// Shared approved request.
    #[must_use]
    pub const fn request(&self) -> &GovernanceIntent {
        &self.request
    }

    /// Unique approving identities in canonical order.
    pub fn voters(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.approvals.iter().map(|a| a.voter)
    }

    fn validate_shape(&self) -> Result<(), codec::DecodeError> {
        self.request.validate()?;
        if self.approvals.is_empty() || self.approvals.len() > MAX_ROTATION_VALIDATORS {
            return Err(codec::DecodeError::LimitExceeded);
        }
        if self
            .approvals
            .windows(2)
            .any(|pair| pair[0].voter >= pair[1].voter)
            || self
                .approvals
                .iter()
                .any(|a| a.request != self.request.id())
        {
            return Err(codec::DecodeError::NonCanonical);
        }
        Ok(())
    }
}
