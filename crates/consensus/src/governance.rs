// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Incumbent-quorum parameter updates with delayed epoch activation.

mod encoding;
mod state;
use crate::{
    ConsensusError,
    rotation::{CommitteeState, MAX_ROTATION_VALIDATORS},
};
use crypto::DigestRequest;
pub use keystore::governance::GovernanceIntent;
pub use state::{GovernancePolicy, GovernanceState, NetworkParameters};
use std::collections::BTreeMap;
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

    fn credentials(
        &self,
        request: &GovernanceIntent,
        context: &crate::AuthenticatedCommittee,
        keys: &BTreeMap<ValidatorId, [u8; 32]>,
    ) -> Result<(u128, DigestRequest), ConsensusError> {
        if self.request != request.id() {
            return Err(ConsensusError::InvalidTransition);
        }
        let power = context
            .voting_power(self.voter)
            .ok_or(ConsensusError::UnknownVoter)?;
        let public_key = *keys.get(&self.voter).ok_or(ConsensusError::UnknownVoter)?;
        Ok((
            power,
            DigestRequest {
                public_key,
                digest: request.approval_hash(self.voter).0,
                signature: self.signature,
            },
        ))
    }
}

/// Indexes the roster by derived identity, replacing a linear scan per approval.
///
/// A validated [`CommitteeState`] roster is strictly ordered by derived
/// identity, so this map has exactly one entry per roster member and resolves
/// the same key the scan it replaces would have found.
fn roster_keys(current: &CommitteeState) -> BTreeMap<ValidatorId, [u8; 32]> {
    let mut keys = BTreeMap::new();
    for member in current.roster() {
        keys.entry(ValidatorId(crypto::blake2s_hash(&member.public_key).0))
            .or_insert(member.public_key);
    }
    keys
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
        let context = current.context()?;
        let keys = roster_keys(current);
        // Hoist every cheap check, keeping its serial order, and stop at the
        // first one that rejects. Only approvals below that position were
        // reached serially, so they are exactly the signatures to decide as one
        // batch. Reaching quorum never ends the loop.
        let mut batch = Vec::with_capacity(self.approvals.len());
        let mut weights = Vec::with_capacity(self.approvals.len());
        let mut rejected = None;
        for approval in &self.approvals {
            match approval.credentials(&self.request, &context, &keys) {
                Ok((power, request)) => {
                    weights.push(power);
                    batch.push(request);
                }
                Err(error) => {
                    rejected = Some(error);
                    break;
                }
            }
        }
        if crypto::batch::first_digest_failure(&batch).is_some() {
            return Err(ConsensusError::InvalidProof);
        }
        if let Some(error) = rejected {
            return Err(error);
        }
        let power = weights.into_iter().try_fold(0u128, |total, weight| {
            total
                .checked_add(weight)
                .ok_or(ConsensusError::InvalidCertificate)
        })?;
        if power < context.quorum() {
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
