// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit incumbent-quorum admission authorization. These envelopes do not
//! activate admission or change membership in existing genesis-v1/v2 profiles.

use codec::{DecodeError, Decoder};
use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
pub use keystore::admission::AdmissionIntent;
use types::{Hash256, ValidatorId};

use crate::{
    ConsensusError,
    rotation::{CommitteeState, MAX_ROTATION_VALIDATORS},
};

mod encoding;

/// Candidate-owned request, bound to one network, parent and incumbent committee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    intent: AdmissionIntent,
    consent: [u8; 64],
}

impl AdmissionRequest {
    /// Creates a signed request after checking that the candidate is unregistered.
    /// The caller independently authenticates `current` and its finalized `parent`.
    pub fn sign(
        current: &CommitteeState,
        parent: Hash256,
        seed: &[u8; 32],
    ) -> Result<Self, ConsensusError> {
        let intent = AdmissionIntent {
            chain_id: current.chain_id(),
            genesis: current.genesis(),
            height: current.height(),
            parent,
            committee_root: current.context()?.root(),
            public_key: ed25519_public_key(seed),
        };
        let consent = ed25519_sign(seed, &intent.consent_hash().0);
        let result = Self { intent, consent };
        result.verify(current, parent)?;
        Ok(result)
    }

    /// Checks candidate ownership, exact anchor and available bounded roster space.
    /// Approval and activation are separate from a valid candidate request.
    pub fn verify(&self, current: &CommitteeState, parent: Hash256) -> Result<(), ConsensusError> {
        if self.intent.chain_id != current.chain_id()
            || self.intent.genesis != current.genesis()
            || self.intent.height != current.height()
            || self.intent.parent != parent
            || self.intent.committee_root != current.context()?.root()
            || current.roster().len() >= MAX_ROTATION_VALIDATORS
            || current
                .roster()
                .iter()
                .any(|v| v.public_key == self.intent.public_key)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        if !self.intent.verify_consent(&self.consent) {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(())
    }

    /// Exact signed context. Its claimed authority still requires verification.
    #[must_use]
    pub const fn intent(&self) -> &AdmissionIntent {
        &self.intent
    }

    /// Candidate signature suitable for the non-exporting typed signer.
    #[must_use]
    pub const fn consent(&self) -> &[u8; 64] {
        &self.consent
    }

    /// Domain-separated complete request identity.
    #[must_use]
    pub fn id(&self) -> Hash256 {
        self.intent.request_id(&self.consent)
    }

    /// Derived candidate identity, not an authority grant.
    #[must_use]
    pub fn candidate(&self) -> ValidatorId {
        ValidatorId(crypto::blake2s_hash(&self.intent.public_key).0)
    }
}

/// An explicit operator approval, distinct from a precommit or candidate consent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionApproval {
    request: Hash256,
    voter: ValidatorId,
    signature: [u8; 64],
}

impl AdmissionApproval {
    /// Verifies membership and consent before asking a protected signer to approve.
    /// No signature is made for an outsider, foreign anchor or invalid request.
    pub fn sign(
        request: &AdmissionRequest,
        current: &CommitteeState,
        parent: Hash256,
        signer: &keystore::DurableSigner,
    ) -> Result<Self, ConsensusError> {
        request.verify(current, parent)?;
        let voter = ValidatorId(crypto::blake2s_hash(&signer.public_key()).0);
        current
            .context()?
            .voting_power(voter)
            .ok_or(ConsensusError::UnknownVoter)?;
        let signature = signer
            .approve_admission(&request.intent, &request.consent)
            .map_err(|_| ConsensusError::InvalidProof)?;
        let result = Self {
            request: request.id(),
            voter,
            signature,
        };
        result.verify(request, current, parent)?;
        Ok(result)
    }

    /// Verifies explicit approval and returns this incumbent's trusted voting power.
    pub fn verify(
        &self,
        request: &AdmissionRequest,
        current: &CommitteeState,
        parent: Hash256,
    ) -> Result<u128, ConsensusError> {
        request.verify(current, parent)?;
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
            .find(|v| ValidatorId(crypto::blake2s_hash(&v.public_key).0) == self.voter)
            .ok_or(ConsensusError::UnknownVoter)?
            .public_key;
        if !ed25519_verify(
            &key,
            &request.intent.approval_hash(&request.consent, self.voter).0,
            &self.signature,
        ) {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(power)
    }

    /// Identity of the incumbent who signed this approval.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.voter
    }
}

/// Canonical explicit approvals exceeding two thirds of incumbent voting power.
/// Decoding does not establish authority, freshness or canonical block inclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionCertificate {
    request: AdmissionRequest,
    approvals: Vec<AdmissionApproval>,
}

impl AdmissionCertificate {
    /// Canonicalizes arrival order; rejects duplicates, outsiders and insufficient power.
    pub fn assemble(
        request: AdmissionRequest,
        mut approvals: Vec<AdmissionApproval>,
        current: &CommitteeState,
        parent: Hash256,
    ) -> Result<Self, ConsensusError> {
        if approvals.len() > MAX_ROTATION_VALIDATORS {
            return Err(ConsensusError::InvalidCertificate);
        }
        approvals.sort_by_key(|a| a.voter);
        let result = Self { request, approvals };
        result.verify(current, parent)?;
        Ok(result)
    }

    /// Authenticates every approval; even signatures after reaching quorum must be valid.
    pub fn verify(&self, current: &CommitteeState, parent: Hash256) -> Result<(), ConsensusError> {
        self.validate_shape()
            .map_err(|_| ConsensusError::InvalidCertificate)?;
        self.request.verify(current, parent)?;
        let mut power = 0u128;
        for approval in &self.approvals {
            power = power
                .checked_add(approval.verify(&self.request, current, parent)?)
                .ok_or(ConsensusError::InvalidCertificate)?;
        }
        if power < current.context()?.quorum() {
            return Err(ConsensusError::InvalidCertificate);
        }
        Ok(())
    }

    /// Candidate request unanimously shared by these approving signatures.
    #[must_use]
    pub const fn request(&self) -> &AdmissionRequest {
        &self.request
    }

    /// Unique approving identities in canonical order.
    pub fn voters(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.approvals.iter().map(|a| a.voter)
    }
}
