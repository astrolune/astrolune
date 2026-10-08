// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit incumbent-quorum admission authorization. These envelopes do not
//! activate admission or change membership in existing genesis-v1/v2 profiles.

use codec::{DecodeError, Decoder};
use crypto::DigestRequest;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
pub use keystore::admission::AdmissionIntent;
use std::collections::BTreeMap;
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
        let (power, candidate) =
            self.credentials(request, &current.context()?, &roster_keys(current))?;
        if !candidate.verify() {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(power)
    }

    /// Resolves the non-cryptographic part of [`Self::verify`] in its exact order.
    ///
    /// `context` and `keys` are the incumbent context and its roster key index,
    /// which `request.verify` has already proven obtainable. Passing them in
    /// lets a certificate resolve them once instead of rebuilding the context
    /// and rescanning the roster for every approval. A rejection here always
    /// sits at a lower position than any signature failure it stops the caller
    /// from reaching, so the reported error is unchanged by batching.
    fn credentials(
        &self,
        request: &AdmissionRequest,
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
                digest: request.intent.approval_hash(&request.consent, self.voter).0,
                signature: self.signature,
            },
        ))
    }

    /// Identity of the incumbent who signed this approval.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.voter
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
        let context = current.context()?;
        let keys = roster_keys(current);
        // Hoist every cheap check, keeping its serial order, and stop at the
        // first one that rejects. Only approvals below that position were
        // reached serially, so they are exactly the signatures to decide as one
        // batch. Reaching quorum never ends the loop: the batch below always
        // covers every approval the serial path would have verified.
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
