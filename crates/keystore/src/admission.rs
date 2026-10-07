// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed admission signatures, separated from votes, proposals and wallet messages.

use codec::{DecodeError, Decoder};
use crypto::blake2s::{domain_hash, ed25519_verify};
use types::{Hash256, ValidatorId};

/// Exact finalized parent and incumbent committee authorizing a candidate key.
/// No caller-selected weight is accepted: the activated policy must assign it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionIntent {
    /// Network replay-protection identifier.
    pub chain_id: u32,
    /// Independently trusted genesis commitment.
    pub genesis: Hash256,
    /// Only height at which this request may be included.
    pub height: u64,
    /// Exact finalized parent of the inclusion block.
    pub parent: Hash256,
    /// Weighted incumbent committee for the inclusion height.
    pub committee_root: Hash256,
    /// Candidate's strong Ed25519 identity key.
    pub public_key: [u8; 32],
}

impl AdmissionIntent {
    /// Fixed-width body, excluding a request tag and candidate signature.
    pub const BYTES: usize = 140;

    /// Rejects invalid coordinates and malformed, noncanonical or weak keys.
    ///
    /// # Errors
    /// Returns an error for an invalid namespace, terminal height or public key.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.chain_id == 0
            || self.genesis == Hash256::ZERO
            || self.parent == Hash256::ZERO
            || self.committee_root == Hash256::ZERO
            || self.height == 0
            || self.height == u64::MAX
        {
            return Err(DecodeError::NonCanonical);
        }
        crypto::Blake2sProvider::new()
            .register_validator(self.public_key)
            .map_err(|_| DecodeError::NonCanonical)?;
        Ok(())
    }

    /// Exact body used by both distinct signing domains.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[..4].copy_from_slice(&self.chain_id.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.genesis.0);
        bytes[36..44].copy_from_slice(&self.height.to_le_bytes());
        bytes[44..76].copy_from_slice(&self.parent.0);
        bytes[76..108].copy_from_slice(&self.committee_root.0);
        bytes[108..].copy_from_slice(&self.public_key);
        bytes
    }

    /// Decodes exact structural context; it does not establish committee authority.
    ///
    /// # Errors
    /// Rejects noncanonical fields, trailing bytes and truncated inputs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::NonCanonical);
        }
        let mut decoder = Decoder::new(bytes);
        let result = Self {
            chain_id: decoder.read_u32()?,
            genesis: Hash256(decoder.read_fixed()?),
            height: decoder.read_u64()?,
            parent: Hash256(decoder.read_fixed()?),
            committee_root: Hash256(decoder.read_fixed()?),
            public_key: decoder.read_fixed()?,
        };
        decoder.finish()?;
        result.validate()?;
        Ok(result)
    }

    /// Candidate proof-of-possession and consent digest, not a consensus vote.
    #[must_use]
    pub fn consent_hash(&self) -> Hash256 {
        domain_hash(b"astrolune.admission.consent.v1", &self.to_bytes())
    }

    /// Checks the candidate's strict signature over all intent fields.
    #[must_use]
    pub fn verify_consent(&self, signature: &[u8; 64]) -> bool {
        self.validate().is_ok()
            && ed25519_verify(&self.public_key, &self.consent_hash().0, signature)
    }

    /// Commitment to the complete signed request.
    #[must_use]
    pub fn request_id(&self, consent: &[u8; 64]) -> Hash256 {
        let mut bytes = Vec::with_capacity(Self::BYTES + consent.len());
        bytes.extend_from_slice(&self.to_bytes());
        bytes.extend_from_slice(consent);
        domain_hash(b"astrolune.admission.request.v1", &bytes)
    }

    /// Incumbent approval digest binds the request and approving identity.
    #[must_use]
    pub fn approval_hash(&self, consent: &[u8; 64], voter: ValidatorId) -> Hash256 {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.request_id(consent).0);
        bytes[32..].copy_from_slice(&voter.0);
        domain_hash(b"astrolune.admission.approval.v1", &bytes)
    }
}
