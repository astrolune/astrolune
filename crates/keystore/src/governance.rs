// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed network parameter approvals, separate from admission and BFT signatures.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use types::{Hash256, Resources, ValidatorId, hash::domain_hash};

/// Exact incumbent context and future activation of a capacity/fee change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernanceIntent {
    /// Chain replay-protection identifier.
    pub chain_id: u32,
    /// Independently configured network namespace.
    pub genesis: Hash256,
    /// Exact inclusion height approved by the incumbents.
    pub height: u64,
    /// Finalized parent immediately before inclusion.
    pub parent: Hash256,
    /// Current weighted voting committee.
    pub committee_root: Hash256,
    /// First height using the new parameters, at the next epoch boundary.
    pub activate_at: u64,
    /// Proposed block limits.
    pub capacity: Resources,
    /// Proposed integer prices per consumed resource unit.
    pub prices: Resources,
}

impl GovernanceIntent {
    /// Fixed canonical request length including its domain tag.
    pub const BYTES: usize = 188;

    /// Checks structural bounds; current authority and epoch policy need separate verification.
    ///
    /// # Errors
    /// Rejects zero namespaces, invalid coordinates and a zero capacity dimension.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.chain_id == 0
            || self.genesis.is_zero()
            || self.parent.is_zero()
            || self.committee_root.is_zero()
            || self.height == 0
            || self.activate_at <= self.height
            || self.capacity.compute == 0
            || self.capacity.memory == 0
            || self.capacity.io == 0
            || self.capacity.bandwidth == 0
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Canonical request, without any implicit approval.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALGVRQ01".to_vec();
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.genesis.0);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.parent.0);
        bytes.extend_from_slice(&self.committee_root.0);
        bytes.extend_from_slice(&self.activate_at.to_le_bytes());
        self.capacity.encode(&mut bytes);
        self.prices.encode(&mut bytes);
        bytes
    }

    /// Decodes exact request framing, without establishing authority.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, other tags and invalid coordinates.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::NonCanonical);
        }
        let mut reader = Decoder::new(bytes);
        if reader.read_exact(8)? != b"ALGVRQ01" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            chain_id: reader.read_u32()?,
            genesis: Hash256(reader.read_fixed()?),
            height: reader.read_u64()?,
            parent: Hash256(reader.read_fixed()?),
            committee_root: Hash256(reader.read_fixed()?),
            activate_at: reader.read_u64()?,
            capacity: Resources::decode(reader.read_exact(32)?)?,
            prices: Resources::decode(reader.read_exact(32)?)?,
        };
        reader.finish()?;
        result.validate()?;
        Ok(result)
    }

    /// Domain-separated identity of the complete request.
    #[must_use]
    pub fn id(&self) -> Hash256 {
        domain_hash(b"astrolune.governance.request.v1", &self.to_bytes())
    }

    /// Explicit approval digest binding the request and approving identity.
    #[must_use]
    pub fn approval_hash(&self, voter: ValidatorId) -> Hash256 {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.id().0);
        bytes[32..].copy_from_slice(&voter.0);
        domain_hash(b"astrolune.governance.approval.v1", &bytes)
    }
}
