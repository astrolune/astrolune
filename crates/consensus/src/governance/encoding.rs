// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Exact bounded governance envelopes; decoding never authenticates an approval.

use super::{
    GovernanceApproval, GovernanceCertificate, GovernanceIntent, GovernancePolicy, GovernanceState,
    NetworkParameters,
};
use crate::rotation::MAX_ROTATION_VALIDATORS;
use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use types::{Hash256, Resources, ValidatorId};

impl GovernanceApproval {
    /// Fixed size of one explicit approval.
    pub const BYTES: usize = 136;
    /// Canonical typed signature bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALGVAP01".to_vec();
        bytes.extend_from_slice(&self.request.0);
        bytes.extend_from_slice(&self.voter.0);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Exact framing; signature verification requires a trusted incumbent context.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Decoder::new(bytes);
        if reader.read_exact(8)? != b"ALGVAP01" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            request: Hash256(reader.read_fixed()?),
            voter: ValidatorId(reader.read_fixed()?),
            signature: reader.read_fixed()?,
        };
        reader.finish()?;
        Ok(result)
    }
}
impl GovernanceCertificate {
    /// Maximum request and full-incumbent approval set.
    pub const MAX_BYTES: usize =
        9 + GovernanceIntent::BYTES + MAX_ROTATION_VALIDATORS * GovernanceApproval::BYTES;
    /// Canonical sorted approvals of one exact request.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let mut bytes = b"ALGVCF01".to_vec();
        bytes.extend_from_slice(&self.request.to_bytes());
        bytes.push(u8::try_from(self.approvals.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for approval in &self.approvals {
            bytes.extend_from_slice(&approval.to_bytes());
        }
        Ok(bytes)
    }
    /// Preflights the fixed signature count before allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut reader = Decoder::new(bytes);
        if reader.read_exact(8)? != b"ALGVCF01" {
            return Err(DecodeError::Unsupported);
        }
        let request = GovernanceIntent::from_bytes(reader.read_exact(GovernanceIntent::BYTES)?)?;
        let count = usize::from(reader.read_u8()?);
        if count == 0
            || count > MAX_ROTATION_VALIDATORS
            || reader.remaining() != count * GovernanceApproval::BYTES
        {
            return Err(DecodeError::NonCanonical);
        }
        let approvals = (0..count)
            .map(|_| GovernanceApproval::from_bytes(reader.read_exact(GovernanceApproval::BYTES)?))
            .collect::<Result<_, _>>()?;
        reader.finish()?;
        let result = Self { request, approvals };
        result.validate_shape()?;
        Ok(result)
    }
}

impl GovernancePolicy {
    /// Fixed canonical immutable policy length.
    pub const BYTES: usize = 104;
    /// Bounded policy fields, included in the explicit configuration namespace.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = self.epoch_blocks.to_le_bytes().to_vec();
        self.minimum_capacity.encode(&mut bytes);
        self.maximum_capacity.encode(&mut bytes);
        self.maximum_prices.encode(&mut bytes);
        bytes
    }
    /// Decodes and validates immutable bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Decoder::new(bytes);
        let result = Self {
            epoch_blocks: reader.read_u64()?,
            minimum_capacity: Resources::decode(reader.read_exact(32)?)?,
            maximum_capacity: Resources::decode(reader.read_exact(32)?)?,
            maximum_prices: Resources::decode(reader.read_exact(32)?)?,
        };
        reader.finish()?;
        result.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(result)
    }
}

impl GovernanceState {
    /// Maximum bounded policy, active parameters and one future update.
    pub const MAX_BYTES: usize = 249;
    /// Canonical state, with exact optional-update framing.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALGVST01".to_vec();
        bytes.extend_from_slice(&self.policy.to_bytes());
        put_parameters(&mut bytes, self.active);
        bytes.push(u8::from(self.pending.is_some()));
        if let Some((height, parameters)) = self.pending {
            bytes.extend_from_slice(&height.to_le_bytes());
            put_parameters(&mut bytes, parameters);
        }
        bytes
    }
    /// Checks shape and bounds; the containing consensus state validates the exact height.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut reader = Decoder::new(bytes);
        if reader.read_exact(8)? != b"ALGVST01" {
            return Err(DecodeError::Unsupported);
        }
        let policy = GovernancePolicy::from_bytes(reader.read_exact(GovernancePolicy::BYTES)?)?;
        let active = read_parameters(&mut reader)?;
        let pending = match reader.read_u8()? {
            0 => None,
            1 => Some((reader.read_u64()?, read_parameters(&mut reader)?)),
            _ => return Err(DecodeError::NonCanonical),
        };
        reader.finish()?;
        policy
            .permits(active)
            .map_err(|_| DecodeError::NonCanonical)?;
        if let Some((height, parameters)) = pending {
            if height <= 1 || !(height - 1).is_multiple_of(policy.epoch_blocks) {
                return Err(DecodeError::NonCanonical);
            }
            policy
                .permits(parameters)
                .map_err(|_| DecodeError::NonCanonical)?;
        }
        Ok(Self {
            policy,
            active,
            pending,
        })
    }
}
fn put_parameters(bytes: &mut Vec<u8>, parameters: NetworkParameters) {
    parameters.capacity.encode(bytes);
    parameters.prices.encode(bytes);
}
fn read_parameters(reader: &mut Decoder<'_>) -> Result<NetworkParameters, DecodeError> {
    Ok(NetworkParameters {
        capacity: Resources::decode(reader.read_exact(32)?)?,
        prices: Resources::decode(reader.read_exact(32)?)?,
    })
}
