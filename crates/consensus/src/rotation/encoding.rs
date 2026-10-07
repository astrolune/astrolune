// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical bounded committee state. Deserialization never establishes trust.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use types::{Hash256, Resources, ValidatorId};

use super::{CommitteeState, MAX_ROTATION_VALIDATORS};
use crate::{PotbWeight, VrfValidator};

impl CommitteeState {
    /// Maximum state bytes for 32 eligible validators and 32 active seats.
    pub const MAX_BYTES: usize = 152 + 80 * MAX_ROTATION_VALIDATORS;

    /// Serializes a validated state in versioned canonical form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate().map_err(|_| DecodeError::NonCanonical)?;
        let mut bytes = b"ALCMST01".to_vec();
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.genesis.0);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.randomness.0);
        self.capacity.encode(&mut bytes);
        for count in [
            self.target_size,
            self.rotation_count,
            self.roster.len(),
            self.members.len(),
        ] {
            bytes.push(u8::try_from(count).map_err(|_| DecodeError::LimitExceeded)?);
        }
        bytes.extend_from_slice(&self.producer.0);
        for validator in &self.roster {
            bytes.extend_from_slice(&validator.public_key);
            bytes.extend_from_slice(&validator.weight.0.to_le_bytes());
        }
        for member in &self.members {
            bytes.extend_from_slice(&member.0);
        }
        Ok(bytes)
    }

    /// Validates sizes, identities, ordering, weights and selected membership.
    /// The returned state is structurally valid, but must still be authenticated.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALCMST01" {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;
        let genesis = Hash256(decoder.read_fixed()?);
        let height = decoder.read_u64()?;
        let randomness = Hash256(decoder.read_fixed()?);
        let capacity = Resources::decode(decoder.read_exact(32)?)?;
        let target_size = usize::from(decoder.read_u8()?);
        let rotation_count = usize::from(decoder.read_u8()?);
        let roster_count = usize::from(decoder.read_u8()?);
        let member_count = usize::from(decoder.read_u8()?);
        if roster_count > MAX_ROTATION_VALIDATORS || member_count > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        let producer = ValidatorId(decoder.read_fixed()?);
        // Preflight the entire envelope before allocating either collection.
        let roster_bytes = decoder.read_exact(roster_count * 48)?;
        let member_bytes = decoder.read_exact(member_count * 32)?;
        decoder.finish()?;
        let mut roster_decoder = Decoder::new(roster_bytes);
        let mut roster = Vec::with_capacity(roster_count);
        for _ in 0..roster_count {
            roster.push(VrfValidator {
                public_key: roster_decoder.read_fixed()?,
                weight: PotbWeight(u128::from_le_bytes(roster_decoder.read_fixed()?)),
            });
        }
        let mut member_decoder = Decoder::new(member_bytes);
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(ValidatorId(member_decoder.read_fixed()?));
        }
        let result = Self {
            chain_id,
            genesis,
            height,
            randomness,
            capacity,
            target_size,
            rotation_count,
            roster,
            members,
            producer,
        };
        result.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(result)
    }
}
