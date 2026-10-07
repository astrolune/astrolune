// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded, exact authority state. Decoding cannot replace authenticated replay.

use super::{
    PotbRecord, PotbState,
    configuration::{read_policy, write_policy},
    identity,
};
use crate::{
    history::CommitteeHistory,
    rotation::{CommitteeState, MAX_ROTATION_VALIDATORS},
};
use codec::{DecodeError, Decoder};
use std::collections::BTreeMap;
use types::Hash256;

impl PotbState {
    /// Upper bound includes 64 history peaks and all 32 permanent identity records.
    pub const LEGACY_MAX_BYTES: usize = 105
        + CommitteeState::MAX_BYTES
        + CommitteeHistory::MAX_BYTES
        + 81 * MAX_ROTATION_VALIDATORS;

    /// Version-two bound including policy and a single pending parameter update.
    pub const MAX_BYTES: usize =
        Self::LEGACY_MAX_BYTES + 4 + crate::governance::GovernanceState::MAX_BYTES;

    /// Serializes validated fields with sorted records and exact optional-offence tags.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate().map_err(|_| DecodeError::NonCanonical)?;
        let mut bytes = if self.governance.is_some() {
            b"ALPTST02"
        } else {
            b"ALPTST01"
        }
        .to_vec();
        write_policy(&mut bytes, self.policy);
        bytes.extend_from_slice(&self.last_batch.0);
        write_field(&mut bytes, &self.committee.to_bytes()?)?;
        write_field(&mut bytes, &self.history.to_bytes())?;
        bytes.push(u8::try_from(self.records.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for record in self.records.values() {
            bytes.extend_from_slice(&record.public_key);
            bytes.extend_from_slice(&record.admitted_at.to_le_bytes());
            bytes.extend_from_slice(&record.eligible_blocks.to_le_bytes());
            bytes.push(u8::from(record.disqualification.is_some()));
            if let Some(offence) = record.disqualification {
                bytes.extend_from_slice(&offence.0);
            }
        }
        if let Some(governance) = &self.governance {
            write_field(&mut bytes, &governance.to_bytes())?;
        }
        Ok(bytes)
    }

    /// Preflights variable records and field lengths before allocating nested state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        let governed = match decoder.read_exact(8)? {
            b"ALPTST01" => false,
            b"ALPTST02" => true,
            _ => return Err(DecodeError::Unsupported),
        };
        let policy = read_policy(&mut decoder)?;
        let last_batch = Hash256(decoder.read_fixed()?);
        let committee = read_field(&mut decoder, CommitteeState::MAX_BYTES)?;
        let history = read_field(&mut decoder, CommitteeHistory::MAX_BYTES)?;
        let count = usize::from(decoder.read_u8()?);
        if count == 0 || count > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let record = PotbRecord {
                public_key: decoder.read_fixed()?,
                admitted_at: decoder.read_u64()?,
                eligible_blocks: decoder.read_u64()?,
                disqualification: match decoder.read_u8()? {
                    0 => None,
                    1 => Some(Hash256(decoder.read_fixed()?)),
                    _ => return Err(DecodeError::NonCanonical),
                },
            };
            let id = identity(&record.public_key);
            if previous.is_some_and(|last| last >= id) {
                return Err(DecodeError::NonCanonical);
            }
            previous = Some(id);
            records.insert(id, record);
        }
        let governance = if governed {
            Some(crate::governance::GovernanceState::from_bytes(read_field(
                &mut decoder,
                crate::governance::GovernanceState::MAX_BYTES,
            )?)?)
        } else {
            None
        };
        decoder.finish()?;
        let result = Self {
            committee: CommitteeState::from_bytes(committee)?,
            policy,
            history: CommitteeHistory::from_bytes(history)?,
            records,
            last_batch,
            governance,
        };
        result.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(result)
    }
}

pub(super) fn write_field(bytes: &mut Vec<u8>, field: &[u8]) -> Result<(), DecodeError> {
    bytes.extend_from_slice(
        &u32::try_from(field.len())
            .map_err(|_| DecodeError::LimitExceeded)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(field);
    Ok(())
}

pub(super) fn read_field<'a>(
    decoder: &mut Decoder<'a>,
    maximum: usize,
) -> Result<&'a [u8], DecodeError> {
    let size = usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::LengthOverflow)?;
    if size > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    decoder.read_exact(size)
}
