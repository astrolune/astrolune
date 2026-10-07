// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded canonical transport encoding for non-membership proofs.

use codec::Decoder;
use types::{Hash256, StateKey};

use crate::{
    MAX_STATE_ENTRIES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES, StateAbsenceProof, StateError,
    StateProof, StateWitness,
};

const MAGIC: &[u8; 8] = b"ASTABSEN";
const VERSION: u16 = 1;
const MAX_SIBLINGS: usize = 20;

/// Maximum encoded absence proof, including two full neighboring values and paths.
pub const MAX_ABSENCE_PROOF_BYTES: usize =
    12 + 2 * (33 + MAX_STATE_KEY_BYTES + MAX_STATE_VALUE_BYTES + 32 * MAX_SIBLINGS);

impl StateAbsenceProof {
    /// Encodes a bounded proof. Authentication remains the responsibility of `verify`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StateError> {
        // Validate both witnesses before allocating or copying either value.
        for witness in [&self.lower, &self.upper].into_iter().flatten() {
            validate_bounds(
                witness.key.len(),
                witness.value.len(),
                witness.proof.index,
                witness.proof.leaf_count,
                witness.proof.siblings.len(),
            )?;
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        for witness in [&self.lower, &self.upper] {
            bytes.push(u8::from(witness.is_some()));
            if let Some(witness) = witness {
                bytes.extend_from_slice(&(witness.key.len() as u64).to_le_bytes());
                bytes.extend_from_slice(witness.key.as_bytes());
                bytes.extend_from_slice(&(witness.value.len() as u64).to_le_bytes());
                bytes.extend_from_slice(&witness.value);
                bytes.extend_from_slice(&witness.proof.index.to_le_bytes());
                bytes.extend_from_slice(&witness.proof.leaf_count.to_le_bytes());
                bytes.push(
                    u8::try_from(witness.proof.siblings.len())
                        .map_err(|_| StateError::LimitExceeded)?,
                );
                for sibling in &witness.proof.siblings {
                    bytes.extend_from_slice(sibling.as_bytes());
                }
            }
        }
        Ok(bytes)
    }

    /// Decodes canonical framing and bounds before allocating owned values.
    ///
    /// Successful decoding does not authenticate absence. Call `verify` with an
    /// independently trusted root and the requested key before accepting a result.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() > MAX_ABSENCE_PROOF_BYTES {
            return Err(StateError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != MAGIC || decoder.read_u16()? != VERSION {
            return Err(StateError::Corrupt);
        }
        let lower = BorrowedWitness::read(&mut decoder)?;
        let upper = BorrowedWitness::read(&mut decoder)?;
        decoder.finish()?;
        Ok(Self {
            lower: lower.map(BorrowedWitness::into_owned),
            upper: upper.map(BorrowedWitness::into_owned),
        })
    }
}

struct BorrowedWitness<'a> {
    key: &'a [u8],
    value: &'a [u8],
    index: u64,
    leaf_count: u64,
    siblings: &'a [u8],
}

impl<'a> BorrowedWitness<'a> {
    fn read(decoder: &mut Decoder<'a>) -> Result<Option<Self>, StateError> {
        match decoder.read_u8()? {
            0 => return Ok(None),
            1 => (),
            _ => return Err(StateError::Corrupt),
        }
        let key = read_bytes(decoder, MAX_STATE_KEY_BYTES)?;
        let value = read_bytes(decoder, MAX_STATE_VALUE_BYTES)?;
        let index = decoder.read_u64()?;
        let leaf_count = decoder.read_u64()?;
        let sibling_count = usize::from(decoder.read_u8()?);
        validate_bounds(key.len(), value.len(), index, leaf_count, sibling_count)?;
        let siblings = decoder.read_exact(sibling_count * 32)?;
        Ok(Some(Self {
            key,
            value,
            index,
            leaf_count,
            siblings,
        }))
    }

    fn into_owned(self) -> StateWitness {
        StateWitness {
            key: StateKey(self.key.to_vec()),
            value: self.value.to_vec(),
            proof: StateProof {
                index: self.index,
                leaf_count: self.leaf_count,
                siblings: self
                    .siblings
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .map(|chunk| {
                        let mut hash = [0; 32];
                        hash.copy_from_slice(chunk);
                        Hash256(hash)
                    })
                    .collect(),
            },
        }
    }
}

fn read_bytes<'a>(decoder: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], StateError> {
    let length = usize::try_from(decoder.read_u64()?).map_err(|_| StateError::LimitExceeded)?;
    if length > max {
        return Err(StateError::LimitExceeded);
    }
    Ok(decoder.read_exact(length)?)
}

fn validate_bounds(
    key_len: usize,
    value_len: usize,
    index: u64,
    leaf_count: u64,
    sibling_count: usize,
) -> Result<(), StateError> {
    if key_len > MAX_STATE_KEY_BYTES
        || value_len > MAX_STATE_VALUE_BYTES
        || leaf_count > MAX_STATE_ENTRIES as u64
        || sibling_count > MAX_SIBLINGS
    {
        return Err(StateError::LimitExceeded);
    }
    if leaf_count == 0 || index >= leaf_count {
        return Err(StateError::Corrupt);
    }
    Ok(())
}
