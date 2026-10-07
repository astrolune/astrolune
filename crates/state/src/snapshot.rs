// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded, versioned snapshot bytes shared by persistence and state exchange.

use std::collections::BTreeMap;

use codec::{DecodeError, Decoder};
use types::{Hash256, StateKey};

use crate::{StateChange, StateDiff, StateError, commitment};

/// Maximum number of entries in the reference state backend.
pub const MAX_STATE_ENTRIES: usize = 1_048_576;
/// Maximum encoded state key size.
pub const MAX_STATE_KEY_BYTES: usize = 256;
/// Maximum individual state value size.
pub const MAX_STATE_VALUE_BYTES: usize = 1_048_576;
/// Maximum complete snapshot size, including framing and commitment.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"ASTSTATE";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + 8 + 32;

pub(crate) fn stage(
    data: &BTreeMap<StateKey, Vec<u8>>,
    diffs: &[StateDiff],
) -> Result<BTreeMap<StateKey, Vec<u8>>, StateError> {
    let mut next = data.clone();
    let mut size = encoded_size(data)?;
    for diff in diffs {
        for change in &diff.changes {
            if change.key().len() > MAX_STATE_KEY_BYTES {
                return Err(StateError::LimitExceeded);
            }
            match change {
                StateChange::Put(key, value) => {
                    if value.len() > MAX_STATE_VALUE_BYTES {
                        return Err(StateError::LimitExceeded);
                    }
                    if let Some(old) = next.get(key) {
                        size -= entry_size(key, old);
                    }
                    size = size
                        .checked_add(entry_size(key, value))
                        .ok_or(StateError::LimitExceeded)?;
                    if size > MAX_SNAPSHOT_BYTES
                        || (!next.contains_key(key) && next.len() == MAX_STATE_ENTRIES)
                    {
                        return Err(StateError::LimitExceeded);
                    }
                    next.insert(key.clone(), value.clone());
                }
                StateChange::Delete(key) => {
                    if let Some(old) = next.remove(key) {
                        size -= entry_size(key, &old);
                    }
                }
            }
        }
    }
    Ok(next)
}

pub(crate) fn encode(data: &BTreeMap<StateKey, Vec<u8>>, root: Hash256) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
    bytes.extend_from_slice(root.as_bytes());
    for (key, value) in data {
        bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(BTreeMap<StateKey, Vec<u8>>, Hash256), StateError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(StateError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.read_exact(8)? != MAGIC || decoder.read_u16()? != VERSION {
        return Err(StateError::Corrupt);
    }
    let count = bounded_length(&mut decoder, MAX_STATE_ENTRIES)?;
    let root = Hash256(decoder.read_fixed()?);
    let entries = decoder;
    let mut previous: Option<&[u8]> = None;
    // Validate ordering, bounds, and complete framing before allocating entry values.
    for _ in 0..count {
        let key = read_bytes(&mut decoder, MAX_STATE_KEY_BYTES)?;
        if previous.is_some_and(|p| p >= key) {
            return Err(StateError::Corrupt);
        }
        previous = Some(key);
        read_bytes(&mut decoder, MAX_STATE_VALUE_BYTES)?;
    }
    decoder.finish()?;
    let mut decoder = entries;
    let mut data = BTreeMap::new();
    for _ in 0..count {
        let key = StateKey(read_bytes(&mut decoder, MAX_STATE_KEY_BYTES)?.to_vec());
        let value = read_bytes(&mut decoder, MAX_STATE_VALUE_BYTES)?.to_vec();
        data.insert(key, value);
    }
    if commitment::compute_root(&data) != root {
        return Err(StateError::RootMismatch);
    }
    Ok((data, root))
}

fn read_bytes<'a>(decoder: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], StateError> {
    let length = bounded_length(decoder, max)?;
    Ok(decoder.read_exact(length)?)
}

fn bounded_length(decoder: &mut Decoder<'_>, max: usize) -> Result<usize, StateError> {
    let length = usize::try_from(decoder.read_u64()?).map_err(|_| StateError::LimitExceeded)?;
    if length > max {
        return Err(StateError::LimitExceeded);
    }
    Ok(length)
}

fn entry_size(key: &StateKey, value: &[u8]) -> usize {
    16 + key.len() + value.len()
}

fn encoded_size(data: &BTreeMap<StateKey, Vec<u8>>) -> Result<usize, StateError> {
    data.iter().try_fold(HEADER_BYTES, |size, (key, value)| {
        size.checked_add(entry_size(key, value))
            .ok_or(StateError::LimitExceeded)
    })
}

impl From<DecodeError> for StateError {
    fn from(_: DecodeError) -> Self {
        Self::Corrupt
    }
}
