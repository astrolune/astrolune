// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded append-log payloads. Operation order is preserved, including repeated keys.

use crate::{Checkpoint, CommitBatch, StorageError, archive};
use codec::{CanonicalEncode, DecodeError, Decoder};
use state::{InMemoryState, StateChange, StateDiff};
use types::{Hash256, StateKey};

pub(super) const MAX_RECORD_BYTES: usize = 72 * 1024 * 1024;
const MAX_CHANGES: usize = 1_048_576;

pub(super) enum Record {
    Anchor(Checkpoint, InMemoryState),
    Batch(Box<CommitBatch>),
}

struct Writer(Vec<u8>);
impl Writer {
    fn append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.len() > MAX_RECORD_BYTES - self.0.len() {
            return Err(StorageError::LimitExceeded);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn number(&mut self, n: usize) -> Result<(), StorageError> {
        self.append(&(n as u64).to_le_bytes())
    }
    fn blob(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.number(bytes.len())?;
        self.append(bytes)
    }
}

pub(super) fn anchor(cp: Checkpoint, state: &InMemoryState) -> Result<Vec<u8>, StorageError> {
    let mut out = Writer(vec![0]);
    out.append(&cp.height.to_le_bytes())?;
    out.append(cp.block.as_bytes())?;
    out.append(cp.state_root.as_bytes())?;
    out.blob(&state.export_snapshot())?;
    Ok(out.0)
}

pub(super) fn batch(batch: &CommitBatch) -> Result<Vec<u8>, StorageError> {
    archive::validate_block(&batch.block, &batch.finality_certificate)?;
    if let Some(effects) = &batch.effects {
        effects.validate(&batch.block)?;
    }
    let mut out = Writer(vec![if batch.effects.is_some() { 2 } else { 1 }]);
    out.append(&batch.block.header.canonical_bytes())?;
    out.number(batch.block.transactions.len())?;
    for tx in &batch.block.transactions {
        out.blob(&tx.to_bytes())?;
    }
    out.blob(&batch.finality_certificate)?;
    if batch.state_diffs.len() > MAX_CHANGES {
        return Err(StorageError::LimitExceeded);
    }
    out.number(batch.state_diffs.len())?;
    let mut total = 0usize;
    for diff in &batch.state_diffs {
        total = total
            .checked_add(diff.len())
            .ok_or(StorageError::LimitExceeded)?;
        if total > MAX_CHANGES {
            return Err(StorageError::LimitExceeded);
        }
        out.number(diff.len())?;
        for change in &diff.changes {
            if change.key().len() > state::MAX_STATE_KEY_BYTES {
                return Err(StorageError::LimitExceeded);
            }
            out.append(&[if matches!(change, StateChange::Put(..)) {
                1
            } else {
                2
            }])?;
            out.blob(&change.key().0)?;
            if let StateChange::Put(_, value) = change {
                if value.len() > state::MAX_STATE_VALUE_BYTES {
                    return Err(StorageError::LimitExceeded);
                }
                out.blob(value)?;
            }
        }
    }
    if let Some(effects) = &batch.effects {
        out.blob(&effects.to_bytes()?)?;
    }
    Ok(out.0)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Record, StorageError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    decode_inner(bytes).map_err(|_| StorageError::Corrupt)
}

fn decode_inner(bytes: &[u8]) -> Result<Record, DecodeError> {
    let mut d = Decoder::new(bytes);
    let record = match d.read_u8()? {
        0 => {
            let cp = Checkpoint {
                height: d.read_u64()?,
                block: Hash256(d.read_fixed()?),
                state_root: Hash256(d.read_fixed()?),
            };
            if cp.block.is_zero() {
                return Err(DecodeError::NonCanonical);
            }
            let state = InMemoryState::from_snapshot(
                archive::read_blob(&mut d, state::MAX_SNAPSHOT_BYTES)?,
                cp.state_root,
            )
            .map_err(|_| DecodeError::NonCanonical)?;
            Record::Anchor(cp, state)
        }
        tag @ (1 | 2) => {
            let block = archive::read_block(&mut d)?;
            let finality_certificate = archive::read_blob(&mut d, 1024 * 1024)?.to_vec();
            archive::validate_block(&block, &finality_certificate)
                .map_err(|_| DecodeError::NonCanonical)?;
            let count = archive::length(&mut d, MAX_CHANGES)?;
            if count > d.remaining() / 8 {
                return Err(DecodeError::Truncated);
            }
            let mut state_diffs = Vec::new();
            let mut total = 0;
            for _ in 0..count {
                let changes = archive::length(&mut d, MAX_CHANGES - total)?;
                total += changes;
                if changes > d.remaining() / 9 {
                    return Err(DecodeError::Truncated);
                }
                let mut diff = StateDiff::new();
                for _ in 0..changes {
                    let tag = d.read_u8()?;
                    let key =
                        StateKey(archive::read_blob(&mut d, state::MAX_STATE_KEY_BYTES)?.to_vec());
                    match tag {
                        1 => diff.put(
                            key,
                            archive::read_blob(&mut d, state::MAX_STATE_VALUE_BYTES)?.to_vec(),
                        ),
                        2 => diff.delete(key),
                        _ => return Err(DecodeError::NonCanonical),
                    }
                }
                state_diffs.push(diff);
            }
            let effects = if tag == 2 {
                let effects = crate::BlockEffects::from_bytes(archive::read_blob(
                    &mut d,
                    crate::MAX_RECEIPTS_BYTES,
                )?)
                .map_err(|_| DecodeError::NonCanonical)?;
                effects
                    .validate(&block)
                    .map_err(|_| DecodeError::NonCanonical)?;
                Some(effects)
            } else {
                None
            };
            Record::Batch(Box::new(CommitBatch {
                block,
                finality_certificate,
                state_diffs,
                effects,
            }))
        }
        _ => return Err(DecodeError::NonCanonical),
    };
    d.finish()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reencode(record: &Record) -> Vec<u8> {
        match record {
            Record::Anchor(cp, state) => anchor(*cp, state).unwrap(),
            Record::Batch(value) => batch(value).unwrap(),
        }
    }

    #[test]
    fn payloads_reject_truncation_and_every_accepted_mutation_is_canonical() {
        let state = InMemoryState::new();
        let cp = Checkpoint {
            height: 0,
            block: Hash256([1; 32]),
            state_root: state.root(),
        };
        let mut diff = StateDiff::new();
        diff.put(StateKey(vec![1]), vec![3]);
        diff.delete(StateKey(vec![1]));
        diff.put(StateKey(vec![1]), vec![5]);
        let batch_value = CommitBatch {
            effects: None,
            block: types::Block {
                header: types::BlockHeader {
                    height: 1,
                    parent: cp.block,
                    state_root: state.prepare(state.root(), &[diff.clone()]).unwrap().root(),
                    transactions_root: Hash256::ZERO,
                    receipts_root: Hash256::ZERO,
                    committee_root: Hash256::ZERO,
                    capacity: types::Resources::ZERO,
                },
                transactions: vec![],
            },
            finality_certificate: vec![3, 4],
            state_diffs: vec![diff],
        };
        let encoded = batch(&batch_value).unwrap();
        let Record::Batch(decoded) = decode(&encoded).unwrap() else {
            panic!("expected batch")
        };
        assert_eq!(*decoded, batch_value);
        for bytes in [anchor(cp, &state).unwrap(), encoded] {
            for at in 0..bytes.len() {
                assert!(decode(&bytes[..at]).is_err());
                for mask in [1, 128, 255] {
                    let mut mutated = bytes.clone();
                    mutated[at] ^= mask;
                    if let Ok(accepted) = decode(&mutated) {
                        assert_eq!(reencode(&accepted), mutated);
                    }
                }
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode(&trailing).is_err());
        }
    }
}
