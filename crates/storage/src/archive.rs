// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded whole-chain reference archive. Checksums detect corruption, not finality.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use state::{InMemoryState, MAX_SNAPSHOT_BYTES};
use types::{Block, BlockHeader, Hash256, Transaction, hash::domain_hash};

use crate::{
    Checkpoint, InMemoryStorage, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_CHECKPOINTS, StorageError,
};

const MAGIC: &[u8; 8] = b"ASTSTORE";
const VERSION: u16 = 2;
const CHECKSUM_DOMAIN: &[u8] = b"astrolune.storage.archive.v1";
const MAX_TRANSACTIONS: usize = 65_536;
const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;

pub(super) fn validate_block(block: &Block, certificate: &[u8]) -> Result<(), StorageError> {
    if block.transactions.len() > MAX_TRANSACTIONS || certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    let mut size = 200_usize;
    for tx in &block.transactions {
        if tx.version != types::TRANSACTION_VERSION {
            return Err(StorageError::VerificationFailed);
        }
        if tx.access_list.len() > codec::MAX_LIST_LEN
            || tx
                .access_list
                .iter()
                .any(|key| key.0.len() > codec::MAX_STATE_KEY_LEN)
            || tx.payload.len() > codec::MAX_PAYLOAD
            || transaction::estimate_encoded_len(tx) > MAX_TRANSACTION_BYTES
        {
            return Err(StorageError::LimitExceeded);
        }
        size = size
            .checked_add(transaction::estimate_encoded_len(tx) + 8)
            .ok_or(StorageError::LimitExceeded)?;
        if size > MAX_ARCHIVE_BYTES {
            return Err(StorageError::LimitExceeded);
        }
    }
    let leaves: Vec<_> = block
        .transactions
        .iter()
        .map(transaction::compute_tx_id)
        .collect();
    if crypto::compute_transactions_root(&leaves) != block.header.transactions_root {
        return Err(StorageError::VerificationFailed);
    }
    Ok(())
}

pub(super) fn encode(storage: &InMemoryStorage) -> Result<Vec<u8>, StorageError> {
    if storage.checkpoints.len() > MAX_ARCHIVE_CHECKPOINTS {
        return Err(StorageError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    let version = if storage.effects.is_empty() {
        VERSION
    } else {
        3
    };
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&(storage.checkpoints.len() as u64).to_le_bytes());
    for checkpoint in storage.checkpoints.values() {
        append(&mut bytes, &checkpoint.height.to_le_bytes())?;
        append(&mut bytes, checkpoint.block.as_bytes())?;
        append(&mut bytes, checkpoint.state_root.as_bytes())?;
        let state = storage
            .snapshots
            .get(&checkpoint.height)
            .ok_or(StorageError::Corrupt)?;
        blob(&mut bytes, &state.export_snapshot())?;
        if let Some(block) = storage.blocks.get(&checkpoint.block) {
            let certificate = storage
                .certificates
                .get(&checkpoint.block)
                .ok_or(StorageError::Corrupt)?;
            validate_block(block, certificate)?;
            let effects = storage.effects.get(&checkpoint.height);
            append(&mut bytes, &[if effects.is_some() { 2 } else { 1 }])?;
            append(&mut bytes, &block.header.canonical_bytes())?;
            append(&mut bytes, &(block.transactions.len() as u64).to_le_bytes())?;
            for tx in &block.transactions {
                blob(&mut bytes, &tx.to_bytes())?;
            }
            blob(&mut bytes, certificate)?;
            if let Some(effects) = effects {
                effects.validate(block)?;
                blob(&mut bytes, &effects.to_bytes()?)?;
            }
        } else {
            append(&mut bytes, &[0])?;
        }
    }
    let checksum = domain_hash(CHECKSUM_DOMAIN, &bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    Ok(bytes)
}

fn append(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), StorageError> {
    if value.len() > MAX_ARCHIVE_BYTES - 32 - bytes.len() {
        return Err(StorageError::LimitExceeded);
    }
    bytes.extend_from_slice(value);
    Ok(())
}

fn blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), StorageError> {
    append(bytes, &(value.len() as u64).to_le_bytes())?;
    append(bytes, value)
}

pub(super) fn decode(bytes: &[u8]) -> Result<InMemoryStorage, StorageError> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    let checksum_at = bytes.len().checked_sub(32).ok_or(StorageError::Corrupt)?;
    let (payload, checksum) = bytes.split_at(checksum_at);
    if domain_hash(CHECKSUM_DOMAIN, payload).as_bytes() != checksum {
        return Err(StorageError::Corrupt);
    }
    decode_payload(payload).map_err(|_| StorageError::Corrupt)
}

fn decode_payload(payload: &[u8]) -> Result<InMemoryStorage, DecodeError> {
    let mut decoder = Decoder::new(payload);
    if decoder.read_exact(8)? != MAGIC {
        return Err(DecodeError::NonCanonical);
    }
    let version = decoder.read_u16()?;
    if version != VERSION && version != 3 {
        return Err(DecodeError::Unsupported);
    }
    let count = length(&mut decoder, MAX_ARCHIVE_CHECKPOINTS)?;
    // Every checkpoint needs 72 fixed bytes, snapshot framing, and a presence byte.
    if count > decoder.remaining() / 81 {
        return Err(DecodeError::Truncated);
    }
    let mut storage = InMemoryStorage::new();
    for index in 0..count {
        let checkpoint = Checkpoint {
            height: decoder.read_u64()?,
            block: Hash256(decoder.read_fixed()?),
            state_root: Hash256(decoder.read_fixed()?),
        };
        if checkpoint.block.is_zero()
            || storage
                .checkpoint()
                .is_some_and(|previous| previous.height.checked_add(1) != Some(checkpoint.height))
        {
            return Err(DecodeError::NonCanonical);
        }
        let state = InMemoryState::from_snapshot(
            read_blob(&mut decoder, MAX_SNAPSHOT_BYTES)?,
            checkpoint.state_root,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        match decoder.read_u8()? {
            0 if index == 0 => (), // Imported anchor: body and certificate are unknown.
            tag @ (1 | 2) if tag == 1 || version == 3 => {
                let block = read_block(&mut decoder)?;
                let certificate = read_blob(&mut decoder, MAX_CERTIFICATE_BYTES)?;
                if block.header.height != checkpoint.height
                    || block.header.state_root != checkpoint.state_root
                    || block.header.compute_hash() != checkpoint.block
                    || (checkpoint.height == 0 && block.header.parent != Hash256::ZERO)
                    || storage
                        .checkpoint()
                        .is_some_and(|previous| block.header.parent != previous.block)
                {
                    return Err(DecodeError::NonCanonical);
                }
                validate_block(&block, certificate).map_err(|_| DecodeError::NonCanonical)?;
                if tag == 2 {
                    let effects = crate::BlockEffects::from_bytes(read_blob(
                        &mut decoder,
                        crate::MAX_RECEIPTS_BYTES,
                    )?)
                    .map_err(|_| DecodeError::NonCanonical)?;
                    effects
                        .validate(&block)
                        .map_err(|_| DecodeError::NonCanonical)?;
                    storage.effects.insert(checkpoint.height, effects);
                }
                storage.transactions.insert(&block);
                storage.blocks.insert(checkpoint.block, block);
                storage
                    .certificates
                    .insert(checkpoint.block, certificate.to_vec());
            }
            _ => return Err(DecodeError::NonCanonical),
        }
        storage.snapshots.insert(checkpoint.height, state.clone());
        storage.state = state;
        storage.checkpoints.insert(checkpoint.height, checkpoint);
    }
    decoder.finish()?;
    Ok(storage)
}

pub(super) fn read_block(decoder: &mut Decoder<'_>) -> Result<Block, DecodeError> {
    let header = BlockHeader::decode(decoder.read_exact(200)?)?;
    let count = length(decoder, MAX_TRANSACTIONS)?;
    if count > decoder.remaining() / 150 {
        return Err(DecodeError::Truncated);
    }
    let mut transactions = Vec::new();
    for _ in 0..count {
        transactions.push(Transaction::decode(read_blob(
            decoder,
            MAX_TRANSACTION_BYTES,
        )?)?);
    }
    Ok(Block {
        header,
        transactions,
    })
}

pub(super) fn length(decoder: &mut Decoder<'_>, limit: usize) -> Result<usize, DecodeError> {
    let value = usize::try_from(decoder.read_u64()?).map_err(|_| DecodeError::LimitExceeded)?;
    if value > limit {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(value)
}

pub(super) fn read_blob<'a>(
    decoder: &mut Decoder<'a>,
    limit: usize,
) -> Result<&'a [u8], DecodeError> {
    let size = length(decoder, limit)?;
    decoder.read_exact(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitBatch, NodeStorage};
    use types::Resources;

    fn fixture() -> Vec<u8> {
        let mut storage = InMemoryStorage::new();
        for height in 0..2 {
            let parent = storage.checkpoint().map_or(Hash256::ZERO, |cp| cp.block);
            storage
                .commit(&CommitBatch {
                    effects: None,
                    block: Block {
                        header: BlockHeader {
                            height,
                            parent,
                            state_root: storage.state.root(),
                            transactions_root: Hash256::ZERO,
                            receipts_root: Hash256::ZERO,
                            committee_root: Hash256::ZERO,
                            capacity: Resources::ZERO,
                        },
                        transactions: vec![],
                    },
                    finality_certificate: vec![1, 2],
                    state_diffs: vec![],
                })
                .unwrap();
        }
        encode(&storage).unwrap()
    }

    fn checksum(bytes: &mut [u8]) {
        let at = bytes.len() - 32;
        let digest = domain_hash(CHECKSUM_DOMAIN, &bytes[..at]);
        bytes[at..].copy_from_slice(digest.as_bytes());
    }

    #[test]
    fn all_truncations_and_single_byte_mutations_fail_closed() {
        let bytes = fixture();
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
        for at in 0..bytes.len() {
            assert!(decode(&bytes[..at]).is_err(), "truncation {at}");
            let mut altered = bytes.clone();
            altered[at] ^= 1;
            assert!(decode(&altered).is_err(), "mutation {at}");
        }
    }

    #[test]
    fn structure_is_checked_even_with_a_valid_checksum() {
        let bytes = fixture();
        // Header 18, checkpoint 72, snapshot length 8, empty snapshot 50,
        // presence 1, block header 200, transaction count 8, certificate length 8 + 2.
        for (offset, value) in [
            (8, 1),
            (8, 4),
            (10, 255),
            (18, 1),
            (90, 255),
            (148, 2),
            (149, 1),
            (189, 1),
            (349, 255),
            (357, 255),
            (367, 0),
        ] {
            let mut altered = bytes.clone();
            altered[offset] = value;
            checksum(&mut altered);
            assert!(decode(&altered).is_err(), "offset {offset}");
        }
        let mut extra = bytes[..bytes.len() - 32].to_vec();
        extra.push(0);
        extra.extend_from_slice(&[0; 32]);
        checksum(&mut extra);
        assert!(decode(&extra).is_err());
    }
}
