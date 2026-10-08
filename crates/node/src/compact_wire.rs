// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Optional compact transport around unchanged reference-network messages.
//!
//! Full transaction identifiers refer only to an owned request-time dictionary.
//! Reconstructed messages still require the receiving node's usual validation.

use crate::network_wire::{
    MAX_BLOCK_BYTES, MAX_EXCHANGE_BYTES, MAX_TRANSACTION_BYTES, NetworkMessage, SyncRequest,
    decode_exchange, encode_block, encode_exchange,
};
use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use std::collections::BTreeMap;
use types::{Block, Hash256, Transaction};

/// Maximum transaction identifiers advertised in a compact request.
pub const MAX_KNOWN_TRANSACTIONS: usize = 256;
/// Maximum canonical transaction bytes retained across one request.
pub const MAX_DICTIONARY_BYTES: usize = 2 * 1024 * 1024;
/// Maximum unwrapped compact request, including all full identifiers.
pub const MAX_COMPACT_REQUEST_BYTES: usize = 50 + MAX_KNOWN_TRANSACTIONS * 32;
const REQUEST_MAGIC: &[u8; 8] = b"ALCQ\x01\0\0\0";
const RESPONSE_MAGIC: &[u8; 8] = b"ALCX\x01\0\0\0";
const LEGACY_MAGIC: &[u8; 8] = b"ALNX\x01\0\0\0";

struct KnownTransaction {
    transaction: Transaction,
    encoded_len: usize,
}

/// Bounded owned transactions retained until a response has been reconstructed.
#[derive(Default)]
pub struct TransactionDictionary {
    transactions: BTreeMap<Hash256, KnownTransaction>,
}

impl TransactionDictionary {
    /// Examines at most 256 candidates, skipping oversized or noncanonical entries.
    #[must_use]
    pub fn new(transactions: impl IntoIterator<Item = Transaction>) -> Self {
        let mut dictionary = Self::default();
        let mut total = 0;
        for transaction in transactions.into_iter().take(MAX_KNOWN_TRANSACTIONS) {
            if transaction::estimate_encoded_len(&transaction) > MAX_TRANSACTION_BYTES {
                continue;
            }
            let bytes = transaction.to_bytes();
            if bytes.len() > MAX_TRANSACTION_BYTES
                || total + bytes.len() > MAX_DICTIONARY_BYTES
                || Transaction::decode(&bytes).is_err()
            {
                continue;
            }
            let id = crate::hash_transaction(&transaction);
            if dictionary.transactions.contains_key(&id) {
                continue;
            }
            total += bytes.len();
            dictionary.transactions.insert(
                id,
                KnownTransaction {
                    transaction,
                    encoded_len: bytes.len(),
                },
            );
        }
        dictionary
    }
}

/// A normal synchronization request accompanied by sorted full transaction IDs.
#[derive(Debug, Eq, PartialEq)]
pub struct CompactRequest {
    sync: SyncRequest,
    known: Vec<Hash256>,
}

impl CompactRequest {
    /// Advertises exactly the owned dictionary retained by the requester.
    #[must_use]
    pub fn new(sync: SyncRequest, dictionary: &TransactionDictionary) -> Self {
        Self {
            sync,
            known: dictionary.transactions.keys().copied().collect(),
        }
    }

    /// Returns the unchanged height and genesis selection.
    #[must_use]
    pub fn sync(&self) -> SyncRequest {
        self.sync
    }

    /// Returns the sorted full transaction IDs available to the requester.
    #[must_use]
    pub fn known(&self) -> &[Hash256] {
        &self.known
    }

    /// Encodes the separate compact request format without changing `ALRQ`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = REQUEST_MAGIC.to_vec();
        bytes.extend_from_slice(self.sync.genesis.as_bytes());
        bytes.extend_from_slice(&self.sync.height.to_le_bytes());
        #[allow(clippy::cast_possible_truncation)] // Both constructors bound this to 256 ids.
        let count = self.known.len() as u16;
        bytes.extend_from_slice(&count.to_le_bytes());
        for id in &self.known {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes
    }

    /// Decodes the bounded request and requires strictly increasing identifiers.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_COMPACT_REQUEST_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut reader = Decoder::new(bytes);
        if reader.read_fixed::<8>()? != *REQUEST_MAGIC {
            return Err(DecodeError::Unsupported);
        }
        let sync = SyncRequest {
            genesis: Hash256(reader.read_fixed()?),
            height: reader.read_u64()?,
        };
        let count = usize::from(reader.read_u16()?);
        if count > MAX_KNOWN_TRANSACTIONS || count > reader.remaining() / 32 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut known = Vec::with_capacity(count);
        for _ in 0..count {
            known.push(Hash256(reader.read_fixed()?));
        }
        reader.finish()?;
        check_known(&known)?;
        Ok(Self { sync, known })
    }
}

fn check_known(known: &[Hash256]) -> Result<(), DecodeError> {
    if known.len() > MAX_KNOWN_TRANSACTIONS {
        return Err(DecodeError::LimitExceeded);
    }
    if known.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn block_mut(message: &mut NetworkMessage) -> Option<&mut Block> {
    match message {
        NetworkMessage::Proposal { block, .. }
        | NetworkMessage::Finalized { block, .. }
        | NetworkMessage::ValidValue { block, .. } => Some(block),
        _ => None,
    }
}

fn append(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), DecodeError> {
    if bytes.len().saturating_add(value.len()) > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    bytes.extend_from_slice(value);
    Ok(())
}

fn put_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), DecodeError> {
    let count = u32::try_from(value.len()).map_err(|_| DecodeError::LimitExceeded)?;
    append(bytes, &count.to_le_bytes())?;
    append(bytes, value)
}

/// Encodes compact block bodies only when the complete response is smaller.
/// Other messages and the legacy fallback retain their original canonical bytes.
pub fn encode_response(
    genesis: Hash256,
    messages: &[NetworkMessage],
    known: &[Hash256],
) -> Result<Vec<u8>, DecodeError> {
    check_known(known)?;
    let legacy = encode_exchange(genesis, messages)?;
    if known.is_empty() {
        return Ok(legacy);
    }
    let mut skeleton = messages.to_vec();
    let bodies: Vec<_> = skeleton
        .iter_mut()
        .filter_map(block_mut)
        .map(|block| std::mem::take(&mut block.transactions))
        .collect();
    if bodies.is_empty() {
        return Ok(legacy);
    }
    let encode_compact = || {
        let skeleton = encode_exchange(genesis, &skeleton)?;
        let mut bytes = RESPONSE_MAGIC.to_vec();
        put_blob(&mut bytes, &skeleton)?;
        for transactions in bodies {
            let count =
                u16::try_from(transactions.len()).map_err(|_| DecodeError::LimitExceeded)?;
            append(&mut bytes, &count.to_le_bytes())?;
            for transaction in transactions {
                let id = crate::hash_transaction(&transaction);
                if known.binary_search(&id).is_ok() {
                    append(&mut bytes, &[0])?;
                    append(&mut bytes, id.as_bytes())?;
                } else {
                    append(&mut bytes, &[1])?;
                    put_blob(&mut bytes, &transaction.to_bytes())?;
                }
            }
        }
        Ok(bytes)
    };
    match encode_compact() {
        Ok(compact) if compact.len() < legacy.len() => Ok(compact),
        Ok(_) | Err(DecodeError::LimitExceeded) => Ok(legacy),
        Err(error) => Err(error),
    }
}

fn charge(block: &mut usize, exchange: &mut usize, length: usize) -> Result<(), DecodeError> {
    let length = length.checked_add(4).ok_or(DecodeError::LimitExceeded)?;
    *block = block
        .checked_add(length)
        .ok_or(DecodeError::LimitExceeded)?;
    *exchange = exchange
        .checked_add(length)
        .ok_or(DecodeError::LimitExceeded)?;
    if *block > MAX_BLOCK_BYTES || *exchange > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(())
}

/// Reconstructs an entire compact response, or decodes an unchanged legacy fallback.
/// Expanded byte limits are checked before cloning any referenced transaction.
pub fn decode_response(
    genesis: Hash256,
    bytes: &[u8],
    dictionary: &TransactionDictionary,
) -> Result<Vec<NetworkMessage>, DecodeError> {
    if bytes.starts_with(LEGACY_MAGIC) {
        return decode_exchange(genesis, bytes);
    }
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut reader = Decoder::new(bytes);
    if reader.read_fixed::<8>()? != *RESPONSE_MAGIC {
        return Err(DecodeError::Unsupported);
    }
    let length = usize::try_from(reader.read_u32()?).map_err(|_| DecodeError::LimitExceeded)?;
    if length > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let skeleton = reader.read_exact(length)?;
    let mut messages = decode_exchange(genesis, skeleton)?;
    let mut exchange_bytes = length;
    for block in messages.iter_mut().filter_map(block_mut) {
        if !block.transactions.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let count = usize::from(reader.read_u16()?);
        if count > 256 || count > reader.remaining() / 5 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut block_bytes = encode_block(block)?.len();
        for _ in 0..count {
            let transaction = match reader.read_u8()? {
                0 => {
                    let id = Hash256(reader.read_fixed()?);
                    let known = dictionary
                        .transactions
                        .get(&id)
                        .ok_or(DecodeError::Unsupported)?;
                    charge(&mut block_bytes, &mut exchange_bytes, known.encoded_len)?;
                    known.transaction.clone()
                }
                1 => {
                    let length = usize::try_from(reader.read_u32()?)
                        .map_err(|_| DecodeError::LimitExceeded)?;
                    if length > MAX_TRANSACTION_BYTES {
                        return Err(DecodeError::LimitExceeded);
                    }
                    charge(&mut block_bytes, &mut exchange_bytes, length)?;
                    Transaction::decode(reader.read_exact(length)?)?
                }
                _ => return Err(DecodeError::Unsupported),
            };
            block.transactions.push(transaction);
        }
    }
    reader.finish()?;
    Ok(messages)
}
