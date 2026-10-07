// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical encoding and decoding for `AstroLune` protocol types.
//!
//! Each protocol type has a single, unambiguous byte representation. All
//! multi-byte integers are little-endian. Length-prefixed sequences use the
//! compact 1-byte / 5-byte encoding defined in the parent module.

use crate::decoder::Decoder;
use crate::error::DecodeError;
use crate::traits::{CanonicalDecode, CanonicalEncode, DecodeAt, DecoderExt};
use types::{
    AccountState, Address, BlockHeader, ExecutionReceipt, Hash256, Resources, StateKey,
    Transaction, ValidatorId,
};

impl CanonicalEncode for AccountState {
    fn encode(&self, output: &mut Vec<u8>) {
        self.nonce.encode(output);
        self.balance.encode(output);
    }
}

impl CanonicalDecode for AccountState {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let account = Self {
            nonce: decoder.read_u64()?,
            balance: decoder.read_u64()?,
        };
        decoder.finish()?;
        Ok(account)
    }
}

impl CanonicalEncode for Hash256 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for Hash256 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for Address {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for Address {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for ValidatorId {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for ValidatorId {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for StateKey {
    fn encode(&self, output: &mut Vec<u8>) {
        super::encode_bytes(&self.0, output);
    }
}

impl CanonicalDecode for StateKey {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let key = super::decode_bytes(&mut decoder, super::MAX_STATE_KEY_LEN)?;
        decoder.finish()?;
        Ok(Self(key.to_vec()))
    }
}

impl CanonicalEncode for Resources {
    fn encode(&self, output: &mut Vec<u8>) {
        self.compute.encode(output);
        self.memory.encode(output);
        self.io.encode(output);
        self.bandwidth.encode(output);
    }
}

impl CanonicalDecode for Resources {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let compute = decoder.read_u64()?;
        let memory = decoder.read_u64()?;
        let io = decoder.read_u64()?;
        let bandwidth = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self {
            compute,
            memory,
            io,
            bandwidth,
        })
    }
}

impl CanonicalEncode for Transaction {
    fn encode(&self, output: &mut Vec<u8>) {
        encode_unsigned_transaction(self, output);
        output.extend_from_slice(&self.signature);
    }
}

/// Appends the canonical transaction fields covered by its signature.
pub fn encode_unsigned_transaction(transaction: &Transaction, output: &mut Vec<u8>) {
    output.extend_from_slice(b"ALTX");
    transaction.version.encode(output);
    transaction.chain_id.encode(output);
    transaction.sender.encode(output);
    transaction.nonce.encode(output);
    transaction.expires_at.encode(output);
    output.push(transaction.lane as u8);
    super::encode_length(transaction.access_list.len(), output);
    for key in &transaction.access_list {
        key.encode(output);
    }
    transaction.resource_limit.encode(output);
    transaction.resource_prices.encode(output);
    super::encode_bytes(&transaction.payload, output);
}

impl CanonicalDecode for Transaction {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);

        if decoder.read_fixed::<4>()? != *b"ALTX" {
            return Err(DecodeError::Unsupported);
        }
        let version = decoder.read_u32()?;
        if version != types::TRANSACTION_VERSION {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;

        let sender_bytes = decoder.read_fixed::<32>()?;
        let sender = Address(sender_bytes);

        let nonce = decoder.read_u64()?;
        let expires_at = decoder.read_u64()?;
        let lane = match decoder.read_u8()? {
            0 => types::TransactionLane::Payments,
            1 => types::TransactionLane::Contracts,
            2 => types::TransactionLane::System,
            _ => return Err(DecodeError::Unsupported),
        };

        let list_len = super::decode_length(&mut decoder)?;
        if list_len > super::MAX_LIST_LEN {
            return Err(DecodeError::LimitExceeded);
        }
        if list_len > decoder.remaining() {
            return Err(DecodeError::Truncated);
        }
        let mut access_decoder = decoder;

        // Validate the entire envelope before allocating owned keys or payload.
        for _ in 0..list_len {
            super::decode_bytes(&mut decoder, super::MAX_STATE_KEY_LEN)?;
        }

        let resource_limit = Resources::decode_at(&mut decoder)?;
        let resource_prices = Resources::decode_at(&mut decoder)?;

        let payload = super::decode_bytes(&mut decoder, super::MAX_PAYLOAD)?;

        let signature: [u8; 64] = decoder.read_fixed::<64>()?;

        decoder.finish()?;

        let mut access_list = Vec::with_capacity(list_len);
        for _ in 0..list_len {
            access_list.push(StateKey::decode_at(&mut access_decoder)?);
        }

        Ok(Self {
            version,
            expires_at,
            lane,
            resource_prices,
            chain_id,
            sender,
            nonce,
            access_list,
            resource_limit,
            payload: payload.to_vec(),
            signature,
        })
    }
}

impl CanonicalEncode for BlockHeader {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.canonical_bytes());
    }
}

impl CanonicalDecode for BlockHeader {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);

        let height = decoder.read_u64()?;
        let parent = Hash256(decoder.read_fixed::<32>()?);
        let transactions_root = Hash256(decoder.read_fixed::<32>()?);
        let state_root = Hash256(decoder.read_fixed::<32>()?);
        let receipts_root = Hash256(decoder.read_fixed::<32>()?);
        let committee_root = Hash256(decoder.read_fixed::<32>()?);
        let capacity = Resources::decode_at(&mut decoder)?;

        decoder.finish()?;

        Ok(Self {
            height,
            parent,
            transactions_root,
            state_root,
            receipts_root,
            committee_root,
            capacity,
        })
    }
}

impl<'a> DecoderExt<'a> for Decoder<'a> {
    fn read_state_key(&mut self) -> Result<StateKey, DecodeError> {
        let key = super::decode_bytes(self, super::MAX_STATE_KEY_LEN)?;
        Ok(StateKey(key.to_vec()))
    }

    fn read_resources(&mut self) -> Result<Resources, DecodeError> {
        let compute = self.read_u64()?;
        let memory = self.read_u64()?;
        let io = self.read_u64()?;
        let bandwidth = self.read_u64()?;
        Ok(Resources {
            compute,
            memory,
            io,
            bandwidth,
        })
    }
}

impl DecodeAt for StateKey {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_state_key()
    }
}

impl DecodeAt for Resources {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_resources()
    }
}

impl CanonicalEncode for ExecutionReceipt {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.canonical_bytes());
    }
}

impl CanonicalDecode for ExecutionReceipt {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let transaction = Hash256(dec.read_fixed::<32>()?);
        let succeeded = match dec.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::NonCanonical),
        };
        let resources = Resources::decode_at(&mut dec)?;
        let output_root = Hash256(dec.read_fixed::<32>()?);
        dec.finish()?;
        Ok(Self {
            transaction,
            succeeded,
            resources,
            output_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CanonicalEncode;

    #[test]
    fn oversized_access_count_fails_before_reading_or_allocating_keys() {
        let mut bytes = b"ALTX".to_vec();
        bytes.extend_from_slice(&types::TRANSACTION_VERSION.to_le_bytes());
        bytes.resize(61, 0);
        crate::encode_length(crate::MAX_LIST_LEN + 1, &mut bytes);
        assert_eq!(Transaction::decode(&bytes), Err(DecodeError::LimitExceeded));
    }

    #[test]
    fn hash256_roundtrip() {
        let hash = Hash256([0xAB; 32]);
        let encoded = hash.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Hash256::decode(&encoded).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn address_roundtrip() {
        let addr = Address([0x42; 32]);
        let encoded = addr.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn validator_id_roundtrip() {
        let vid = ValidatorId([0x99; 32]);
        let encoded = vid.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = ValidatorId::decode(&encoded).unwrap();
        assert_eq!(vid, decoded);
    }

    #[test]
    fn state_key_roundtrip() {
        let key = StateKey(vec![1, 2, 3, 4, 5]);
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn state_key_empty_roundtrip() {
        let key = StateKey(Vec::new());
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn resources_roundtrip() {
        let r = Resources {
            compute: 100,
            memory: 200,
            io: 300,
            bandwidth: 400,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn resources_nonzero_roundtrip() {
        let r = Resources {
            compute: 18_446_744_073_709_551_615,
            memory: 123_456_789,
            io: 987_654_321,
            bandwidth: 42,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: Address([1u8; 32]),
            nonce: 42,
            access_list: vec![StateKey(vec![10, 20])],
            resource_limit: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            payload: vec![0xDE, 0xAD],
            signature: [0xBE; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn transaction_empty_access_list() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: Address::ZERO,
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn transaction_roundtrip_many_access_list_entries() {
        let access_list: Vec<StateKey> = (0u8..100).map(|i| StateKey(vec![i; 10])).collect();
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: u32::MAX,
            sender: Address([0xFF; 32]),
            nonce: u64::MAX,
            access_list,
            resource_limit: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
            payload: vec![0xDE; 512],
            signature: [0xAD; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn block_header_roundtrip() {
        let header = BlockHeader {
            height: 100,
            parent: Hash256([1u8; 32]),
            transactions_root: Hash256([2u8; 32]),
            state_root: Hash256([3u8; 32]),
            receipts_root: Hash256([4u8; 32]),
            committee_root: Hash256([5u8; 32]),
            capacity: Resources {
                compute: 10,
                memory: 20,
                io: 30,
                bandwidth: 40,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn block_header_roundtrip_all_max() {
        let header = BlockHeader {
            height: u64::MAX,
            parent: Hash256([0xFF; 32]),
            transactions_root: Hash256([0xFF; 32]),
            state_root: Hash256([0xFF; 32]),
            receipts_root: Hash256([0xFF; 32]),
            committee_root: Hash256([0xFF; 32]),
            capacity: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn golden_resources_zero() {
        let r = Resources::ZERO;
        let encoded = r.to_bytes();
        assert_eq!(encoded, [0u8; 32]);
    }

    #[test]
    fn golden_transaction_minimal() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: Address([0xAA; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0xBB; 64],
        };
        let encoded = tx.to_bytes();
        // 8 (magic/version) + 4 (chain) + 32 (sender) + 8 (nonce) + 8 (expiry)
        //   + 1 (lane) + 1 (list) + 64 (limits/prices) + 1 (payload) + 64 (signature).
        assert_eq!(encoded.len(), 191);
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn golden_transaction_with_access_list() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 42,
            sender: Address([0x11; 32]),
            nonce: 99,
            access_list: vec![StateKey(vec![1, 2, 3]), StateKey(vec![4, 5])],
            resource_limit: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: [0xCC; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
        // Access list: list prefix (1) + key1 (1+3) + key2 (1+2) = 8
        assert!(encoded.len() > 191);
    }

    #[test]
    fn golden_block_header_all_zeros() {
        let header = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let encoded = header.to_bytes();
        assert_eq!(encoded, [0u8; 200]);
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn state_key_length_boundary() {
        let max_key = StateKey::new(vec![0xAA; 256]).unwrap();
        let encoded = max_key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(max_key, decoded);

        let over_max = StateKey(vec![0xBB; 257]);
        let encoded = over_max.to_bytes();
        assert_eq!(StateKey::decode(&encoded), Err(DecodeError::LimitExceeded));
    }

    #[test]
    fn trailing_byte_rejection_protocol_types() {
        // Hash256 with trailing byte
        let data = vec![0u8; 33];
        assert_eq!(Hash256::decode(&data), Err(DecodeError::TrailingBytes));
        // Address with trailing byte
        assert_eq!(Address::decode(&[0u8; 33]), Err(DecodeError::TrailingBytes));
        // ValidatorId with trailing byte
        assert_eq!(
            ValidatorId::decode(&[0u8; 33]),
            Err(DecodeError::TrailingBytes)
        );
        // Resources with trailing byte
        let mut r_enc = vec![0u8; 32];
        r_enc.push(0xFF);
        assert_eq!(Resources::decode(&r_enc), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn truncation_rejection_protocol_types() {
        assert!(Hash256::decode(&[0u8; 31]).is_err());
        assert!(Address::decode(&[0u8; 31]).is_err());
        assert!(ValidatorId::decode(&[0u8; 31]).is_err());
        // Resources needs exactly 32 bytes
        assert!(Resources::decode(&[0u8; 31]).is_err());
        assert!(Resources::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn block_header_truncation() {
        // BlockHeader is 200 bytes; fewer bytes must fail
        assert!(BlockHeader::decode(&[0u8; 199]).is_err());
        assert!(BlockHeader::decode(&[0u8; 201]).is_err());
    }

    #[test]
    fn encoding_determinism_protocol_types() {
        let hash = Hash256([0x42; 32]);
        assert_eq!(hash.to_bytes(), hash.to_bytes());

        let addr = Address([0x42; 32]);
        assert_eq!(addr.to_bytes(), addr.to_bytes());

        let r = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        assert_eq!(r.to_bytes(), r.to_bytes());
    }

    #[test]
    fn golden_hash256_zero() {
        let hash = Hash256::ZERO;
        let encoded = hash.to_bytes();
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, [0u8; 32]);
    }

    #[test]
    fn golden_hash256_one() {
        let hash = Hash256([0x01; 32]);
        let encoded = hash.to_bytes();
        assert_eq!(encoded, [0x01; 32]);
    }

    #[test]
    fn golden_hash256_max() {
        let hash = Hash256([0xFF; 32]);
        let encoded = hash.to_bytes();
        assert_eq!(encoded, [0xFF; 32]);
    }

    #[test]
    fn golden_address_zero() {
        let addr = Address::ZERO;
        let encoded = addr.to_bytes();
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, [0u8; 32]);
    }

    #[test]
    fn golden_address_one() {
        let addr = Address([0x01; 32]);
        let encoded = addr.to_bytes();
        assert_eq!(encoded, [0x01; 32]);
    }

    #[test]
    fn golden_validator_id_zero() {
        let vid = ValidatorId([0u8; 32]);
        let encoded = vid.to_bytes();
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, [0u8; 32]);
    }

    #[test]
    fn golden_validator_id_one() {
        let vid = ValidatorId([0x01; 32]);
        let encoded = vid.to_bytes();
        assert_eq!(encoded, [0x01; 32]);
    }

    #[test]
    fn golden_resources_all_ones() {
        let r = Resources {
            compute: 1,
            memory: 1,
            io: 1,
            bandwidth: 1,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn golden_resources_max_values() {
        let r = Resources {
            compute: u64::MAX,
            memory: u64::MAX,
            io: u64::MAX,
            bandwidth: u64::MAX,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn golden_state_key_empty() {
        let key = StateKey(Vec::new());
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
        assert_eq!(encoded.len(), 1); // length prefix only
    }

    #[test]
    fn golden_state_key_one_byte() {
        let key = StateKey(vec![0xAB]);
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
        assert_eq!(encoded.len(), 2); // length prefix + 1 byte
    }

    #[test]
    fn golden_state_key_max_length() {
        let key = StateKey(vec![0xCD; 256]);
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
        // 5 bytes (long length prefix) + 256 bytes
        assert_eq!(encoded.len(), 261);
    }

    #[test]
    fn golden_transaction_zero_nonce() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 0,
            sender: Address::ZERO,
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn golden_transaction_max_nonce() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: u32::MAX,
            sender: Address([0xFF; 32]),
            nonce: u64::MAX,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0xFF; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn golden_block_header_height_one() {
        let header = BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([0xBB; 32]),
            state_root: Hash256([0xCC; 32]),
            receipts_root: Hash256([0xDD; 32]),
            committee_root: Hash256([0xEE; 32]),
            capacity: Resources {
                compute: 1,
                memory: 2,
                io: 3,
                bandwidth: 4,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
        assert_eq!(encoded.len(), 200);
    }

    #[test]
    fn golden_block_header_max_height() {
        let header = BlockHeader {
            height: u64::MAX,
            parent: Hash256([0xFF; 32]),
            transactions_root: Hash256([0xFF; 32]),
            state_root: Hash256([0xFF; 32]),
            receipts_root: Hash256([0xFF; 32]),
            committee_root: Hash256([0xFF; 32]),
            capacity: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn canonical_encoding_little_endian() {
        let r = Resources {
            compute: 0x0102_0304_0506_0708,
            memory: 0x1112_1314_1516_1718,
            io: 0x2122_2324_2526_2728,
            bandwidth: 0x3132_3334_3536_3738,
        };
        let encoded = r.to_bytes();
        assert_eq!(
            &encoded[0..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            &encoded[8..16],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
    }

    #[test]
    fn canonical_encoding_no_inter_type_confusion() {
        let hash = Hash256([0x42; 32]);
        let addr = Address([0x42; 32]);
        let vid = ValidatorId([0x42; 32]);
        assert_eq!(hash.to_bytes(), addr.to_bytes());
        assert_eq!(addr.to_bytes(), vid.to_bytes());
    }

    #[test]
    fn transaction_decode_truncated_chain_id() {
        let mut bytes = [0u8; 100];
        bytes[0] = 1;
        assert!(Transaction::decode(&bytes[..2]).is_err());
    }

    #[test]
    fn transaction_decode_truncated_sender() {
        let mut bytes = [0u8; 100];
        bytes[0] = 1;
        assert!(Transaction::decode(&bytes[..5]).is_err());
    }

    #[test]
    fn transaction_decode_truncated_nonce() {
        let mut bytes = [0u8; 100];
        bytes[0] = 1;
        assert!(Transaction::decode(&bytes[..36]).is_err());
    }

    #[test]
    fn transaction_decode_truncated_signature() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: Address([0xAA; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0xBB; 64],
        };
        let mut encoded = tx.to_bytes();
        encoded.truncate(encoded.len() - 1);
        assert!(Transaction::decode(&encoded).is_err());
    }

    #[test]
    fn block_header_decode_truncated_height() {
        let header = BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([0xBB; 32]),
            state_root: Hash256([0xCC; 32]),
            receipts_root: Hash256([0xDD; 32]),
            committee_root: Hash256([0xEE; 32]),
            capacity: Resources {
                compute: 1,
                memory: 2,
                io: 3,
                bandwidth: 4,
            },
        };
        let encoded = header.to_bytes();
        assert!(BlockHeader::decode(&encoded[..7]).is_err());
    }

    #[test]
    fn block_header_decode_truncated_parent() {
        let header = BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([0xBB; 32]),
            state_root: Hash256([0xCC; 32]),
            receipts_root: Hash256([0xDD; 32]),
            committee_root: Hash256([0xEE; 32]),
            capacity: Resources {
                compute: 1,
                memory: 2,
                io: 3,
                bandwidth: 4,
            },
        };
        let encoded = header.to_bytes();
        assert!(BlockHeader::decode(&encoded[..10]).is_err());
    }

    #[test]
    fn state_key_decode_empty() {
        let key = StateKey(Vec::new());
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(decoded.0, [] as [u8; 0]);
    }

    #[test]
    fn state_key_decode_truncated() {
        let mut encoded = vec![0x80];
        encoded.extend_from_slice(&256u32.to_le_bytes());
        encoded.extend_from_slice(&[0xAA; 200]);
        assert!(StateKey::decode(&encoded).is_err());
    }

    #[test]
    fn resources_decode_all_zero() {
        let encoded = [0u8; 32];
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(decoded, Resources::ZERO);
    }

    #[test]
    fn resources_decode_little_endian_order() {
        let r = Resources {
            compute: 0x01,
            memory: 0x02,
            io: 0x03,
            bandwidth: 0x04,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(encoded[8], 0x02);
        assert_eq!(encoded[16], 0x03);
        assert_eq!(encoded[24], 0x04);
    }

    #[test]
    fn transaction_roundtrip_with_large_payload() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: Address([0xAA; 32]),
            nonce: 100,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 1000,
                memory: 2000,
                io: 3000,
                bandwidth: 4000,
            },
            payload: vec![0xBB; 1024],
            signature: [0xCC; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn transaction_roundtrip_with_multiple_access_list_entries() {
        let access_list: Vec<StateKey> = (0..10).map(|i| StateKey(vec![i; 5])).collect();
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 42,
            sender: Address([0x11; 32]),
            nonce: 99,
            access_list,
            resource_limit: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: [0xCC; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn block_header_roundtrip_with_large_capacity() {
        let header = BlockHeader {
            height: 1000,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([0xBB; 32]),
            state_root: Hash256([0xCC; 32]),
            receipts_root: Hash256([0xDD; 32]),
            committee_root: Hash256([0xEE; 32]),
            capacity: Resources {
                compute: u64::MAX - 1,
                memory: u64::MAX - 2,
                io: u64::MAX - 3,
                bandwidth: u64::MAX - 4,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn hash256_decode_various_lengths() {
        assert!(Hash256::decode(&[0u8; 31]).is_err());
        assert!(Hash256::decode(&[0u8; 32]).is_ok());
        assert!(Hash256::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn address_decode_various_lengths() {
        assert!(Address::decode(&[0u8; 31]).is_err());
        assert!(Address::decode(&[0u8; 32]).is_ok());
        assert!(Address::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn validator_id_decode_various_lengths() {
        assert!(ValidatorId::decode(&[0u8; 31]).is_err());
        assert!(ValidatorId::decode(&[0u8; 32]).is_ok());
        assert!(ValidatorId::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn execution_receipt_roundtrip() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([0x01; 32]),
            succeeded: true,
            resources: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            output_root: Hash256([0x02; 32]),
        };
        let encoded = receipt.to_bytes();
        let decoded = ExecutionReceipt::decode(&encoded).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn execution_receipt_roundtrip_all_zeros() {
        let receipt = ExecutionReceipt {
            transaction: Hash256::ZERO,
            succeeded: false,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let encoded = receipt.to_bytes();
        let decoded = ExecutionReceipt::decode(&encoded).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn execution_receipt_roundtrip_all_max() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([0xFF; 32]),
            succeeded: true,
            resources: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
            output_root: Hash256([0xFF; 32]),
        };
        let encoded = receipt.to_bytes();
        let decoded = ExecutionReceipt::decode(&encoded).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn execution_receipt_encoding_deterministic() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([0xAA; 32]),
            succeeded: true,
            resources: Resources {
                compute: 42,
                memory: 43,
                io: 44,
                bandwidth: 45,
            },
            output_root: Hash256([0xBB; 32]),
        };
        assert_eq!(receipt.to_bytes(), receipt.to_bytes());
    }

    #[test]
    fn execution_receipt_differs_by_succeeded() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let r2 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: false,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        assert_ne!(r1.to_bytes(), r2.to_bytes());
    }

    #[test]
    fn execution_receipt_differs_by_transaction() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let r2 = ExecutionReceipt {
            transaction: Hash256([2u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        assert_ne!(r1.to_bytes(), r2.to_bytes());
    }

    #[test]
    fn execution_receipt_truncation_rejection() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let encoded = receipt.to_bytes();
        assert!(ExecutionReceipt::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn execution_receipt_trailing_bytes_rejection() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut encoded = receipt.to_bytes();
        encoded.push(0xFF);
        assert_eq!(
            ExecutionReceipt::decode(&encoded),
            Err(DecodeError::TrailingBytes)
        );
    }
}
