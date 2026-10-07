// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical, bounded protocol encoding primitives.
//!
//! All multi-byte integers use little-endian byte order. Length-prefixed byte
//! sequences use a compact 1-byte or 5-byte length encoding:
//!
//! - If the length fits in 7 bits (< 128), it is stored as one byte.
//! - Otherwise, the first byte is `0x80` followed by 4 little-endian bytes
//!   representing the length, giving a maximum of 2^32 - 1 bytes.
//!
//! This avoids the overhead of varint libraries while remaining compact for
//! the expected range of inputs.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod decoder;
pub mod error;
pub mod primitives;
pub mod protocol;
pub mod traits;

pub use decoder::Decoder;
pub use error::DecodeError;
pub use traits::{CanonicalDecode, CanonicalEncode};

/// Maximum allowed payload size (1 MiB).
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Maximum allowed number of items in a length-prefixed list.
pub const MAX_LIST_LEN: usize = 1 << 20;

/// Maximum allowed state key length.
pub const MAX_STATE_KEY_LEN: usize = 256;

/// Current canonical encoding version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Encodes a length as a compact prefix.
///
/// # Panics
///
/// Panics if `len > u32::MAX`.
pub fn encode_length(len: usize, output: &mut Vec<u8>) {
    if len < 128 {
        output.push(u8::try_from(len).expect("length < 128 fits in u8"));
    } else {
        output.push(0x80);
        let len32 = u32::try_from(len).expect("length validated by caller");
        output.extend_from_slice(&len32.to_le_bytes());
    }
}

/// Decodes a compact length prefix.
pub(crate) fn decode_length(decoder: &mut Decoder<'_>) -> Result<usize, DecodeError> {
    let first = decoder.read_u8()?;
    if first < 128 {
        return Ok(first as usize);
    }
    if first != 0x80 {
        return Err(DecodeError::NonCanonical);
    }
    let value = decoder.read_u32()?;
    if value < 128 {
        return Err(DecodeError::NonCanonical);
    }
    if value as usize > MAX_LIST_LEN {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(value as usize)
}

/// Encodes a byte slice with a length prefix.
pub fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    encode_length(bytes.len(), output);
    output.extend_from_slice(bytes);
}

/// Decodes a length-prefixed byte slice.
pub(crate) fn decode_bytes<'a>(
    decoder: &mut Decoder<'a>,
    limit: usize,
) -> Result<&'a [u8], DecodeError> {
    let len = decode_length(decoder)?;
    if len > limit {
        return Err(DecodeError::LimitExceeded);
    }
    decoder.read_exact(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CanonicalEncode;
    use types::{Address, BlockHeader, Hash256, Resources, StateKey, Transaction};

    #[test]
    fn length_prefix_short() {
        let encoded = [5u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 5);
        let data = decoder.read_exact(5).unwrap();
        assert_eq!(data, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn length_prefix_long() {
        let mut encoded = vec![0x80u8];
        encoded.extend_from_slice(&300u32.to_le_bytes());
        encoded.extend_from_slice(&[0xAB; 300]);

        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 300);
        let data = decoder.read_exact(300).unwrap();
        assert_eq!(data, &[0xAB; 300]);
    }

    #[test]
    fn length_prefix_exactly_127() {
        let data = vec![0xAA; 127];
        let mut encoded = vec![127u8];
        encoded.extend_from_slice(&data);
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 127);
        let result = decoder.read_exact(127).unwrap();
        assert_eq!(result, &[0xAA; 127]);
    }

    #[test]
    fn length_prefix_exactly_128() {
        let data = vec![0xBB; 128];
        let mut encoded = vec![0x80u8];
        encoded.extend_from_slice(&128u32.to_le_bytes());
        encoded.extend_from_slice(&data);
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 128);
        let result = decoder.read_exact(128).unwrap();
        assert_eq!(result, &[0xBB; 128]);
    }

    #[test]
    fn length_prefix_zero() {
        let mut decoder = Decoder::new(&[0u8]);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 0);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn length_prefix_golden_vectors() {
        for (length, expected) in [
            (0, vec![0]),
            (127, vec![127]),
            (128, vec![0x80, 0x80, 0, 0, 0]),
            (256, vec![0x80, 0, 1, 0, 0]),
            (MAX_LIST_LEN, vec![0x80, 0, 0, 0x10, 0]),
        ] {
            let mut encoded = Vec::new();
            encode_length(length, &mut encoded);
            assert_eq!(encoded, expected);
            let mut decoder = Decoder::new(&expected);
            assert_eq!(decode_length(&mut decoder), Ok(length));
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn every_supported_length_roundtrips() {
        let mut encoded = Vec::with_capacity(5);
        for length in 0..=MAX_LIST_LEN {
            encoded.clear();
            encode_length(length, &mut encoded);
            let mut decoder = Decoder::new(&encoded);
            assert_eq!(decode_length(&mut decoder), Ok(length));
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn mixed_sequence_encoding() {
        let mut output = Vec::new();
        42u32.encode(&mut output);
        Address([0x42; 32]).encode(&mut output);
        true.encode(&mut output);
        255u8.encode(&mut output);

        let mut decoder = Decoder::new(&output);
        assert_eq!(decoder.read_u32().unwrap(), 42);
        let addr_bytes = decoder.read_fixed::<32>().unwrap();
        assert_eq!(addr_bytes, [0x42; 32]);
        let b = decoder.read_u8().unwrap();
        assert_eq!(b, 1);
        let last = decoder.read_u8().unwrap();
        assert_eq!(last, 255);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn golden_resources_zero() {
        let r = Resources::ZERO;
        let encoded = r.to_bytes();
        assert_eq!(encoded, [0u8; 32]);
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
        let vid = types::ValidatorId([0x99; 32]);
        let encoded = vid.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = types::ValidatorId::decode(&encoded).unwrap();
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
        assert!(encoded.len() > 142);
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
}
