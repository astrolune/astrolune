// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical byte compatibility and malformed-input regression tests.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, MAX_LIST_LEN, MAX_PAYLOAD};
use types::{Address, ExecutionReceipt, Resources, StateKey, Transaction};

fn transaction() -> Transaction {
    Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 0x0403_0201,
        sender: Address([0x11; 32]),
        nonce: 0x0807_0605_0403_0201,
        access_list: vec![StateKey(vec![0x22])],
        resource_limit: Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        },
        payload: vec![0x33],
        signature: [0x44; 64],
    }
}

#[test]
fn transaction_golden_bytes() {
    let expected = [
        b"ALTX".as_slice(),
        &[1, 0, 0, 0],
        &[1, 2, 3, 4],
        &[0x11; 32],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        &[0xff; 8],
        &[0],
        &[1, 1, 0x22],
        &[1, 0, 0, 0, 0, 0, 0, 0],
        &[2, 0, 0, 0, 0, 0, 0, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0],
        &[4, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 0, 0, 0, 0, 0, 0],
        &[0; 24],
        &[1, 0x33],
        &[0x44; 64],
    ]
    .concat();
    assert_eq!(transaction().to_bytes(), expected);
    assert_eq!(Transaction::decode(&expected), Ok(transaction()));
}

#[test]
fn state_keys_reject_every_overlong_short_length() {
    for length in 0u8..128 {
        let mut bytes = vec![0x80, length, 0, 0, 0];
        bytes.extend(vec![0xAA; usize::from(length)]);
        assert_eq!(StateKey::decode(&bytes), Err(DecodeError::NonCanonical));
    }
}

#[test]
fn state_keys_reject_every_reserved_length_marker() {
    let mut bytes = StateKey(vec![0xAA; 128]).to_bytes();
    for marker in 0x81..=0xFF {
        bytes[0] = marker;
        assert_eq!(StateKey::decode(&bytes), Err(DecodeError::NonCanonical));
        assert_eq!(StateKey::decode(&[marker]), Err(DecodeError::NonCanonical));
    }
}

#[test]
fn state_key_limit_is_checked_before_reading_content() {
    assert_eq!(
        StateKey::decode(&[0x80, 1, 1, 0, 0]),
        Err(DecodeError::LimitExceeded)
    );
    let mut bytes = transaction().to_bytes();
    bytes.splice(62..63, [0x80, 1, 1, 0, 0]);
    assert_eq!(Transaction::decode(&bytes), Err(DecodeError::LimitExceeded));
}

#[test]
fn transaction_rejects_noncanonical_lengths_at_every_position() {
    for position in [61, 62, 128] {
        let mut bytes = transaction().to_bytes();
        bytes.splice(position..=position, [0x80, 1, 0, 0, 0]);
        assert_eq!(Transaction::decode(&bytes), Err(DecodeError::NonCanonical));

        for marker in 0x81..=0xFF {
            bytes[position] = marker;
            assert_eq!(Transaction::decode(&bytes), Err(DecodeError::NonCanonical));
        }
    }
}

#[test]
fn transaction_rejects_unbacked_or_excessive_access_counts() {
    for (count, error) in [
        (MAX_LIST_LEN, DecodeError::Truncated),
        (MAX_LIST_LEN + 1, DecodeError::LimitExceeded),
    ] {
        let mut bytes = transaction().to_bytes()[..61].to_vec();
        codec::encode_length(count, &mut bytes);
        assert_eq!(Transaction::decode(&bytes), Err(error));
    }
}

#[test]
fn transaction_payload_limit() {
    let mut tx = transaction();
    tx.payload = vec![0xAA; MAX_PAYLOAD];
    assert_eq!(Transaction::decode(&tx.to_bytes()), Ok(tx));

    let mut bytes = transaction().to_bytes()[..128].to_vec();
    codec::encode_length(MAX_PAYLOAD + 1, &mut bytes);
    assert_eq!(Transaction::decode(&bytes), Err(DecodeError::LimitExceeded));
}

#[test]
fn transaction_rejects_every_truncation_and_trailing_bytes() {
    let mut tx = transaction();
    tx.access_list = vec![StateKey(vec![0xAA; 128]); 128];
    tx.payload = vec![0xBB; 128];
    let mut bytes = tx.to_bytes();
    for length in 0..bytes.len() {
        assert_eq!(
            Transaction::decode(&bytes[..length]),
            Err(DecodeError::Truncated),
            "accepted truncation at {length}"
        );
    }
    assert_eq!(Transaction::decode(&bytes), Ok(tx));
    bytes.push(0);
    assert_eq!(Transaction::decode(&bytes), Err(DecodeError::TrailingBytes));
}

#[test]
fn receipts_accept_only_canonical_boolean_bytes() {
    let mut bytes = [0u8; 97];
    for value in 0..=u8::MAX {
        bytes[32] = value;
        let result = ExecutionReceipt::decode(&bytes);
        if value <= 1 {
            let receipt = result.unwrap();
            assert_eq!(receipt.succeeded, value == 1);
            assert_eq!(receipt.to_bytes(), bytes);
        } else {
            assert_eq!(result, Err(DecodeError::NonCanonical));
        }
    }
}

#[test]
fn accepted_transaction_mutations_preserve_exact_bytes() {
    let mut bytes = transaction().to_bytes();
    for position in 0..bytes.len() {
        let original = bytes[position];
        for value in 0..=u8::MAX {
            bytes[position] = value;
            if let Ok(decoded) = Transaction::decode(&bytes) {
                assert_eq!(decoded.to_bytes(), bytes);
            }
        }
        bytes[position] = original;
    }
}

#[test]
fn transaction_versions_lanes_and_legacy_bytes_fail_closed() {
    let bytes = transaction().to_bytes();
    for version in [0u32, 2, u32::MAX] {
        let mut altered = bytes.clone();
        altered[4..8].copy_from_slice(&version.to_le_bytes());
        assert_eq!(Transaction::decode(&altered), Err(DecodeError::Unsupported));
    }
    for lane in 0..=u8::MAX {
        let mut altered = bytes.clone();
        altered[60] = lane;
        if lane <= 2 {
            assert_eq!(Transaction::decode(&altered).unwrap().to_bytes(), altered);
        } else {
            assert_eq!(Transaction::decode(&altered), Err(DecodeError::Unsupported));
        }
    }
    let legacy = [&bytes[8..52], &bytes[61..96], &bytes[128..]].concat();
    assert_eq!(Transaction::decode(&legacy), Err(DecodeError::Unsupported));
}
