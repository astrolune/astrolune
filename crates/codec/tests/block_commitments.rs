// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independent commitment fixtures and regressions for former XOR collisions.

use codec::{CanonicalDecode, CanonicalEncode};
use types::{BlockHeader, ExecutionReceipt};

#[test]
fn canonical_zero_fixtures_match_independent_blake2s_vectors() {
    // Generated independently with Python hashlib.blake2s and explicit domain framing.
    let header = BlockHeader::decode(&[0; 200]).unwrap();
    let receipt = ExecutionReceipt::decode(&[0; 97]).unwrap();
    assert_eq!(
        header.compute_hash().to_string(),
        "352097b3306fdf84041c0fa12a4252ba14a9b9db32bcddc416a82ab65eaacd1e"
    );
    assert_eq!(
        receipt.commitment().to_string(),
        "4325d0e0b1941d851f54326348853a25a8efb8b87a228ee2f8d7ee158335f60f"
    );
    assert_eq!(header.to_bytes(), vec![0; 200]);
    assert_eq!(receipt.to_bytes(), vec![0; 97]);
}

#[test]
fn every_canonical_byte_is_bound_and_xor_cancellation_no_longer_works() {
    let original = BlockHeader::decode(&[0; 200]).unwrap().compute_hash();
    for at in 0..200 {
        let mut bytes = [0; 200];
        bytes[at] = 1;
        let header = BlockHeader::decode(&bytes).unwrap();
        assert_eq!(header.to_bytes(), bytes);
        assert_ne!(header.compute_hash(), original);
        if at + 32 < bytes.len() {
            bytes[at + 32] = 1;
            assert_ne!(
                BlockHeader::decode(&bytes).unwrap().compute_hash(),
                original
            );
        }
    }
    let original = ExecutionReceipt::decode(&[0; 97]).unwrap().commitment();
    for at in 0..97 {
        let mut bytes = [0; 97];
        bytes[at] = 1;
        let receipt = ExecutionReceipt::decode(&bytes).unwrap();
        assert_eq!(receipt.to_bytes(), bytes);
        assert_ne!(receipt.commitment(), original);
        if at + 32 < bytes.len() {
            bytes[at + 32] = 1;
            assert_ne!(
                ExecutionReceipt::decode(&bytes).unwrap().commitment(),
                original
            );
        }
    }
}

#[test]
fn exhausted_height_cannot_have_a_child() {
    let mut parent = BlockHeader::decode(&[0; 200]).unwrap();
    parent.height = u64::MAX;
    let mut child = parent;
    child.parent = parent.compute_hash();
    assert!(!child.validate_parent(&parent));
}
