// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State compatibility, proof tampering, bounded decoding, and rollback invariants.

use state::{
    InMemoryState, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES, StateDatabase, StateDiff,
    StateError, StateProof, StateSnapshot,
};
use types::{Hash256, StateKey};

fn populated(entries: &[(&[u8], &[u8])]) -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for (key, value) in entries {
        diff.put(StateKey(key.to_vec()), value.to_vec());
    }
    state.commit(state.root(), &[diff]).unwrap();
    state
}

#[test]
fn independent_blake2s_golden_roots() {
    // These fixtures were computed independently with Python hashlib.blake2s.
    assert_eq!(
        InMemoryState::new().root().to_string(),
        "292b37da034d0be78d8a0747a314188cdadcae8d268a3dfd433972228b7f3d36"
    );
    assert_eq!(
        populated(&[(b"a", b"one")]).root().to_string(),
        "d94433205d9877eeeb9d9ddabceadde64b43baea74e42fb9cb8ecc4027fd9386"
    );
    assert_eq!(
        populated(&[(b"c", b"three"), (b"a", b"one"), (b"b", b"two")])
            .root()
            .to_string(),
        "3e407847770a949f75e8511319ac21ed51f11011dce5a92739e51cb52e8c25ba"
    );
}

#[test]
fn commitment_binds_full_contents_and_entry_boundaries() {
    let original = populated(&[(&[1; 64], &[2; 96])]);
    for position in 0..64 {
        let mut key = [1; 64];
        key[position] ^= 1;
        assert_ne!(populated(&[(&key, &[2; 96])]).root(), original.root());
    }
    for position in 0..96 {
        let mut value = [2; 96];
        value[position] ^= 1;
        assert_ne!(populated(&[(&[1; 64], &value)]).root(), original.root());
    }
    assert_ne!(
        populated(&[(b"ab", b"c")]).root(),
        populated(&[(b"a", b"bc")]).root()
    );
    assert_ne!(
        populated(&[(b"a", b"a"), (b"b", b"b")]).root(),
        InMemoryState::new().root()
    );
}

#[test]
fn generated_tree_shapes_have_valid_and_strict_paths() {
    for count in 1..=65u8 {
        let mut state = InMemoryState::new();
        let mut diff = StateDiff::new();
        for index in 0..count {
            diff.put(StateKey(vec![index]), vec![index; 3]);
        }
        state.commit(state.root(), &[diff]).unwrap();
        for index in 0..count {
            let key = StateKey(vec![index]);
            let value = [index; 3];
            let proof = state.prove(&key).unwrap().unwrap();
            assert!(proof.verify(state.root(), &key, &value));
            assert!(!proof.verify(Hash256::ZERO, &key, &value));
            assert!(!proof.verify(state.root(), &StateKey(vec![255]), &value));
            assert!(!proof.verify(state.root(), &key, &[255; 3]));
            let mut changed = proof.clone();
            changed.index = changed.leaf_count;
            assert!(!changed.verify(state.root(), &key, &value));
            changed = proof.clone();
            changed.leaf_count += 1;
            assert!(!changed.verify(state.root(), &key, &value));
            changed = proof.clone();
            changed.siblings.push(Hash256::ZERO);
            assert!(!changed.verify(state.root(), &key, &value));
            for sibling in 0..proof.siblings.len() {
                changed = proof.clone();
                changed.siblings[sibling].0[0] ^= 1;
                assert!(!changed.verify(state.root(), &key, &value));
            }
            if !proof.siblings.is_empty() {
                changed = proof;
                changed.siblings.pop();
                assert!(!changed.verify(state.root(), &key, &value));
            }
        }
        assert!(state.prove(&StateKey(vec![255])).unwrap().is_none());
    }
    let invalid = StateProof {
        index: u64::MAX,
        leaf_count: u64::MAX,
        siblings: vec![],
    };
    assert!(!invalid.verify(Hash256::ZERO, &StateKey(vec![]), &[]));
}

#[test]
fn snapshot_golden_framing_and_roundtrip() {
    let state = populated(&[(b"a", b"one")]);
    let mut expected = b"ASTSTATE\x01\x00".to_vec();
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.extend_from_slice(state.root().as_bytes());
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.push(b'a');
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(b"one");
    assert_eq!(state.export_snapshot(), expected);
    let decoded = InMemoryState::from_snapshot(&expected, state.root()).unwrap();
    assert_eq!(
        decoded.get(&StateKey(b"a".to_vec())),
        Some(b"one".as_slice())
    );
    assert_eq!(decoded.export_snapshot(), expected);
    assert_eq!(
        InMemoryState::from_snapshot(&expected, Hash256::ZERO).unwrap_err(),
        StateError::RootMismatch
    );
}

#[test]
fn snapshot_rejects_every_truncation_and_single_byte_mutation() {
    let state = populated(&[(b"a", b"one"), (b"b", b"two")]);
    let bytes = state.export_snapshot();
    for length in 0..bytes.len() {
        assert!(InMemoryState::from_snapshot(&bytes[..length], state.root()).is_err());
    }
    for position in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[position] ^= 1;
        assert!(
            InMemoryState::from_snapshot(&changed, state.root()).is_err(),
            "byte {position}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(InMemoryState::from_snapshot(&trailing, state.root()).is_err());
}

#[test]
fn snapshot_rejects_duplicates_ordering_and_unbounded_lengths() {
    let state = populated(&[(b"a", b"one"), (b"b", b"two")]);
    let bytes = state.export_snapshot();
    // Each entry here is 20 bytes after the fixed 50-byte header.
    let mut duplicate = bytes.clone();
    duplicate[70..90].copy_from_slice(&bytes[50..70]);
    assert_eq!(
        InMemoryState::from_snapshot(&duplicate, state.root()).unwrap_err(),
        StateError::Corrupt
    );
    let mut reversed = bytes.clone();
    reversed[50..70].copy_from_slice(&bytes[70..90]);
    reversed[70..90].copy_from_slice(&bytes[50..70]);
    assert_eq!(
        InMemoryState::from_snapshot(&reversed, state.root()).unwrap_err(),
        StateError::Corrupt
    );
    for offset in [10, 50, 59] {
        let mut changed = bytes.clone();
        changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            InMemoryState::from_snapshot(&changed, state.root()).unwrap_err(),
            StateError::LimitExceeded
        );
    }
}

#[test]
fn rejected_overlay_preserves_state_and_existing_snapshots() {
    let mut state = populated(&[(b"a", b"one")]);
    let old_bytes = state.export_snapshot();
    let snapshot = state.snapshot().unwrap();
    let mut diff = StateDiff::new();
    diff.put(StateKey(b"a".to_vec()), b"changed".to_vec());
    assert_eq!(
        state.commit_verified(state.root(), &[diff.clone()], Hash256::ZERO),
        Err(StateError::RootMismatch)
    );
    assert_eq!(state.export_snapshot(), old_bytes);
    diff.put(StateKey(vec![0; MAX_STATE_KEY_BYTES + 1]), vec![]);
    assert_eq!(
        state.commit(state.root(), &[diff]),
        Err(StateError::LimitExceeded)
    );
    assert_eq!(state.export_snapshot(), old_bytes);
    assert_eq!(
        snapshot.get(&StateKey(b"a".to_vec())).unwrap(),
        Some(b"one".to_vec())
    );
    assert!(
        snapshot
            .prove(&StateKey(b"a".to_vec()))
            .unwrap()
            .unwrap()
            .verify(snapshot.root(), &StateKey(b"a".to_vec()), b"one")
    );
}

#[test]
fn exact_key_value_bounds_and_ordered_writes() {
    let mut state = InMemoryState::new();
    let key = StateKey(vec![42; MAX_STATE_KEY_BYTES]);
    let mut diff = StateDiff::new();
    diff.put(key.clone(), vec![7; MAX_STATE_VALUE_BYTES]);
    state.commit(state.root(), &[diff]).unwrap();
    let original = state.root();
    let mut invalid = StateDiff::new();
    invalid.put(key.clone(), vec![7; MAX_STATE_VALUE_BYTES + 1]);
    assert_eq!(
        state.commit(original, &[invalid]),
        Err(StateError::LimitExceeded)
    );
    assert_eq!(state.root(), original);
    let snapshot = state.snapshot().unwrap();
    let mut first = StateDiff::new();
    first.put(key.clone(), vec![1]);
    first.delete(key.clone());
    let mut second = StateDiff::new();
    second.put(key.clone(), vec![2]);
    state.commit(original, &[first, second]).unwrap();
    assert_eq!(state.get(&key), Some([2].as_slice()));
    assert_eq!(
        snapshot.get(&key).unwrap().unwrap().len(),
        MAX_STATE_VALUE_BYTES
    );
}

#[test]
fn diff_commitment_binds_order_and_operation_boundaries() {
    let mut first = StateDiff::new();
    first.put(StateKey(b"a".to_vec()), b"bc".to_vec());
    first.delete(StateKey(b"a".to_vec()));
    let mut reversed = first.clone();
    reversed.changes.reverse();
    assert_ne!(first.commitment(), reversed.commitment());
    assert_ne!(first.commitment(), StateDiff::new().commitment());
    let mut changed = first.clone();
    changed.changes[0] = state::StateChange::Put(StateKey(b"ab".to_vec()), b"c".to_vec());
    assert_ne!(first.commitment(), changed.commitment());
}
