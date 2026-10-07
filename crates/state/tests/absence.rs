// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Non-membership, canonical transport, adversarial gaps, and snapshot isolation.

use state::{
    InMemoryState, MAX_ABSENCE_PROOF_BYTES, MAX_STATE_ENTRIES, MAX_STATE_KEY_BYTES,
    MAX_STATE_VALUE_BYTES, StateAbsenceProof, StateDatabase, StateDiff, StateError, StateProof,
    StateSnapshot, StateWitness,
};
use types::{Hash256, StateKey};

fn populated(keys: &[&[u8]]) -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for key in keys {
        diff.put(StateKey(key.to_vec()), key.to_vec());
    }
    state.commit(state.root(), &[diff]).unwrap();
    state
}

fn witness(state: &InMemoryState, key: &[u8]) -> StateWitness {
    let key = StateKey(key.to_vec());
    StateWitness {
        value: state.get(&key).unwrap().to_vec(),
        proof: state.prove(&key).unwrap().unwrap(),
        key,
    }
}

#[test]
fn generated_gaps_cover_empty_singleton_odd_and_even_trees() {
    for count in (0..=17u8).chain([31, 32, 33, 63, 64, 65]) {
        let mut state = InMemoryState::new();
        let mut diff = StateDiff::new();
        for index in 0..count {
            diff.put(StateKey(vec![index * 2 + 1]), vec![index]);
        }
        state.commit(state.root(), &[diff]).unwrap();
        for query in 0..=count * 2 + 1 {
            let key = StateKey(vec![query]);
            let proof = state.prove_absence(&key).unwrap();
            assert_eq!(proof.is_none(), state.get(&key).is_some());
            if let Some(proof) = proof {
                assert!(proof.verify(state.root(), &key));
                assert!(!proof.verify(Hash256::ZERO, &key));
                let bytes = proof.to_bytes().unwrap();
                let decoded = StateAbsenceProof::from_bytes(&bytes).unwrap();
                assert_eq!(decoded, proof);
                assert_eq!(decoded.to_bytes().unwrap(), bytes);
            }
        }
    }
}

#[test]
fn ordering_uses_complete_key_bytes_including_empty_keys_and_prefixes() {
    let state = populated(&[b"", b"a", b"a\0", b"a\xff", b"b", &[255; 256]]);
    for bytes in [
        b"\0".as_slice(),
        b"a\0\0",
        b"a\x01",
        b"ab",
        b"b\0",
        &[255; 255],
    ] {
        let key = StateKey(bytes.to_vec());
        assert!(
            state
                .prove_absence(&key)
                .unwrap()
                .unwrap()
                .verify(state.root(), &key)
        );
    }
    for bytes in [b"".as_slice(), b"a", b"a\0", b"a\xff", b"b", &[255; 256]] {
        assert!(
            state
                .prove_absence(&StateKey(bytes.to_vec()))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn authentic_but_nonadjacent_or_nonboundary_witnesses_do_not_prove_absence() {
    let state = populated(&[&[10], &[20], &[30]]);
    let lower = witness(&state, &[10]);
    let upper = witness(&state, &[30]);
    let skipped = StateAbsenceProof {
        lower: Some(lower.clone()),
        upper: Some(upper.clone()),
    };
    for key in [15, 20, 25] {
        assert!(!skipped.verify(state.root(), &StateKey(vec![key])));
    }
    let false_start = StateAbsenceProof {
        lower: None,
        upper: Some(upper),
    };
    assert!(!false_start.verify(state.root(), &StateKey(vec![5])));
    let false_end = StateAbsenceProof {
        lower: Some(lower),
        upper: None,
    };
    assert!(!false_end.verify(state.root(), &StateKey(vec![35])));
    let empty = StateAbsenceProof {
        lower: None,
        upper: None,
    };
    assert!(!empty.verify(state.root(), &StateKey(vec![15])));
    assert!(empty.verify(InMemoryState::new().root(), &StateKey(vec![])));

    let key = StateKey(vec![15]);
    let valid = state.prove_absence(&key).unwrap().unwrap();
    for existing in [10, 20] {
        assert!(!valid.verify(state.root(), &StateKey(vec![existing])));
    }
    let mut swapped = valid.clone();
    std::mem::swap(&mut swapped.lower, &mut swapped.upper);
    assert!(!swapped.verify(state.root(), &key));
    let mut overflow = valid.clone();
    overflow.lower.as_mut().unwrap().proof.index = u64::MAX;
    overflow.lower.as_mut().unwrap().proof.leaf_count = u64::MAX;
    assert!(!overflow.verify(state.root(), &key));
    let other = populated(&[&[10], &[20]]);
    let mut mixed = valid;
    mixed.upper = Some(witness(&other, &[20]));
    assert!(!mixed.verify(state.root(), &key));
}

#[test]
fn proof_is_bound_to_snapshot_across_insert_delete_and_snapshot_exchange() {
    let mut state = populated(&[b"a", b"c"]);
    let key = StateKey(b"b".to_vec());
    let old = state.snapshot().unwrap();
    let proof = old.prove_absence(&key).unwrap().unwrap();
    let mut insert = StateDiff::new();
    insert.put(key.clone(), vec![1]);
    state.commit(state.root(), &[insert]).unwrap();
    assert!(proof.verify(old.root(), &key));
    assert!(!proof.verify(state.root(), &key));
    assert!(state.prove_absence(&key).unwrap().is_none());
    assert_eq!(old.prove_absence(&key).unwrap(), Some(proof.clone()));

    let mut delete = StateDiff::new();
    delete.delete(key.clone());
    state.commit(state.root(), &[delete]).unwrap();
    let imported = InMemoryState::from_snapshot(&state.export_snapshot(), state.root()).unwrap();
    assert_eq!(imported.prove_absence(&key).unwrap(), Some(proof));
}

#[test]
fn golden_framing_and_every_truncation_or_byte_mutation() {
    let state = populated(&[b"a"]);
    let key = StateKey(b"b".to_vec());
    let proof = state.prove_absence(&key).unwrap().unwrap();
    let mut expected = b"ASTABSEN\x01\x00\x01".to_vec();
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.push(b'a');
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.push(b'a');
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.extend_from_slice(&[0, 0]); // No siblings, no upper witness.
    assert_eq!(proof.to_bytes().unwrap(), expected);
    let empty = StateAbsenceProof {
        lower: None,
        upper: None,
    };
    assert_eq!(empty.to_bytes().unwrap(), b"ASTABSEN\x01\x00\x00\x00");

    let state = populated(&[b"a", b"c", b"e"]);
    let proof = state.prove_absence(&key).unwrap().unwrap();
    let bytes = proof.to_bytes().unwrap();
    for length in 0..bytes.len() {
        assert!(StateAbsenceProof::from_bytes(&bytes[..length]).is_err());
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            !StateAbsenceProof::from_bytes(&changed).is_ok_and(|p| p.verify(state.root(), &key)),
            "byte {index}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        StateAbsenceProof::from_bytes(&trailing),
        Err(StateError::Corrupt)
    );
    for flag in 2..=255u8 {
        let mut invalid = empty.to_bytes().unwrap();
        invalid[10] = flag;
        assert_eq!(
            StateAbsenceProof::from_bytes(&invalid),
            Err(StateError::Corrupt)
        );
        invalid[10] = 0;
        invalid[11] = flag;
        assert_eq!(
            StateAbsenceProof::from_bytes(&invalid),
            Err(StateError::Corrupt)
        );
    }
}

#[test]
fn rejects_oversized_queries_lengths_paths_and_packets() {
    let state = populated(&[b"a"]);
    let key = StateKey(vec![0; MAX_STATE_KEY_BYTES + 1]);
    assert_eq!(state.prove_absence(&key), Err(StateError::LimitExceeded));
    let empty = StateAbsenceProof {
        lower: None,
        upper: None,
    };
    assert!(!empty.verify(InMemoryState::new().root(), &key));
    let proof = state
        .prove_absence(&StateKey(b"b".to_vec()))
        .unwrap()
        .unwrap();
    let bytes = proof.to_bytes().unwrap();
    for offset in [11, 20, 37] {
        // Key length, value length, leaf count.
        let mut invalid = bytes.clone();
        invalid[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            StateAbsenceProof::from_bytes(&invalid),
            Err(StateError::LimitExceeded)
        );
    }
    let mut invalid = bytes;
    invalid[45] = 21;
    assert_eq!(
        StateAbsenceProof::from_bytes(&invalid),
        Err(StateError::LimitExceeded)
    );
    assert_eq!(
        StateAbsenceProof::from_bytes(&vec![0; MAX_ABSENCE_PROOF_BYTES + 1]),
        Err(StateError::LimitExceeded)
    );

    let boundary = StateWitness {
        key: StateKey(vec![1; MAX_STATE_KEY_BYTES]),
        value: vec![2; MAX_STATE_VALUE_BYTES],
        proof: StateProof {
            index: 0,
            leaf_count: MAX_STATE_ENTRIES as u64,
            siblings: vec![Hash256::ZERO; 20],
        },
    };
    let mut maximum = StateAbsenceProof {
        lower: Some(boundary.clone()),
        upper: Some(boundary),
    };
    let bytes = maximum.to_bytes().unwrap();
    assert_eq!(bytes.len(), MAX_ABSENCE_PROOF_BYTES);
    assert_eq!(StateAbsenceProof::from_bytes(&bytes).unwrap(), maximum);
    maximum
        .upper
        .as_mut()
        .unwrap()
        .proof
        .siblings
        .push(Hash256::ZERO);
    assert_eq!(maximum.to_bytes(), Err(StateError::LimitExceeded));
    maximum.upper.as_mut().unwrap().proof.siblings.pop();
    maximum.upper.as_mut().unwrap().value.push(0);
    assert_eq!(maximum.to_bytes(), Err(StateError::LimitExceeded));
    maximum.upper.as_mut().unwrap().value.pop();
    maximum.upper.as_mut().unwrap().key.0.push(0);
    assert_eq!(maximum.to_bytes(), Err(StateError::LimitExceeded));
}
