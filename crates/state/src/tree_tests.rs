// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Differential checks against the original flat-map state algorithms.

use super::*;
use crate::InMemoryState;

fn key(index: u16) -> StateKey {
    StateKey(index.to_be_bytes().to_vec())
}

fn check(state: &InMemoryState, reference: &BTreeMap<StateKey, Vec<u8>>) {
    use crate::StateSnapshot;

    assert_eq!(state.root(), commitment::compute_root(reference));
    assert_eq!(
        state.export_snapshot(),
        snapshot::encode(
            reference.len(),
            reference.iter().map(|(key, value)| (key, value.as_slice())),
            state.root(),
        )
    );
    for index in 0..=70 {
        let key = key(index);
        assert_eq!(state.get(&key), reference.get(&key).map(Vec::as_slice));
        assert_eq!(
            state.prove(&key).unwrap(),
            commitment::prove(reference, &key)
        );
        assert_eq!(
            state.prove_absence(&key),
            commitment::prove_absence(reference, &key)
        );
    }
}

#[test]
fn updates_and_topology_changes_match_flat_reference() {
    for count in [0, 1, 2, 3, 5, 7, 8, 9, 31, 32, 33, 64, 65] {
        let mut reference: BTreeMap<_, _> = (0..count)
            .map(|i| (key(i), i.to_le_bytes().to_vec()))
            .collect();
        let bytes = snapshot::encode(
            reference.len(),
            reference.iter().map(|(key, value)| (key, value.as_slice())),
            commitment::compute_root(&reference),
        );
        let mut state =
            InMemoryState::from_snapshot(&bytes, commitment::compute_root(&reference)).unwrap();
        let mut random = 19_u64;
        for round in 0..12 {
            let previous = state.clone();
            let previous_bytes = previous.export_snapshot();
            let mut diffs = vec![StateDiff::new(), StateDiff::new()];
            for _ in 0..9 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let index = u16::try_from((random >> 32) % 70).unwrap();
                if round % 3 == 0 {
                    diffs[0].delete(key(index));
                } else {
                    diffs[0].put(key(index), vec![round; usize::from(index % 7)]);
                }
                // Duplicate writes in separate transactions keep their ordering.
                diffs[1].put(key(index), vec![round + 1; usize::from(index % 5)]);
            }
            reference = snapshot::stage(reference, &diffs).unwrap();
            state = state.prepare(state.root(), &diffs).unwrap();
            check(&state, &reference);
            assert_eq!(previous.export_snapshot(), previous_bytes);
        }
    }
}

#[test]
fn fixed_layout_updates_share_unaffected_branches_and_preserve_proofs() {
    let reference: BTreeMap<_, _> = (0..65).map(|i| (key(i), vec![7; 17])).collect();
    let tree = Tree::from_map(reference.clone());
    let mut changes = StateDiff::new();
    changes.put(key(0), vec![9]);
    changes.put(key(0), vec![11; 19]);
    changes.delete(key(99));
    let next = tree.prepare(&[changes.clone()]).unwrap().unwrap();
    let expected = snapshot::stage(reference, &[changes]).unwrap();
    assert_eq!(next.hash(), commitment::compute_root(&expected));
    let (Kind::Branch(old_left, old_right), Kind::Branch(new_left, new_right)) = (
        &tree.root.as_ref().unwrap().kind,
        &next.root.as_ref().unwrap().kind,
    ) else {
        panic!("fixture has two root children")
    };
    assert!(!Arc::ptr_eq(old_left, new_left));
    assert!(Arc::ptr_eq(old_right, new_right));
    for index in 0..=66 {
        assert_eq!(
            next.prove(&key(index)),
            commitment::prove(&expected, &key(index))
        );
        assert_eq!(
            next.prove_absence(&key(index)),
            commitment::prove_absence(&expected, &key(index))
        );
    }
    assert_eq!(tree.get(&key(0)), Some([7; 17].as_slice()));
    let unchanged = next.prepare(&[]).unwrap().unwrap();
    assert!(Arc::ptr_eq(
        next.root.as_ref().unwrap(),
        unchanged.root.as_ref().unwrap()
    ));
}

#[test]
fn transient_snapshot_overflow_is_rejected_before_write_coalescing() {
    // Fill the encoded snapshot exactly, without exceeding the individual value bound.
    let mut entries = BTreeMap::new();
    for index in 0..63 {
        entries.insert(key(index), vec![0; MAX_STATE_VALUE_BYTES]);
    }
    let remaining =
        MAX_SNAPSHOT_BYTES - snapshot::HEADER_BYTES - 64 * 18 - 63 * MAX_STATE_VALUE_BYTES;
    entries.insert(key(63), vec![0; remaining]);
    let tree = Tree::from_map(entries.clone());
    let original = tree.hash();
    let mut changes = StateDiff::new();
    changes.put(key(63), vec![1; remaining + 1]);
    changes.put(key(63), vec![]);
    assert!(matches!(
        tree.prepare(&[changes.clone()]),
        Err(StateError::LimitExceeded)
    ));
    assert_eq!(
        snapshot::stage(entries.clone(), &[changes]),
        Err(StateError::LimitExceeded)
    );
    let mut valid = StateDiff::new();
    valid.put(key(63), vec![]);
    valid.put(key(0), vec![1; MAX_STATE_VALUE_BYTES]);
    valid.put(key(63), vec![2; remaining]);
    let next = tree.prepare(&[valid.clone()]).unwrap().unwrap();
    assert_eq!(
        next.hash(),
        commitment::compute_root(&snapshot::stage(entries, &[valid]).unwrap())
    );
    assert_eq!(tree.hash(), original);
}
