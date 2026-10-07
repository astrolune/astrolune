// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded membership/absence framing and exact-key authentication.

use state::{InMemoryState, StateDatabase, StateDiff, StateValueProof};
use types::{Hash256, StateKey};

#[test]
fn bounded_value_proofs_distinguish_absence_empty_values_and_wrong_contexts() {
    let mut db = InMemoryState::new();
    for keys in [vec![], vec![2], vec![2, 4, 8, 16]] {
        let mut diff = StateDiff::new();
        for key in keys {
            diff.put(
                StateKey(vec![key]),
                if key == 2 { vec![] } else { vec![key + 1] },
            );
        }
        db.commit(db.root(), &[diff]).unwrap();
        let snapshot = db.snapshot().unwrap();
        for key in 0..20 {
            let key = StateKey(vec![key]);
            let proof = StateValueProof::create(snapshot.as_ref(), &key).unwrap();
            assert_eq!(proof.verify(db.root(), &key).unwrap(), db.get(&key));
            let bytes = proof.to_bytes().unwrap();
            assert_eq!(StateValueProof::from_bytes(&bytes).unwrap(), proof);
            assert!(proof.verify(Hash256::ZERO, &key).is_err());
            if matches!(proof, StateValueProof::Present(_)) {
                assert!(proof.verify(db.root(), &StateKey(vec![99])).is_err());
            }
            for len in 0..bytes.len() {
                assert!(StateValueProof::from_bytes(&bytes[..len]).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(StateValueProof::from_bytes(&trailing).is_err());
        }
    }
}
