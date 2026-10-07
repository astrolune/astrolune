// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Versioned state, access leasing, immutable snapshots, and deferred commits.
//!
//! This crate provides the core state management abstractions and a reference
//! in-memory implementation for testing and development.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod absence;
pub mod account;
pub mod commitment;
pub mod database;
pub mod diff;
pub mod lease;
pub mod memory;
pub mod persistent;
pub mod snapshot;
mod value_proof;
pub use value_proof::StateValueProof;

pub use absence::MAX_ABSENCE_PROOF_BYTES;
pub use account::{account_key, read_account};
pub use commitment::{StateAbsenceProof, StateProof, StateWitness};
pub use database::{StateDatabase, StateError, StateSnapshot};
pub use diff::{StateChange, StateDiff};
pub use lease::{AccessMode, AccessRequest, StateLease};
pub use memory::InMemoryState;
pub use persistent::FileBackedState;
pub use snapshot::{
    MAX_SNAPSHOT_BYTES, MAX_STATE_ENTRIES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;
    use codec::CanonicalEncode;
    use std::collections::BTreeMap;
    use types::{Hash256, StateKey};

    fn key(b: u8) -> StateKey {
        StateKey(vec![b])
    }

    fn val(b: u8) -> Vec<u8> {
        vec![b]
    }

    #[test]
    fn lease_covers_read_access() {
        let lease = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Read,
            }],
        };
        assert!(lease.covers(&key(1), AccessMode::Read));
        assert!(!lease.covers(&key(1), AccessMode::Write));
        assert!(!lease.covers(&key(2), AccessMode::Read));
    }

    #[test]
    fn lease_has_writes() {
        let read_only = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Read,
            }],
        };
        assert!(!read_only.has_writes());

        let with_write = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Write,
            }],
        };
        assert!(with_write.has_writes());
    }

    #[test]
    fn lease_write_keys() {
        let lease = StateLease {
            requests: vec![
                AccessRequest {
                    key: key(1),
                    mode: AccessMode::Read,
                },
                AccessRequest {
                    key: key(2),
                    mode: AccessMode::Write,
                },
                AccessRequest {
                    key: key(3),
                    mode: AccessMode::Write,
                },
            ],
        };
        let writes = lease.write_keys();
        assert_eq!(writes.len(), 2);
        assert!(writes.contains(&&key(2)));
        assert!(writes.contains(&&key(3)));
    }

    #[test]
    fn diff_put_and_delete() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));
        diff.delete(key(1));
        assert_eq!(diff.len(), 3);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_apply_to_empty() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        let state = BTreeMap::new();
        let result = diff.apply_to(&state);
        assert_eq!(result.len(), 2);
        assert_eq!(result[&key(1)], val(10));
        assert_eq!(result[&key(2)], val(20));
    }

    #[test]
    fn diff_apply_delete() {
        let mut state = BTreeMap::new();
        state.insert(key(1), val(10));
        state.insert(key(2), val(20));

        let mut diff = StateDiff::new();
        diff.delete(key(1));

        let result = diff.apply_to(&state);
        assert_eq!(result.len(), 1);
        assert!(!result.contains_key(&key(1)));
        assert_eq!(result[&key(2)], val(20));
    }

    #[test]
    fn diff_sort_canonical() {
        let mut diff = StateDiff::new();
        diff.put(key(3), val(30));
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        diff.sort_canonical();
        assert_eq!(diff.changes[0].key(), &key(1));
        assert_eq!(diff.changes[1].key(), &key(2));
        assert_eq!(diff.changes[2].key(), &key(3));
    }

    #[test]
    fn diff_merge() {
        let mut a = StateDiff::new();
        a.put(key(1), val(10));

        let mut b = StateDiff::new();
        b.put(key(2), val(20));

        a.merge(b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn empty_state() {
        let state = InMemoryState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.root(), commitment::empty_root());
    }

    #[test]
    fn state_commit_and_snapshot() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        let root1 = state.commit(root0, &[diff]).unwrap();
        assert_ne!(root0, root1);
        assert_eq!(state.len(), 2);
        assert_eq!(state.get(&key(1)), Some(val(10).as_slice()));
        assert_eq!(state.get(&key(2)), Some(val(20).as_slice()));
    }

    #[test]
    fn state_commit_rejects_stale_parent() {
        let mut state = InMemoryState::new();
        let bad_root = Hash256([0xFF; 32]);

        let diff = StateDiff::new();
        assert_eq!(
            state.commit(bad_root, &[diff]),
            Err(StateError::StaleSnapshot)
        );
    }

    #[test]
    fn state_snapshot_isolation() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        state.commit(root0, &[diff]).unwrap();

        let snapshot = state.snapshot().unwrap();
        assert_eq!(snapshot.root(), state.root());
        assert_eq!(snapshot.get(&key(1)).unwrap(), Some(val(10)));

        let mut diff2 = StateDiff::new();
        diff2.put(key(2), val(20));
        state.commit(state.root(), &[diff2]).unwrap();

        assert_eq!(snapshot.get(&key(2)).unwrap(), None);
    }

    #[test]
    fn state_delete_through_commit() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        let root1 = state.commit(root0, &[diff]).unwrap();

        let mut diff2 = StateDiff::new();
        diff2.delete(key(1));
        let _root2 = state.commit(root1, &[diff2]).unwrap();

        assert!(state.is_empty());
    }

    #[test]
    fn state_multiple_diffs_in_one_commit() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff1 = StateDiff::new();
        diff1.put(key(1), val(10));

        let mut diff2 = StateDiff::new();
        diff2.put(key(2), val(20));

        state.commit(root0, &[diff1, diff2]).unwrap();
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn state_root_changes_on_same_data() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        let root1 = state.commit(root0, &[diff]).unwrap();

        let mut diff2 = StateDiff::new();
        diff2.put(key(1), val(10));
        let root2 = state.commit(root1, &[diff2]).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn state_error_display() {
        assert_ne!(StateError::Corrupt.to_string(), "");
        assert_ne!(StateError::LeaseViolation.to_string(), "");
        assert_ne!(StateError::StaleSnapshot.to_string(), "");
        assert_ne!(StateError::LimitExceeded.to_string(), "");
    }

    #[test]
    fn state_change_key() {
        let put = StateChange::Put(key(1), val(10));
        assert_eq!(put.key(), &key(1));

        let del = StateChange::Delete(key(2));
        assert_eq!(del.key(), &key(2));
    }

    #[test]
    fn state_diff_encode_empty() {
        let diff = StateDiff::new();
        let encoded = diff.to_bytes();
        assert_ne!(encoded, [] as [u8; 0]);
    }

    #[test]
    fn state_diff_encode_put() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        let encoded = diff.to_bytes();
        assert_ne!(encoded, [] as [u8; 0]);
    }

    #[test]
    fn state_diff_encode_delete() {
        let mut diff = StateDiff::new();
        diff.delete(key(1));
        let encoded = diff.to_bytes();
        assert_ne!(encoded, [] as [u8; 0]);
    }

    #[test]
    fn state_diff_encode_deterministic() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));
        assert_eq!(diff.to_bytes(), diff.to_bytes());
    }

    #[test]
    fn state_diff_encode_sorted_canonical() {
        let mut diff = StateDiff::new();
        diff.put(key(3), val(30));
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));
        diff.sort_canonical();
        let encoded = diff.to_bytes();
        assert_ne!(encoded, [] as [u8; 0]);
    }
}
