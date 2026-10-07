// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Rebuildable, bounded reverse state index. It never supplies consensus authority.

use crate::{Checkpoint, StorageError};
use state::{InMemoryState, StateDiff};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Maximum finalized transitions retained by the recent historical-state index.
pub const MAX_STATE_HISTORY_BLOCKS: usize = 64;
/// Maximum accounted key/value and entry bytes in the reverse state index.
pub const MAX_STATE_HISTORY_BYTES: usize = 32 * 1024 * 1024;
/// Maximum reverse changes retained across the history window.
pub const MAX_STATE_HISTORY_CHANGES: usize = 65_536;

#[derive(Debug)]
struct Undo {
    before: Checkpoint,
    after: Checkpoint,
    diff: StateDiff,
    bytes: usize,
}

#[derive(Debug, Default)]
pub(crate) struct StateHistory {
    entries: VecDeque<Undo>,
    bytes: usize,
    changes: usize,
}

impl StateHistory {
    pub(crate) fn record(
        &mut self,
        before: Option<Checkpoint>,
        after: Checkpoint,
        state: &InMemoryState,
        diffs: &[StateDiff],
    ) {
        let Some(before) = before else {
            *self = Self::default();
            return;
        };
        let Some(undo) = capture(before, after, state, diffs) else {
            // An individually oversized transition advances the floor. Index limits
            // never reject a valid consensus transition or retain a disconnected prefix.
            *self = Self::default();
            return;
        };
        self.bytes += undo.bytes;
        self.changes += undo.diff.len();
        self.entries.push_back(undo);
        while self.entries.len() > MAX_STATE_HISTORY_BLOCKS
            || self.bytes > MAX_STATE_HISTORY_BYTES
            || self.changes > MAX_STATE_HISTORY_CHANGES
        {
            let removed = self.entries.pop_front().expect("nonempty index");
            self.bytes -= removed.bytes;
            self.changes -= removed.diff.len();
        }
    }

    pub(crate) fn read(
        &self,
        height: u64,
        current: Option<Checkpoint>,
        state: &InMemoryState,
    ) -> Result<Option<(Checkpoint, InMemoryState)>, StorageError> {
        let Some(mut checkpoint) = current else {
            return Ok(None);
        };
        if height > checkpoint.height
            || height
                < self
                    .entries
                    .front()
                    .map_or(checkpoint.height, |v| v.before.height)
        {
            return Ok(None);
        }
        let mut state = state.clone();
        if height == checkpoint.height {
            return Ok(Some((checkpoint, state)));
        }
        let mut values = BTreeMap::new();
        for undo in self.entries.iter().rev() {
            if checkpoint != undo.after {
                return Err(StorageError::Corrupt);
            }
            for change in &undo.diff.changes {
                let value = match change {
                    state::StateChange::Put(_, value) => Some(value),
                    state::StateChange::Delete(_) => None,
                };
                values.insert(change.key(), value);
            }
            checkpoint = undo.before;
            if checkpoint.height == height {
                // Remove affected keys before restoring them so a valid historical
                // snapshot at the size limit cannot exceed it through a transient union.
                let mut diff = StateDiff::new();
                for key in values.keys() {
                    diff.delete((*key).clone());
                }
                for (key, value) in values {
                    if let Some(value) = value {
                        diff.put(key.clone(), value.clone());
                    }
                }
                state
                    .commit_verified(state.root(), &[diff], checkpoint.state_root)
                    .map_err(|_| StorageError::Corrupt)?;
                return Ok(Some((checkpoint, state)));
            }
        }
        Err(StorageError::Corrupt)
    }
}

fn capture(
    before: Checkpoint,
    after: Checkpoint,
    state: &InMemoryState,
    diffs: &[StateDiff],
) -> Option<Undo> {
    let mut keys = BTreeSet::new();
    let mut diff = StateDiff::new();
    let mut bytes = 160usize;
    for change in diffs.iter().flat_map(|diff| &diff.changes) {
        let key = change.key();
        if !keys.insert(key) {
            continue;
        }
        let previous = state.get(key);
        bytes = bytes.checked_add(64 + key.len() + previous.map_or(0, <[u8]>::len))?;
        if bytes > MAX_STATE_HISTORY_BYTES || keys.len() > MAX_STATE_HISTORY_CHANGES {
            return None;
        }
        match previous {
            Some(value) => diff.put(key.clone(), value.to_vec()),
            None => diff.delete(key.clone()),
        }
    }
    Some(Undo {
        before,
        after,
        diff,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Hash256, StateKey};

    fn checkpoint(height: u64, state: &InMemoryState) -> Checkpoint {
        Checkpoint {
            height,
            block: Hash256([u8::try_from(height + 1).unwrap(); 32]),
            state_root: state.root(),
        }
    }

    #[test]
    fn repeated_updates_restore_original_values_and_deletions_in_one_root_check() {
        let mut state = InMemoryState::new();
        let initial = checkpoint(0, &state);
        let mut current = initial;
        let mut index = StateHistory::default();
        let key = StateKey(vec![1]);
        let mut versions = vec![state.clone()];
        for height in 1..=8 {
            let mut diff = StateDiff::new();
            diff.put(key.clone(), vec![4]);
            diff.delete(key.clone());
            if height % 2 == 0 {
                diff.put(key.clone(), vec![9]);
            }
            let next = state
                .prepare(state.root(), std::slice::from_ref(&diff))
                .unwrap();
            let after = checkpoint(height, &next);
            index.record(Some(current), after, &state, &[diff]);
            current = after;
            state = next;
            versions.push(state.clone());
        }
        for (height, expected) in versions.iter().enumerate() {
            let (cp, actual) = index
                .read(height as u64, Some(current), &state)
                .unwrap()
                .unwrap();
            assert_eq!(cp.state_root, expected.root());
            assert_eq!(actual.export_snapshot(), expected.export_snapshot());
        }
        index.entries.back_mut().unwrap().after.block = Hash256::ZERO;
        assert!(matches!(
            index.read(0, Some(current), &state),
            Err(StorageError::Corrupt)
        ));
    }

    #[test]
    fn a_transition_exceeding_change_limit_drops_the_disconnected_prefix() {
        let state = InMemoryState::new();
        let mut index = StateHistory::default();
        let first = checkpoint(0, &state);
        let second = checkpoint(1, &state);
        index.record(Some(first), second, &state, &[]);
        let mut diff = StateDiff::new();
        for n in 0..=MAX_STATE_HISTORY_CHANGES {
            diff.put(StateKey(n.to_le_bytes().to_vec()), vec![]);
        }
        let third = checkpoint(2, &state);
        index.record(Some(second), third, &state, &[diff]);
        assert!(index.read(1, Some(third), &state).unwrap().is_none());
        assert!(index.read(2, Some(third), &state).unwrap().is_some());
        assert_eq!(index.bytes, 0);
        assert_eq!(index.changes, 0);
    }

    #[test]
    fn byte_budget_evicts_old_versions_before_the_height_limit() {
        let mut state = InMemoryState::new();
        let key = StateKey(vec![1]);
        let mut diff = StateDiff::new();
        diff.put(key, vec![5; state::MAX_STATE_VALUE_BYTES]);
        state = state
            .prepare(state.root(), std::slice::from_ref(&diff))
            .unwrap();
        let mut current = checkpoint(0, &state);
        let mut index = StateHistory::default();
        for height in 1..=40 {
            let next = checkpoint(height, &state);
            index.record(Some(current), next, &state, std::slice::from_ref(&diff));
            current = next;
            assert!(index.bytes <= MAX_STATE_HISTORY_BYTES);
        }
        assert!(index.read(1, Some(current), &state).unwrap().is_none());
        let (previous, restored) = index.read(39, Some(current), &state).unwrap().unwrap();
        assert_eq!(previous.height, 39);
        assert_eq!(restored.root(), state.root());
    }
}
