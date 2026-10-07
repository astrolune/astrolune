// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State diffs and canonical ordering for deferred commits.

use std::collections::BTreeMap;

use codec::traits::CanonicalEncode;
use types::StateKey;

/// A single canonical state mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateChange {
    /// Insert or replace a value.
    Put(StateKey, Vec<u8>),
    /// Remove a value.
    Delete(StateKey),
}

impl StateChange {
    /// Returns the key affected by this change.
    #[must_use]
    pub fn key(&self) -> &StateKey {
        match self {
            Self::Put(key, _) | Self::Delete(key) => key,
        }
    }
}

/// Deferred output of transaction or wave execution.
///
/// Diffs are accumulated during execution and applied atomically during
/// the commit stage. The commitment preserves operation order; the final state
/// is committed separately in lexicographic key order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateDiff {
    /// Changes in deterministic execution order.
    pub changes: Vec<StateChange>,
}

impl StateDiff {
    /// Creates an empty diff.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a put change.
    pub fn put(&mut self, key: StateKey, value: Vec<u8>) {
        self.changes.push(StateChange::Put(key, value));
    }

    /// Adds a delete change.
    pub fn delete(&mut self, key: StateKey) {
        self.changes.push(StateChange::Delete(key));
    }

    /// Returns `true` if the diff contains no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the number of changes in the diff.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Sorts changes by key in canonical order.
    ///
    /// For duplicate keys, later operations overwrite earlier ones. Delete
    /// after Put removes the key; Put after Delete re-inserts it.
    pub fn sort_canonical(&mut self) {
        self.changes.sort_by(|a, b| a.key().cmp(b.key()));
    }

    /// Applies this diff to an in-memory state, returning the new state.
    ///
    /// Changes are applied in order. For canonical diffs, call
    /// [`sort_canonical`](Self::sort_canonical) first.
    #[must_use]
    pub fn apply_to(&self, state: &BTreeMap<StateKey, Vec<u8>>) -> BTreeMap<StateKey, Vec<u8>> {
        let mut result = state.clone();
        for change in &self.changes {
            match change {
                StateChange::Put(key, value) => {
                    result.insert(key.clone(), value.clone());
                }
                StateChange::Delete(key) => {
                    result.remove(key);
                }
            }
        }
        result
    }

    /// Merges another diff into this one.
    ///
    /// The other diff's changes are appended after this diff's changes.
    /// Later changes for the same key overwrite earlier ones when applied.
    pub fn merge(&mut self, other: Self) {
        self.changes.extend(other.changes);
    }

    /// Commits every ordered operation, including repeated writes and deletions.
    #[must_use]
    pub fn commitment(&self) -> types::Hash256 {
        crypto::blake2s::domain_hash(types::domain::STATE_DIFF, &self.to_bytes())
    }
}

impl CanonicalEncode for StateChange {
    fn encode(&self, output: &mut Vec<u8>) {
        match self {
            Self::Put(key, value) => {
                output.push(0x01);
                key.encode(output);
                codec::encode_bytes(value, output);
            }
            Self::Delete(key) => {
                output.push(0x02);
                key.encode(output);
            }
        }
    }
}

impl CanonicalEncode for StateDiff {
    fn encode(&self, output: &mut Vec<u8>) {
        codec::encode_length(self.changes.len(), output);
        for change in &self.changes {
            change.encode(output);
        }
    }
}
