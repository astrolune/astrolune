// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Immutable shared snapshots and atomic, bounded state transitions.

use types::{Hash256, StateKey};

use crate::{
    StateAbsenceProof, StateDatabase, StateDiff, StateError, StateProof, StateSnapshot, commitment,
    snapshot, tree::Tree,
};

/// Version-1 state database; immutable snapshots share unchanged Merkle subtrees.
#[derive(Clone, Debug)]
pub struct InMemoryState {
    data: Tree,
    root: Hash256,
}

impl InMemoryState {
    /// Creates an empty database with the canonical empty-state commitment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Tree::default(),
            root: commitment::empty_root(),
        }
    }

    /// Returns the current state commitment.
    #[must_use]
    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the state has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Borrows an entry from this state version.
    #[must_use]
    pub fn get(&self, key: &StateKey) -> Option<&[u8]> {
        self.data.get(key)
    }

    /// Prepares an isolated transition, preserving transaction and duplicate-write order.
    pub fn prepare(&self, parent: Hash256, diffs: &[StateDiff]) -> Result<Self, StateError> {
        if parent != self.root {
            return Err(StateError::StaleSnapshot);
        }
        let data = match self.data.prepare(diffs)? {
            Some(data) => data,
            // Inserting or deleting a leaf can shift every subsequent v1 index.
            // Preserve the original, ordered bound checks before rebuilding.
            None => Tree::from_map(snapshot::stage(self.data.to_map(), diffs)?),
        };
        let root = data.hash();
        Ok(Self { data, root })
    }

    /// Publishes changes only when their computed root matches the proposal.
    pub fn commit_verified(
        &mut self,
        parent: Hash256,
        diffs: &[StateDiff],
        expected: Hash256,
    ) -> Result<Hash256, StateError> {
        let next = self.prepare(parent, diffs)?;
        if next.root != expected {
            return Err(StateError::RootMismatch);
        }
        *self = next;
        Ok(self.root)
    }

    /// Exports the complete canonical snapshot, bounded by `MAX_SNAPSHOT_BYTES`.
    #[must_use]
    pub fn export_snapshot(&self) -> Vec<u8> {
        snapshot::encode(self.data.len(), self.data.entries(), self.root)
    }

    /// Loads a canonical snapshot and verifies it against an independently trusted root.
    pub fn from_snapshot(bytes: &[u8], expected: Hash256) -> Result<Self, StateError> {
        let state = Self::decode_snapshot(bytes)?;
        if state.root != expected {
            return Err(StateError::RootMismatch);
        }
        Ok(state)
    }

    pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<Self, StateError> {
        let (data, root) = snapshot::decode(bytes)?;
        Ok(Self { data, root })
    }
}

impl Default for InMemoryState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateSnapshot for InMemoryState {
    fn root(&self) -> Hash256 {
        self.root
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(<[u8]>::to_vec))
    }

    fn prove(&self, key: &StateKey) -> Result<Option<StateProof>, StateError> {
        Ok(self.data.prove(key))
    }

    fn prove_absence(&self, key: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
        self.data.prove_absence(key)
    }
}

impl StateDatabase for InMemoryState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        Ok(Box::new(self.clone()))
    }

    fn prefetch(&self, _keys: &[StateKey]) -> Result<(), StateError> {
        Ok(())
    }

    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
        *self = self.prepare(parent, diffs)?;
        Ok(self.root)
    }
}
