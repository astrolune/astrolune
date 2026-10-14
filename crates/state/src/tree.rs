// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Persistent representation of the unchanged, sorted version-1 Merkle tree.

use std::{collections::BTreeMap, sync::Arc};

use types::{Hash256, StateKey};

use crate::{
    MAX_SNAPSHOT_BYTES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES, StateAbsenceProof, StateChange,
    StateDiff, StateError, StateProof, StateWitness, commitment, snapshot,
};

#[derive(Debug)]
struct Node {
    hash: Hash256,
    // Shared with the rightmost leaf, rather than copied into every ancestor.
    last_key: Arc<StateKey>,
    count: usize,
    bytes: usize,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Leaf(Vec<u8>),
    Branch(Arc<Node>, Arc<Node>),
}

impl Node {
    fn leaf(key: Arc<StateKey>, value: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            hash: commitment::leaf_hash(&key, &value),
            bytes: snapshot::entry_size(&key, &value),
            last_key: key,
            count: 1,
            kind: Kind::Leaf(value),
        })
    }

    fn branch(left: Arc<Self>, right: Arc<Self>) -> Arc<Self> {
        // Both children come from a state already checked against the entry and
        // snapshot limits. These sums fit usize on every supported target.
        Arc::new(Self {
            hash: commitment::node_hash(left.hash, right.hash),
            last_key: Arc::clone(&right.last_key),
            count: left.count + right.count,
            bytes: left.bytes + right.bytes,
            kind: Kind::Branch(left, right),
        })
    }

    fn replace(node: &Arc<Self>, writes: &[(&StateKey, &Vec<u8>)]) -> Arc<Self> {
        if writes.is_empty() {
            return Arc::clone(node);
        }
        match &node.kind {
            Kind::Leaf(value) => {
                if value == writes[0].1 {
                    Arc::clone(node)
                } else {
                    Self::leaf(Arc::clone(&node.last_key), writes[0].1.clone())
                }
            }
            Kind::Branch(left, right) => {
                let split = writes.partition_point(|(key, _)| *key <= left.last_key.as_ref());
                let next_left = Self::replace(left, &writes[..split]);
                let next_right = Self::replace(right, &writes[split..]);
                if Arc::ptr_eq(left, &next_left) && Arc::ptr_eq(right, &next_right) {
                    Arc::clone(node)
                } else {
                    Self::branch(next_left, next_right)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Tree {
    root: Option<Arc<Node>>,
}

impl Tree {
    /// Input entries have passed the snapshot limits and canonical ordering checks.
    pub(crate) fn from_map(data: BTreeMap<StateKey, Vec<u8>>) -> Self {
        let mut level: Vec<_> = data
            .into_iter()
            .map(|(key, value)| Node::leaf(Arc::new(key), value))
            .collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut nodes = level.into_iter();
            while let Some(left) = nodes.next() {
                next.push(match nodes.next() {
                    Some(right) => Node::branch(left, right),
                    // Promotion must not add a hash or a sibling to v1 proofs.
                    None => left,
                });
            }
            level = next;
        }
        Self { root: level.pop() }
    }

    pub(crate) fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |node| node.count)
    }

    pub(crate) fn hash(&self) -> Hash256 {
        commitment::root_hash(
            self.len() as u64,
            self.root.as_ref().map_or(Hash256::ZERO, |node| node.hash),
        )
    }

    pub(crate) fn get(&self, key: &StateKey) -> Option<&[u8]> {
        let mut node = self.root.as_deref()?;
        loop {
            match &node.kind {
                Kind::Leaf(value) => return (key == node.last_key.as_ref()).then_some(value),
                Kind::Branch(left, right) => {
                    node = if key <= left.last_key.as_ref() {
                        left
                    } else {
                        right
                    };
                }
            }
        }
    }

    /// None requests the reference topology-changing path. Bounds are checked in
    /// operation order, before collapsing repeated writes into final values.
    pub(crate) fn prepare(&self, diffs: &[StateDiff]) -> Result<Option<Self>, StateError> {
        let mut bytes = snapshot::HEADER_BYTES + self.root.as_ref().map_or(0, |node| node.bytes);
        let mut writes = BTreeMap::<&StateKey, &Vec<u8>>::new();
        for change in diffs.iter().flat_map(|diff| &diff.changes) {
            let key = change.key();
            if key.len() > MAX_STATE_KEY_BYTES {
                return Err(StateError::LimitExceeded);
            }
            match change {
                StateChange::Put(_, value) => {
                    if value.len() > MAX_STATE_VALUE_BYTES {
                        return Err(StateError::LimitExceeded);
                    }
                    let Some(original) = self.get(key) else {
                        return Ok(None);
                    };
                    let old = writes.get(key).map_or(original, |value| value.as_slice());
                    bytes = (bytes - old.len())
                        .checked_add(value.len())
                        .filter(|size| *size <= MAX_SNAPSHOT_BYTES)
                        .ok_or(StateError::LimitExceeded)?;
                    writes.insert(key, value);
                }
                StateChange::Delete(_) => {
                    if self.get(key).is_some() {
                        return Ok(None);
                    }
                }
            }
        }
        let writes: Vec<_> = writes.into_iter().collect();
        Ok(Some(Self {
            root: self.root.as_ref().map(|root| Node::replace(root, &writes)),
        }))
    }

    pub(crate) fn entries(&self) -> Entries<'_> {
        Entries {
            pending: self.root.as_deref().into_iter().collect(),
        }
    }

    pub(crate) fn to_map(&self) -> BTreeMap<StateKey, Vec<u8>> {
        self.entries()
            .map(|(key, value)| (key.clone(), value.to_vec()))
            .collect()
    }

    fn position(&self, key: &StateKey) -> Result<usize, usize> {
        let Some(mut node) = self.root.as_deref() else {
            return Err(0);
        };
        let mut index = 0;
        loop {
            match &node.kind {
                Kind::Leaf(_) => {
                    return match key.cmp(&node.last_key) {
                        std::cmp::Ordering::Equal => Ok(index),
                        std::cmp::Ordering::Less => Err(index),
                        std::cmp::Ordering::Greater => Err(index + 1),
                    };
                }
                Kind::Branch(left, right) => {
                    if key <= left.last_key.as_ref() {
                        node = left;
                    } else {
                        index += left.count;
                        node = right;
                    }
                }
            }
        }
    }

    fn entry_proof(&self, index: usize) -> Option<(&StateKey, &[u8], StateProof)> {
        if index >= self.len() {
            return None;
        }
        let mut node = self.root.as_deref()?;
        let mut position = index;
        let mut siblings = Vec::new();
        loop {
            match &node.kind {
                Kind::Leaf(value) => {
                    siblings.reverse();
                    return Some((
                        &node.last_key,
                        value,
                        StateProof {
                            index: index as u64,
                            leaf_count: self.len() as u64,
                            siblings,
                        },
                    ));
                }
                Kind::Branch(left, right) => {
                    if position < left.count {
                        siblings.push(right.hash);
                        node = left;
                    } else {
                        position -= left.count;
                        siblings.push(left.hash);
                        node = right;
                    }
                }
            }
        }
    }

    pub(crate) fn prove(&self, key: &StateKey) -> Option<StateProof> {
        self.entry_proof(self.position(key).ok()?)
            .map(|(_, _, proof)| proof)
    }

    pub(crate) fn prove_absence(
        &self,
        key: &StateKey,
    ) -> Result<Option<StateAbsenceProof>, StateError> {
        if key.len() > MAX_STATE_KEY_BYTES {
            return Err(StateError::LimitExceeded);
        }
        let Err(index) = self.position(key) else {
            return Ok(None);
        };
        let witness = |index| {
            self.entry_proof(index)
                .map(|(key, value, proof)| StateWitness {
                    key: key.clone(),
                    value: value.to_vec(),
                    proof,
                })
        };
        Ok(Some(StateAbsenceProof {
            lower: index.checked_sub(1).and_then(witness),
            upper: witness(index),
        }))
    }
}

pub(crate) struct Entries<'a> {
    pending: Vec<&'a Node>,
}

impl<'a> Iterator for Entries<'a> {
    type Item = (&'a StateKey, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.pending.pop() {
            match &node.kind {
                Kind::Leaf(value) => return Some((&node.last_key, value)),
                Kind::Branch(left, right) => {
                    self.pending.push(right);
                    self.pending.push(left);
                }
            }
        }
        None
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
