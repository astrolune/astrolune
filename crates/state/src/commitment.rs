// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Count-bound Merkle commitments over lexicographically sorted state entries.

use std::collections::BTreeMap;

use crypto::blake2s::domain_hash;
use types::{Hash256, StateKey, domain};

use crate::{MAX_STATE_ENTRIES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES, StateError};

/// An authenticated entry bordering a range of absent keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateWitness {
    /// Complete key bytes in lexicographic order.
    pub key: StateKey,
    /// Complete value authenticated by the membership path.
    pub value: Vec<u8>,
    /// Position and siblings under the trusted state root.
    pub proof: StateProof,
}

/// Non-membership evidence under a trusted, canonically ordered state root.
///
/// Interior gaps require two adjacent entries. A boundary gap requires the first
/// or last entry, and an empty tree requires neither. Neighbor values are included
/// because the version-1 leaf commitment binds both the key and the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateAbsenceProof {
    /// Immediate predecessor, or `None` before the first entry.
    pub lower: Option<StateWitness>,
    /// Immediate successor, or `None` after the last entry.
    pub upper: Option<StateWitness>,
}

impl StateAbsenceProof {
    /// Authenticates the gap containing `key`, including adjacency and tree edges.
    ///
    /// The caller must authenticate `root` independently. As with membership
    /// proofs, a root supplied by the prover alone does not establish finality.
    #[must_use]
    pub fn verify(&self, root: Hash256, key: &StateKey) -> bool {
        if key.len() > MAX_STATE_KEY_BYTES {
            return false;
        }
        if let Some(lower) = &self.lower
            && (lower.key >= *key || !lower.proof.verify(root, &lower.key, &lower.value))
        {
            return false;
        }
        if let Some(upper) = &self.upper
            && (upper.key <= *key || !upper.proof.verify(root, &upper.key, &upper.value))
        {
            return false;
        }
        match (&self.lower, &self.upper) {
            (None, None) => root == empty_root(),
            (None, Some(upper)) => upper.proof.index == 0,
            (Some(lower), None) => lower.proof.index + 1 == lower.proof.leaf_count,
            (Some(lower), Some(upper)) => {
                lower.proof.leaf_count == upper.proof.leaf_count
                    && lower.proof.index + 1 == upper.proof.index
            }
        }
    }
}

/// Membership path for a key/value pair under a trusted state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    /// Zero-based position in lexicographic key order.
    pub index: u64,
    /// Total leaves, authenticated by the root wrapper.
    pub leaf_count: u64,
    /// Siblings from the leaf upwards; unpaired nodes are promoted unchanged.
    pub siblings: Vec<Hash256>,
}

impl StateProof {
    /// Checks the value, position, tree shape, and every sibling against `root`.
    #[must_use]
    pub fn verify(&self, root: Hash256, key: &StateKey, value: &[u8]) -> bool {
        if self.leaf_count == 0
            || self.leaf_count > MAX_STATE_ENTRIES as u64
            || self.index >= self.leaf_count
            || self.siblings.len() > 20
            || key.len() > MAX_STATE_KEY_BYTES
            || value.len() > MAX_STATE_VALUE_BYTES
        {
            return false;
        }
        let mut hash = leaf_hash(key, value);
        let mut index = self.index;
        let mut width = self.leaf_count;
        let mut siblings = self.siblings.iter();
        while width > 1 {
            if index % 2 == 1 {
                let Some(left) = siblings.next() else {
                    return false;
                };
                hash = node_hash(*left, hash);
            } else if index + 1 < width {
                let Some(right) = siblings.next() else {
                    return false;
                };
                hash = node_hash(hash, *right);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none() && root_hash(self.leaf_count, hash) == root
    }
}

/// Commitment of the empty state; it is intentionally not the all-zero sentinel.
#[must_use]
pub fn empty_root() -> Hash256 {
    root_hash(0, Hash256::ZERO)
}

pub(crate) fn compute_root(data: &BTreeMap<StateKey, Vec<u8>>) -> Hash256 {
    let mut level: Vec<_> = data.iter().map(|(k, v)| leaf_hash(k, v)).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    root_hash(
        data.len() as u64,
        level.first().copied().unwrap_or(Hash256::ZERO),
    )
}

pub(crate) fn prove(data: &BTreeMap<StateKey, Vec<u8>>, key: &StateKey) -> Option<StateProof> {
    let index = data.keys().position(|candidate| candidate == key)?;
    Some(proof_at(data, index))
}

pub(crate) fn prove_absence(
    data: &BTreeMap<StateKey, Vec<u8>>,
    key: &StateKey,
) -> Result<Option<StateAbsenceProof>, StateError> {
    if key.len() > MAX_STATE_KEY_BYTES {
        return Err(StateError::LimitExceeded);
    }
    if data.contains_key(key) {
        return Ok(None);
    }
    let mut lower = None;
    let mut upper = None;
    for (index, (candidate, value)) in data.iter().enumerate() {
        if candidate < key {
            lower = Some((index, candidate, value));
        } else {
            upper = Some((index, candidate, value));
            break;
        }
    }
    let witness = |(index, key, value): (usize, &StateKey, &Vec<u8>)| StateWitness {
        key: key.clone(),
        value: value.clone(),
        proof: proof_at(data, index),
    };
    Ok(Some(StateAbsenceProof {
        lower: lower.map(witness),
        upper: upper.map(witness),
    }))
}

fn proof_at(data: &BTreeMap<StateKey, Vec<u8>>, index: usize) -> StateProof {
    let mut proof = StateProof {
        index: index as u64,
        leaf_count: data.len() as u64,
        siblings: Vec::new(),
    };
    let mut position = index;
    let mut level: Vec<_> = data.iter().map(|(k, v)| leaf_hash(k, v)).collect();
    while level.len() > 1 {
        if let Some(sibling) = level.get(position ^ 1) {
            proof.siblings.push(*sibling);
        }
        position /= 2;
        level = next_level(&level);
    }
    proof
}

fn next_level(level: &[Hash256]) -> Vec<Hash256> {
    level
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                node_hash(pair[0], pair[1])
            } else {
                pair[0]
            }
        })
        .collect()
}

fn leaf_hash(key: &StateKey, value: &[u8]) -> Hash256 {
    // Fixed-width lengths separate keys from values even when bytes share prefixes.
    let mut bytes = Vec::with_capacity(16 + key.len() + value.len());
    bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
    domain_hash(domain::STATE_LEAF, &bytes)
}

fn node_hash(left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    domain_hash(domain::STATE_NODE, &bytes)
}

fn root_hash(count: u64, top: Hash256) -> Hash256 {
    let mut bytes = [0; 40];
    bytes[..8].copy_from_slice(&count.to_le_bytes());
    bytes[8..].copy_from_slice(top.as_bytes());
    domain_hash(domain::STATE_ROOT, &bytes)
}
