// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded commitments to historical committees for a future activated policy profile.
//!
//! Tree shape follows RFC 9162 section 2.1, with `AstroLune` BLAKE2s domains and
//! chain/genesis/height binding. This is not the CT wire format. Construction and
//! decoding do not establish authority: the accumulator must come from independently
//! authenticated finalized state. Genesis-v1/v2 do not activate this state.

mod evidence;
pub use evidence::HistoricalEvidence;

use crate::{AuthenticatedCommittee, ConsensusError};
use codec::{DecodeError, Decoder};
use types::{Hash256, hash::domain_hash};

/// Constant-memory frontier for contiguous committee heights starting at one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeHistory {
    chain_id: u32,
    genesis: Hash256,
    entries: u64,
    frontier: [Option<Hash256>; 64],
}
impl CommitteeHistory {
    /// Maximum encoded frontier: namespace, count and at most 64 occupied peaks.
    pub const MAX_BYTES: usize = 52 + 64 * 32;

    /// Empty history bound to independently supplied network identity.
    pub fn new(chain_id: u32, genesis: Hash256) -> Result<Self, ConsensusError> {
        if chain_id == 0 || genesis == Hash256::ZERO {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(Self {
            chain_id,
            genesis,
            entries: 0,
            frontier: [None; 64],
        })
    }

    /// Number of contiguous recorded committee heights.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Chain identifier committed by every historical leaf.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Independently authenticated genesis namespace of this history.
    #[must_use]
    pub const fn genesis(&self) -> Hash256 {
        self.genesis
    }

    /// Commits the namespace, exact count and ordered tree root.
    #[must_use]
    pub fn commitment(&self) -> Hash256 {
        let mut bytes = self.namespace().to_vec();
        bytes.extend_from_slice(&self.entries.to_le_bytes());
        bytes.extend_from_slice(&self.tree_root().0);
        domain_hash(b"astrolune.committee.history.root.v1", &bytes)
    }

    /// Adds the exact next committee. The caller must authenticate its authority
    /// through execution/finality; an arbitrary constructed context is not trusted.
    /// Failed namespace/height/overflow checks leave this frontier unchanged.
    ///
    /// # Panics
    /// Panics only if the private count/frontier invariant has been violated.
    pub fn append(&mut self, context: &AuthenticatedCommittee) -> Result<(), ConsensusError> {
        let next = self
            .entries
            .checked_add(1)
            .ok_or(ConsensusError::InvalidTransition)?;
        if context.chain_id() != self.chain_id || context.height() != next {
            return Err(ConsensusError::InvalidTransition);
        }
        let mut carry = self.leaf(next, context.root());
        let mut occupied = self.entries;
        let mut level = 0;
        while occupied & 1 == 1 {
            // Private frontier invariant: occupied bits correspond exactly to present peaks.
            let left = self.frontier[level]
                .take()
                .expect("validated history frontier");
            carry = node(left, carry);
            occupied >>= 1;
            level += 1;
        }
        self.frontier[level] = Some(carry);
        self.entries = next;
        Ok(())
    }

    /// Builds a proof by reading each historical root once in height order.
    /// Memory is bounded by 64 tree frames and 64 proof hashes. The explicit work
    /// limit is checked before calling `lookup`; missing/corrupt input is rejected
    /// against this complete independently authenticated frontier.
    pub fn prove(
        &self,
        height: u64,
        maximum_entries: u64,
        mut lookup: impl FnMut(u64) -> Result<Hash256, ConsensusError>,
    ) -> Result<CommitteeHistoryProof, ConsensusError> {
        if height == 0 || height > self.entries || self.entries > maximum_entries {
            return Err(ConsensusError::InvalidTransition);
        }
        let mut proof = CommitteeHistoryProof {
            entries: self.entries,
            height,
            committee_root: Hash256::ZERO,
            siblings: Vec::new(),
        };
        let root = self.subtree(0, self.entries, &mut lookup, &mut proof)?;
        if root != self.tree_root() {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(proof)
    }

    fn subtree(
        &self,
        start: u64,
        count: u64,
        lookup: &mut impl FnMut(u64) -> Result<Hash256, ConsensusError>,
        proof: &mut CommitteeHistoryProof,
    ) -> Result<Hash256, ConsensusError> {
        if count == 1 {
            let height = start + 1;
            let root = lookup(height)?;
            if height == proof.height {
                proof.committee_root = root;
            }
            return Ok(self.leaf(height, root));
        }
        let split = split(count);
        let left = self.subtree(start, split, lookup, proof)?;
        let right = self.subtree(start + split, count - split, lookup, proof)?;
        if proof.height > start && proof.height <= start + count {
            proof.siblings.push(if proof.height <= start + split {
                right
            } else {
                left
            });
        }
        Ok(node(left, right))
    }

    fn namespace(&self) -> [u8; 36] {
        let mut bytes = [0; 36];
        bytes[..4].copy_from_slice(&self.chain_id.to_le_bytes());
        bytes[4..].copy_from_slice(&self.genesis.0);
        bytes
    }
    fn leaf(&self, height: u64, committee: Hash256) -> Hash256 {
        let mut bytes = self.namespace().to_vec();
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&committee.0);
        domain_hash(b"astrolune.committee.history.leaf.v1", &bytes)
    }
    fn tree_root(&self) -> Hash256 {
        self.frontier
            .iter()
            .flatten()
            .fold(None, |right, left| {
                Some(right.map_or(*left, |right| node(*left, right)))
            })
            .unwrap_or_else(|| domain_hash(b"astrolune.committee.history.empty.v1", &[]))
    }

    /// Exact compact frontier encoding. Occupancy is determined solely by count bits.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALCHST01".to_vec();
        bytes.extend_from_slice(&self.namespace());
        bytes.extend_from_slice(&self.entries.to_le_bytes());
        for hash in self.frontier.iter().flatten() {
            bytes.extend_from_slice(&hash.0);
        }
        bytes
    }

    /// Bounded structural decoding; caller must authenticate the resulting commitment.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALCHST01" {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;
        let genesis = Hash256(decoder.read_fixed()?);
        let mut result = Self::new(chain_id, genesis).map_err(|_| DecodeError::NonCanonical)?;
        result.entries = decoder.read_u64()?;
        if decoder.remaining() != result.entries.count_ones() as usize * 32 {
            return Err(DecodeError::NonCanonical);
        }
        for (level, entry) in result.frontier.iter_mut().enumerate() {
            if result.entries & (1 << level) != 0 {
                *entry = Some(Hash256(decoder.read_fixed()?));
            }
        }
        decoder.finish()?;
        Ok(result)
    }
}

/// Logarithmic witness for one past committee. It cannot choose its own authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeHistoryProof {
    entries: u64,
    height: u64,
    committee_root: Hash256,
    siblings: Vec<Hash256>,
}
impl CommitteeHistoryProof {
    /// Maximum framing plus the full-width 64-hash path.
    pub const MAX_BYTES: usize = 57 + 64 * 32;

    /// Historical height whose membership must match the supplied context.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Verifies exact count, committee/height, namespace and shortest tree path.
    /// `trusted` must be authenticated independently of this proof and its context.
    pub fn verify(
        &self,
        trusted: &CommitteeHistory,
        context: &AuthenticatedCommittee,
    ) -> Result<(), ConsensusError> {
        self.validate_shape()
            .map_err(|_| ConsensusError::InvalidProof)?;
        if self.entries != trusted.entries
            || context.chain_id() != trusted.chain_id
            || context.height() != self.height
            || context.root() != self.committee_root
        {
            return Err(ConsensusError::InvalidProof);
        }
        let mut index = self.height - 1;
        let mut last = self.entries - 1;
        let mut root = trusted.leaf(self.height, self.committee_root);
        for sibling in &self.siblings {
            if last == 0 {
                return Err(ConsensusError::InvalidProof);
            }
            if index & 1 == 1 || index == last {
                root = node(*sibling, root);
                while index != 0 && index & 1 == 0 {
                    index >>= 1;
                    last >>= 1;
                }
            } else {
                root = node(root, *sibling);
            }
            index >>= 1;
            last >>= 1;
        }
        if last != 0 || root != trusted.tree_root() {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<(), DecodeError> {
        if self.height == 0 || self.height > self.entries || self.siblings.len() > 64 {
            return Err(DecodeError::NonCanonical);
        }
        let mut index = self.height - 1;
        let mut count = self.entries;
        let mut depth = 0;
        while count > 1 {
            let split = split(count);
            if index < split {
                count = split;
            } else {
                index -= split;
                count -= split;
            }
            depth += 1;
        }
        if self.siblings.len() != depth {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
    /// Exact shortest-path encoding; no duplicate padding nodes are accepted.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let mut bytes = b"ALCHPF01".to_vec();
        bytes.extend_from_slice(&self.entries.to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.committee_root.0);
        bytes.push(u8::try_from(self.siblings.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for hash in &self.siblings {
            bytes.extend_from_slice(&hash.0);
        }
        Ok(bytes)
    }
    /// Checks the full envelope size and shortest-path shape before publishing it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALCHPF01" {
            return Err(DecodeError::Unsupported);
        }
        let entries = decoder.read_u64()?;
        let height = decoder.read_u64()?;
        let committee_root = Hash256(decoder.read_fixed()?);
        let count = usize::from(decoder.read_u8()?);
        if count > 64 || decoder.remaining() != count * 32 {
            return Err(DecodeError::NonCanonical);
        }
        let mut result = Self {
            entries,
            height,
            committee_root,
            siblings: Vec::with_capacity(count),
        };
        for _ in 0..count {
            result.siblings.push(Hash256(decoder.read_fixed()?));
        }
        decoder.finish()?;
        result.validate_shape()?;
        Ok(result)
    }
}
fn split(count: u64) -> u64 {
    1u64 << (count - 1).ilog2()
}
fn node(left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left.0);
    bytes[32..].copy_from_slice(&right.0);
    domain_hash(b"astrolune.committee.history.node.v1", &bytes)
}
