// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Receipt publication payloads and bounded, rebuildable transaction lookup indexes.

use crate::StorageError;
use codec::{CanonicalDecode, Decoder};
use state::StateValueProof;
use std::collections::{BTreeMap, VecDeque};
use types::{Block, BlockHeader, ExecutionReceipt, Hash256};

/// Maximum receipt count in one retained block.
pub const MAX_BLOCK_RECEIPTS: usize = 16_384;
/// Maximum recent transaction IDs retained in the optional lookup index.
pub const MAX_INDEXED_TRANSACTIONS: usize = 100_000;
/// Bound on encoded receipts plus the small genesis membership witness.
pub const MAX_RECEIPTS_BYTES: usize = MAX_BLOCK_RECEIPTS * 97 + 16384;

/// Execution data published atomically alongside the finalized block and state delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockEffects {
    /// Receipts in exact transaction order.
    pub receipts: Vec<ExecutionReceipt>,
    /// Post-state witness binding this block to its independently trusted genesis.
    pub genesis: StateValueProof,
    /// Optional authenticated next-committee witness, retained for streaming handoffs.
    pub committee: Option<StateValueProof>,
    /// Optional `PoTB` authority witness; mutually exclusive with the legacy committee.
    pub potb: Option<StateValueProof>,
}
impl BlockEffects {
    /// Checks all receipt IDs, their commitment, resource totals and genesis membership.
    pub fn validate(&self, block: &Block) -> Result<(), StorageError> {
        if self.receipts.len() != block.transactions.len()
            || self.receipts.len() > MAX_BLOCK_RECEIPTS
            || self
                .receipts
                .iter()
                .zip(&block.transactions)
                .any(|(receipt, tx)| receipt.transaction != transaction::compute_tx_id(tx))
        {
            return Err(StorageError::VerificationFailed);
        }
        self.validate_header(&block.header)
    }

    /// Checks the complete receipt commitment and genesis proof without block bodies.
    pub fn validate_header(&self, header: &BlockHeader) -> Result<(), StorageError> {
        if self.committee.is_some() && self.potb.is_some() {
            return Err(StorageError::VerificationFailed);
        }
        if self.receipts.len() > MAX_BLOCK_RECEIPTS {
            return Err(StorageError::LimitExceeded);
        }
        let hashes: Vec<_> = self
            .receipts
            .iter()
            .map(ExecutionReceipt::commitment)
            .collect();
        let mut resources = types::Resources::ZERO;
        for receipt in &self.receipts {
            resources = resources
                .checked_add(receipt.resources)
                .ok_or(StorageError::VerificationFailed)?;
        }
        if crypto::compute_receipts_root(&hashes) != header.receipts_root
            || !resources.fits_in(header.capacity)
            || self
                .genesis
                .verify(header.state_root, &genesis::genesis_key())
                .map_err(|_| StorageError::VerificationFailed)?
                .is_none_or(|value| value.len() != 32)
        {
            return Err(StorageError::VerificationFailed);
        }
        if let Some(proof) = &self.committee {
            let value = proof
                .verify(
                    header.state_root,
                    &types::StateKey(types::domain::COMMITTEE_STATE_KEY.to_vec()),
                )
                .map_err(|_| StorageError::VerificationFailed)?;
            if value.is_none_or(|bytes| bytes.is_empty() || bytes.len() > 2712) {
                return Err(StorageError::VerificationFailed);
            }
        }
        if let Some(proof) = &self.potb {
            let value = proof
                .verify(
                    header.state_root,
                    &types::StateKey(types::domain::POTB_STATE_KEY.to_vec()),
                )
                .map_err(|_| StorageError::VerificationFailed)?;
            if value.is_none_or(|bytes| bytes.is_empty() || bytes.len() > 7509) {
                return Err(StorageError::VerificationFailed);
            }
        }
        Ok(())
    }

    /// Encodes bounded canonical receipts and a bounded membership proof.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StorageError> {
        if self.committee.is_some() && self.potb.is_some() {
            return Err(StorageError::VerificationFailed);
        }
        if self.receipts.len() > MAX_BLOCK_RECEIPTS {
            return Err(StorageError::LimitExceeded);
        }
        let proof = self
            .genesis
            .to_bytes()
            .map_err(|_| StorageError::LimitExceeded)?;
        if proof.len() > 2048 {
            return Err(StorageError::LimitExceeded);
        }
        let mut bytes = if self.potb.is_some() {
            b"ALEFF003"
        } else if self.committee.is_some() {
            b"ALEFF002"
        } else {
            b"ALEFFECT"
        }
        .to_vec();
        bytes.extend_from_slice(
            &u32::try_from(self.receipts.len())
                .map_err(|_| StorageError::LimitExceeded)?
                .to_le_bytes(),
        );
        for receipt in &self.receipts {
            bytes.extend_from_slice(&receipt.canonical_bytes());
        }
        bytes.extend_from_slice(
            &u32::try_from(proof.len())
                .map_err(|_| StorageError::LimitExceeded)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&proof);
        if let Some(committee) = self.committee.as_ref().or(self.potb.as_ref()) {
            let proof = committee
                .to_bytes()
                .map_err(|_| StorageError::LimitExceeded)?;
            if proof.len() > if self.potb.is_some() { 12_288 } else { 4096 } {
                return Err(StorageError::LimitExceeded);
            }
            bytes.extend_from_slice(
                &u32::try_from(proof.len())
                    .map_err(|_| StorageError::LimitExceeded)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&proof);
        }
        Ok(bytes)
    }

    /// Decodes exact lengths without authenticating finality or receipt contents.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        fn decode(bytes: &[u8]) -> Result<BlockEffects, codec::DecodeError> {
            let mut decoder = Decoder::new(bytes);
            let profile = match decoder.read_exact(8)? {
                b"ALEFFECT" => 0,
                b"ALEFF002" => 2,
                b"ALEFF003" => 3,
                _ => return Err(codec::DecodeError::Unsupported),
            };
            let count = decoder.read_u32()? as usize;
            if count > MAX_BLOCK_RECEIPTS {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let data = decoder.read_exact(count * 97)?;
            let receipts = data
                .as_chunks::<97>()
                .0
                .iter()
                .map(|chunk| ExecutionReceipt::decode(chunk))
                .collect::<Result<Vec<_>, _>>()?;
            let length = decoder.read_u32()? as usize;
            if length > 2048 {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let genesis = StateValueProof::from_bytes(decoder.read_exact(length)?)
                .map_err(|_| codec::DecodeError::NonCanonical)?;
            let authority = if profile != 0 {
                let length = decoder.read_u32()? as usize;
                if length > if profile == 3 { 12_288 } else { 4096 } {
                    return Err(codec::DecodeError::LimitExceeded);
                }
                Some(
                    StateValueProof::from_bytes(decoder.read_exact(length)?)
                        .map_err(|_| codec::DecodeError::NonCanonical)?,
                )
            } else {
                None
            };
            decoder.finish()?;
            let (committee, potb) = if profile == 3 {
                (None, authority)
            } else {
                (authority, None)
            };
            Ok(BlockEffects {
                receipts,
                genesis,
                committee,
                potb,
            })
        }
        if bytes.len() > MAX_RECEIPTS_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        decode(bytes).map_err(|_| StorageError::Corrupt)
    }
}

/// Receipt data read from one immutable finalized storage record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReceipts {
    /// Certified block header.
    pub header: BlockHeader,
    /// Canonical precommit certificate.
    pub certificate: Vec<u8>,
    /// Ordered receipts and the same-state genesis witness.
    pub effects: BlockEffects,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RecentTransactions {
    by_id: BTreeMap<Hash256, (u64, usize)>,
    order: VecDeque<(Hash256, u64, usize)>,
}
impl RecentTransactions {
    pub(super) fn insert(&mut self, block: &Block) {
        for (index, tx) in block.transactions.iter().enumerate() {
            let id = transaction::compute_tx_id(tx);
            self.by_id.insert(id, (block.header.height, index));
            self.order.push_back((id, block.header.height, index));
            while self.order.len() > MAX_INDEXED_TRANSACTIONS {
                if let Some((id, height, index)) = self.order.pop_front()
                    && self.by_id.get(&id) == Some(&(height, index))
                {
                    self.by_id.remove(&id);
                }
            }
        }
    }
    pub(super) fn get(&self, id: Hash256) -> Option<(u64, usize)> {
        self.by_id.get(&id).copied()
    }
    pub(super) fn prune(&mut self, before: u64) {
        self.order.retain(|(_, height, _)| *height >= before);
        self.by_id.retain(|_, (height, _)| *height >= before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn potb_effects_use_a_distinct_tag_key_and_exclusive_bounded_witness() {
        use state::{InMemoryState, StateDatabase, StateDiff};
        let mut db = InMemoryState::new();
        let key = types::StateKey(types::domain::POTB_STATE_KEY.to_vec());
        let mut diff = StateDiff::new();
        diff.put(genesis::genesis_key(), vec![7; 32]);
        diff.put(key.clone(), vec![9; 7509]);
        db.commit(db.root(), &[diff]).unwrap();
        let snapshot = db.snapshot().unwrap();
        let mut effects = BlockEffects {
            receipts: vec![],
            genesis: StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap(),
            committee: None,
            potb: Some(StateValueProof::create(snapshot.as_ref(), &key).unwrap()),
        };
        let header = BlockHeader {
            height: 1,
            parent: Hash256::ZERO,
            state_root: db.root(),
            receipts_root: crypto::compute_receipts_root(&[]),
            transactions_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: types::Resources::ZERO,
        };
        effects.validate_header(&header).unwrap();
        let bytes = effects.to_bytes().unwrap();
        assert_eq!(&bytes[..8], b"ALEFF003");
        assert_eq!(BlockEffects::from_bytes(&bytes).unwrap(), effects);
        assert!(BlockEffects::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(BlockEffects::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
        let mut legacy = bytes.clone();
        legacy[..8].copy_from_slice(b"ALEFF002");
        assert!(BlockEffects::from_bytes(&legacy).is_err());
        effects.committee = effects.potb.clone();
        assert!(effects.to_bytes().is_err());
        assert!(effects.validate_header(&header).is_err());
        effects.committee = None;
        effects.potb = Some(effects.genesis.clone());
        assert!(effects.validate_header(&header).is_err());
        let mut diff = StateDiff::new();
        diff.put(key.clone(), vec![9; 7510]);
        db.commit(db.root(), &[diff]).unwrap();
        let snapshot = db.snapshot().unwrap();
        effects.genesis =
            StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap();
        effects.potb = Some(StateValueProof::create(snapshot.as_ref(), &key).unwrap());
        assert!(
            effects
                .validate_header(&BlockHeader {
                    state_root: db.root(),
                    ..header
                })
                .is_err()
        );
    }

    #[test]
    fn effects_preserve_legacy_bytes_and_authenticate_the_optional_witness() {
        use state::{InMemoryState, StateDatabase, StateDiff};
        let mut db = InMemoryState::new();
        let key = types::StateKey(types::domain::COMMITTEE_STATE_KEY.to_vec());
        let mut diff = StateDiff::new();
        diff.put(genesis::genesis_key(), vec![7; 32]);
        diff.put(key.clone(), vec![9; 100]);
        db.commit(db.root(), &[diff]).unwrap();
        let snapshot = db.snapshot().unwrap();
        let mut effects = BlockEffects {
            receipts: vec![],
            genesis: StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap(),
            committee: None,
            potb: None,
        };
        let header = BlockHeader {
            height: 1,
            parent: Hash256::ZERO,
            state_root: db.root(),
            receipts_root: crypto::compute_receipts_root(&[]),
            transactions_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: types::Resources::ZERO,
        };
        let proof = effects.genesis.to_bytes().unwrap();
        let mut legacy = b"ALEFFECT".to_vec();
        legacy.extend_from_slice(&0_u32.to_le_bytes());
        legacy.extend_from_slice(&u32::try_from(proof.len()).unwrap().to_le_bytes());
        legacy.extend_from_slice(&proof);
        assert_eq!(effects.to_bytes().unwrap(), legacy);
        assert_eq!(BlockEffects::from_bytes(&legacy).unwrap(), effects);
        effects.validate_header(&header).unwrap();
        effects.committee = Some(StateValueProof::create(snapshot.as_ref(), &key).unwrap());
        let encoded = effects.to_bytes().unwrap();
        assert_eq!(&encoded[..8], b"ALEFF002");
        assert_eq!(BlockEffects::from_bytes(&encoded).unwrap(), effects);
        effects.validate_header(&header).unwrap();
        for size in 0..encoded.len() {
            assert!(BlockEffects::from_bytes(&encoded[..size]).is_err());
        }
        assert!(BlockEffects::from_bytes(&[encoded.as_slice(), &[0]].concat()).is_err());
        let mut excessive = encoded;
        excessive[legacy.len()..legacy.len() + 4].copy_from_slice(&4097_u32.to_le_bytes());
        assert!(BlockEffects::from_bytes(&excessive).is_err());
        effects.committee = Some(effects.genesis.clone());
        assert!(effects.validate_header(&header).is_err());
        effects.committee = Some(
            StateValueProof::create(snapshot.as_ref(), &types::StateKey(b"missing".to_vec()))
                .unwrap(),
        );
        assert!(effects.validate_header(&header).is_err());
        let mut changed = StateDiff::new();
        changed.put(key.clone(), vec![8; 100]);
        db.commit(db.root(), &[changed]).unwrap();
        effects.committee =
            Some(StateValueProof::create(db.snapshot().unwrap().as_ref(), &key).unwrap());
        assert!(effects.validate_header(&header).is_err());
    }

    #[test]
    fn recent_index_evicts_old_positions_without_erasing_a_newer_duplicate() {
        let tx = types::Transaction {
            version: 1,
            chain_id: 7,
            sender: types::Address([1; 32]),
            nonce: 0,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources::ZERO,
            resource_limit: types::Resources::ZERO,
            access_list: vec![],
            payload: vec![],
            signature: [0; 64],
        };
        let first = transaction::compute_tx_id(&tx);
        let mut block = Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                state_root: Hash256::ZERO,
                receipts_root: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: types::Resources::ZERO,
            },
            transactions: vec![tx],
        };
        let mut index = RecentTransactions::default();
        index.insert(&block);
        block.header.height = 1;
        index.insert(&block);
        for height in 2..=MAX_INDEXED_TRANSACTIONS as u64 {
            block.header.height = height;
            block.transactions[0].nonce = height;
            index.insert(&block);
        }
        assert_eq!(index.get(first), Some((1, 0)));
        assert_eq!(index.order.len(), MAX_INDEXED_TRANSACTIONS);
        assert_eq!(index.by_id.len(), MAX_INDEXED_TRANSACTIONS);
        block.header.height += 1;
        block.transactions[0].nonce += 1;
        let newest = transaction::compute_tx_id(&block.transactions[0]);
        index.insert(&block);
        assert_eq!(index.get(first), None);
        index.prune(block.header.height);
        assert_eq!(index.get(newest), Some((block.header.height, 0)));
        assert_eq!(index.order.len(), 1);
        assert_eq!(index.by_id.len(), 1);
    }
}
