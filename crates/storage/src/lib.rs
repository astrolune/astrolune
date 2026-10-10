// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Validator-local persistence for finalized blocks, state, and certificates.
//!
//! This crate is node infrastructure. It is not a user-data storage or file-
//! sharing service and creates no storage marketplace.
//!
//! `ChainStorage` selects append-only logs for new network directories and preserves
//! existing bounded `FileBackedStorage` archives. All backends implement `NodeStorage`.
//! The log retains bodies on disk, with an in-memory height index and latest state.
//! An opt-in [`RetentionPolicy`] compacts the log in place after a commit. Finality
//! authentication and any independently held recovery pin remain the caller's
//! responsibility; retention establishes no trust and proves nothing to a peer.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use state::{InMemoryState, StateDiff, StateError};
use types::{Block, Hash256};

mod archive;
mod chain;
mod history;
mod log;
mod log_record;
mod persistent;
mod receipts;
mod retention;
mod snapshot;
pub use receipts::{
    BlockEffects, MAX_BLOCK_RECEIPTS, MAX_INDEXED_TRANSACTIONS, MAX_RECEIPTS_BYTES, StoredReceipts,
};

pub use chain::ChainStorage;
pub use history::{MAX_STATE_HISTORY_BLOCKS, MAX_STATE_HISTORY_BYTES, MAX_STATE_HISTORY_CHANGES};
pub use log::AppendOnlyStorage;
pub use persistent::FileBackedStorage;
pub use retention::{
    DEFAULT_COMPACTION_BYTES, DEFAULT_COMPACTION_INTERVAL_BLOCKS, DEFAULT_RETAINED_BLOCKS,
    MAX_COMPACTION_BYTES, MAX_COMPACTION_INTERVAL_BLOCKS, MAX_RETAINED_BLOCKS,
    MIN_COMPACTION_BYTES, MIN_COMPACTION_INTERVAL_BLOCKS, MIN_RETAINED_BLOCKS, RetentionPolicy,
    RetentionState,
};

/// Maximum encoded reference chain archive size (256 MiB).
pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum retained checkpoints in a reference archive; prune before reaching it.
pub const MAX_ARCHIVE_CHECKPOINTS: usize = 4096;

/// Maximum individual snapshot transport chunk size.
pub const SNAPSHOT_CHUNK_BYTES: usize = 64 * 1024;

/// Durable finalized chain position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Finalized height.
    pub height: u64,
    /// Finalized block identifier.
    pub block: Hash256,
    /// State root published at this height.
    pub state_root: Hash256,
}

/// Atomic finalized update prepared before durable commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitBatch {
    /// Finalized canonical block.
    pub block: Block,
    /// Opaque canonical finality certificate.
    pub finality_certificate: Vec<u8>,
    /// Execution diffs in committed transaction order.
    pub state_diffs: Vec<StateDiff>,
    /// Optional ordered receipts and genesis binding; absent in historical v1 records.
    pub effects: Option<BlockEffects>,
}

/// Validator-local durable storage boundary.
pub trait NodeStorage {
    /// Returns the last complete checkpoint after recovery.
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError>;

    /// Atomically publishes one finalized batch after syncing its dependencies.
    /// The caller authenticates finality and execution; storage checks ordering,
    /// transaction commitments, structural bounds, and state roots.
    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError>;

    /// Exports a verified snapshot through a bounded caller-owned sink.
    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError>;

    /// Imports bounded chunks against an independently authenticated checkpoint.
    /// The caller must verify finality before passing `expected`.
    fn import_snapshot(
        &mut self,
        expected: Checkpoint,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError>;

    /// Prunes data older than the local retention policy without deleting required proofs.
    /// A full-history backend can return `StorageError::Unsupported`.
    fn prune(&mut self, before_height: u64) -> Result<(), StorageError>;
}

/// Bounded destination for snapshot chunks.
pub trait SnapshotSink {
    /// Writes one ordered immutable chunk.
    fn write_chunk(&mut self, index: u32, bytes: &[u8]) -> Result<(), StorageError>;
}

/// Bounded source for snapshot chunks.
pub trait SnapshotSource {
    /// Returns the next ordered chunk or `None` at completion.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError>;
}

/// Durable storage failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// Persistent bytes or checksums are invalid.
    Corrupt,
    /// Batch does not extend the current finalized checkpoint.
    InvalidOrder,
    /// A commitment or finality proof is invalid.
    VerificationFailed,
    /// Requested operation exceeds a configured bound.
    LimitExceeded,
    /// Persistent I/O did not complete.
    Io,
    /// Another process holds the database writer lock.
    Locked,
    /// Publication occurred but durability is uncertain; reopen before further work.
    DurabilityUnknown,
    /// This backend cannot perform the requested retention/import operation.
    Unsupported,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt => write!(f, "storage data is corrupt"),
            Self::InvalidOrder => write!(f, "invalid commit order"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::LimitExceeded => write!(f, "storage limit exceeded"),
            Self::Io => write!(f, "storage I/O error"),
            Self::Locked => write!(f, "storage is locked by another writer"),
            Self::DurabilityUnknown => {
                write!(f, "storage durability is uncertain; reopen required")
            }
            Self::Unsupported => write!(f, "operation is not supported by this storage backend"),
        }
    }
}

impl std::error::Error for StorageError {}

/// In-memory reference implementation of `NodeStorage`.
///
/// Stores finalized blocks, state, and certificates in memory. No data
/// survives process restarts. Useful for testing and development.
#[derive(Clone, Debug)]
pub struct InMemoryStorage {
    /// Finalized checkpoints indexed by height.
    checkpoints: BTreeMap<u64, Checkpoint>,
    /// State database.
    state: InMemoryState,
    /// Block bodies indexed by block hash.
    blocks: BTreeMap<Hash256, Block>,
    /// Finality certificates indexed by block hash.
    certificates: BTreeMap<Hash256, Vec<u8>>,
    /// Immutable historical state views retained for authenticated snapshot export.
    snapshots: BTreeMap<u64, InMemoryState>,
    /// Optional ordered execution metadata for new finalized blocks.
    effects: BTreeMap<u64, BlockEffects>,
    /// Rebuildable recent transaction lookup index.
    transactions: receipts::RecentTransactions,
}

impl InMemoryStorage {
    /// Creates a new empty storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoints: BTreeMap::new(),
            state: InMemoryState::new(),
            blocks: BTreeMap::new(),
            certificates: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            effects: BTreeMap::new(),
            transactions: receipts::RecentTransactions::default(),
        }
    }

    /// Returns the current checkpoint, if any.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoints.values().next_back()
    }

    /// Returns the number of finalized blocks stored.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Height of the oldest retained checkpoint; absence means an empty store.
    /// A floor states local availability, never that a height was not finalized.
    #[must_use]
    pub fn retained_floor(&self) -> Option<u64> {
        self.checkpoints.keys().next().copied()
    }

    /// Lowest height whose exact state this reference backend still retains.
    #[must_use]
    pub fn history_floor(&self) -> Option<u64> {
        self.snapshots.keys().next().copied()
    }

    /// Returns the underlying state database (read-only).
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Reads a retained state and its exact checkpoint; absence means unavailable history.
    pub fn read_state_at(
        &self,
        height: u64,
    ) -> Result<Option<(Checkpoint, InMemoryState)>, StorageError> {
        let Some(checkpoint) = self.checkpoints.get(&height) else {
            return Ok(None);
        };
        let state = self.snapshots.get(&height).ok_or(StorageError::Corrupt)?;
        if state.root() != checkpoint.state_root {
            return Err(StorageError::Corrupt);
        }
        Ok(Some((*checkpoint, state.clone())))
    }

    /// Returns a block by its hash.
    #[must_use]
    pub fn get_block(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Returns a finality certificate by its block hash.
    #[must_use]
    pub fn get_certificate(&self, hash: &Hash256) -> Option<&[u8]> {
        self.certificates.get(hash).map(Vec::as_slice)
    }

    /// Finds a recent finalized transaction. Missing does not prove non-inclusion.
    #[must_use]
    pub fn transaction_location(&self, id: Hash256) -> Option<(u64, usize)> {
        self.transactions.get(id)
    }

    /// Reads ordered receipt metadata when that block retained it.
    pub fn read_receipts(&self, height: u64) -> Result<Option<StoredReceipts>, StorageError> {
        let Some(effects) = self.effects.get(&height) else {
            return Ok(None);
        };
        let cp = self.checkpoints.get(&height).ok_or(StorageError::Corrupt)?;
        let block = self.blocks.get(&cp.block).ok_or(StorageError::Corrupt)?;
        let certificate = self
            .certificates
            .get(&cp.block)
            .ok_or(StorageError::Corrupt)?;
        effects.validate(block)?;
        Ok(Some(StoredReceipts {
            header: block.header,
            certificate: certificate.clone(),
            effects: effects.clone(),
        }))
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeStorage for InMemoryStorage {
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError> {
        Ok(self.checkpoints.values().next_back().copied())
    }

    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError> {
        archive::validate_block(&batch.block, &batch.finality_certificate)?;
        if let Some(effects) = &batch.effects {
            effects.validate(&batch.block)?;
        }
        let (expected_height, expected_parent) = match self.checkpoint() {
            Some(checkpoint) => (
                checkpoint
                    .height
                    .checked_add(1)
                    .ok_or(StorageError::InvalidOrder)?,
                checkpoint.block,
            ),
            None => (0, Hash256::ZERO),
        };
        if batch.block.header.height != expected_height
            || batch.block.header.parent != expected_parent
        {
            return Err(StorageError::InvalidOrder);
        }
        // Nothing is published until the complete execution overlay matches the header.
        let next = self
            .state
            .prepare(self.state.root(), &batch.state_diffs)
            .map_err(map_state_error)?;
        if next.root() != batch.block.header.state_root {
            return Err(StorageError::VerificationFailed);
        }

        let block_hash = batch.block.header.compute_hash();
        self.transactions.insert(&batch.block);
        if let Some(effects) = &batch.effects {
            self.effects
                .insert(batch.block.header.height, effects.clone());
        }
        self.blocks.insert(block_hash, batch.block.clone());
        self.certificates
            .insert(block_hash, batch.finality_certificate.clone());

        let checkpoint = Checkpoint {
            height: batch.block.header.height,
            block: block_hash,
            state_root: next.root(),
        };
        self.snapshots.insert(checkpoint.height, next.clone());
        self.state = next;
        self.checkpoints.insert(checkpoint.height, checkpoint);

        Ok(checkpoint)
    }

    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError> {
        if self.checkpoints.get(&checkpoint.height) != Some(&checkpoint) {
            return Err(StorageError::VerificationFailed);
        }
        let state = self
            .snapshots
            .get(&checkpoint.height)
            .ok_or(StorageError::Corrupt)?;
        snapshot::export(checkpoint, state, sink)
    }

    fn import_snapshot(
        &mut self,
        expected: Checkpoint,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError> {
        if self
            .checkpoint()
            .is_some_and(|current| expected.height <= current.height)
        {
            return Err(StorageError::InvalidOrder);
        }
        let next = snapshot::import(expected, source)?;
        // The trusted checkpoint may be on a different history; retain no unverified ancestors.
        self.blocks.clear();
        self.certificates.clear();
        self.checkpoints.clear();
        self.snapshots.clear();
        self.effects.clear();
        self.transactions = receipts::RecentTransactions::default();
        self.snapshots.insert(expected.height, next.clone());
        self.state = next;
        self.checkpoints.insert(expected.height, expected);
        Ok(expected)
    }

    fn prune(&mut self, before_height: u64) -> Result<(), StorageError> {
        let latest = self.checkpoint().map(|checkpoint| checkpoint.height);
        let heights_to_prune: Vec<u64> = self
            .checkpoints
            .keys()
            .copied()
            .filter(|&h| h < before_height && Some(h) != latest)
            .collect();

        for height in &heights_to_prune {
            if let Some(checkpoint) = self.checkpoints.remove(height) {
                self.blocks.remove(&checkpoint.block);
                self.certificates.remove(&checkpoint.block);
            }
        }

        self.snapshots
            .retain(|&height, _| self.checkpoints.contains_key(&height));
        self.effects
            .retain(|height, _| self.checkpoints.contains_key(height));
        self.transactions
            .prune(before_height.min(latest.unwrap_or(0)));

        Ok(())
    }
}

fn map_state_error(error: StateError) -> StorageError {
    match error {
        StateError::StaleSnapshot => StorageError::InvalidOrder,
        StateError::RootMismatch => StorageError::VerificationFailed,
        StateError::LimitExceeded => StorageError::LimitExceeded,
        StateError::Io | StateError::Locked | StateError::DurabilityUnknown => StorageError::Io,
        StateError::Corrupt | StateError::LeaseViolation => StorageError::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Resources;

    fn make_block(height: u64, parent: Hash256, state_root: Hash256) -> Block {
        Block {
            header: types::BlockHeader {
                height,
                parent,
                transactions_root: Hash256::ZERO,
                state_root,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: Resources {
                    compute: 100,
                    memory: 100,
                    io: 100,
                    bandwidth: 100,
                },
            },
            transactions: Vec::new(),
        }
    }

    fn make_batch(height: u64, parent_hash: Hash256, state_root: Hash256) -> CommitBatch {
        CommitBatch {
            effects: None,
            block: make_block(height, parent_hash, state_root),
            finality_certificate: vec![0xAA; 32],
            state_diffs: Vec::new(),
        }
    }

    struct Source(std::vec::IntoIter<Vec<u8>>);
    impl SnapshotSource for Source {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.0.next())
        }
    }

    struct VecSink<'a>(&'a mut Vec<Vec<u8>>);

    impl SnapshotSink for VecSink<'_> {
        fn write_chunk(&mut self, _index: u32, bytes: &[u8]) -> Result<(), StorageError> {
            self.0.push(bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn empty_storage_recovers_none() {
        let mut storage = InMemoryStorage::new();
        assert!(storage.recover().unwrap().is_none());
    }

    #[test]
    fn commit_advances_checkpoint() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, storage.state().root());
        let checkpoint = storage.commit(&batch).unwrap();
        assert_eq!(checkpoint.height, 0);
        assert!(storage.block_count() > 0);
    }

    #[test]
    fn commit_rejects_wrong_height() {
        let mut storage = InMemoryStorage::new();
        let mut batch = make_batch(0, Hash256::ZERO, storage.state().root());
        batch.block.header.height = 5;
        assert_eq!(storage.commit(&batch), Err(StorageError::InvalidOrder));
    }

    #[test]
    fn commit_rejects_wrong_state_root() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, Hash256([0xFF; 32]));
        assert_eq!(
            storage.commit(&batch),
            Err(StorageError::VerificationFailed)
        );
    }

    #[test]
    fn sequential_commits() {
        let mut storage = InMemoryStorage::new();
        let batch0 = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp0 = storage.commit(&batch0).unwrap();
        let batch1 = make_batch(1, cp0.block, storage.state().root());
        let cp1 = storage.commit(&batch1).unwrap();
        assert_eq!(cp1.height, 1);
        assert_eq!(storage.recover().unwrap().unwrap().height, 1);
    }

    #[test]
    fn prune_removes_old_data() {
        let mut storage = InMemoryStorage::new();
        let batch0 = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp0 = storage.commit(&batch0).unwrap();
        let batch1 = make_batch(1, cp0.block, storage.state().root());
        storage.commit(&batch1).unwrap();
        storage.prune(1).unwrap();
        assert_eq!(storage.checkpoint().unwrap().height, 1);
    }

    #[test]
    fn snapshot_export_import_roundtrip() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp = storage.commit(&batch).unwrap();

        let mut exported = Vec::new();
        storage
            .export_snapshot(cp, &mut VecSink(&mut exported))
            .unwrap();
        let mut restored = InMemoryStorage::new();
        assert_eq!(
            restored.import_snapshot(cp, &mut Source(exported.into_iter())),
            Ok(cp)
        );
        assert_eq!(restored.state().root(), storage.state().root());
    }

    #[test]
    fn storage_error_display() {
        assert_ne!(StorageError::Corrupt.to_string(), "");
        assert_ne!(StorageError::InvalidOrder.to_string(), "");
        assert_ne!(StorageError::VerificationFailed.to_string(), "");
        assert_ne!(StorageError::LimitExceeded.to_string(), "");
        assert_ne!(StorageError::Io.to_string(), "");
    }

    #[test]
    fn recover_returns_latest_checkpoint() {
        let mut storage = InMemoryStorage::new();
        for h in 0..5u64 {
            let parent = if h == 0 {
                Hash256::ZERO
            } else {
                storage.checkpoint().unwrap().block
            };
            let batch = make_batch(h, parent, storage.state().root());
            storage.commit(&batch).unwrap();
        }
        assert_eq!(storage.recover().unwrap().unwrap().height, 4);
    }
}
