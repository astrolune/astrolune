// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Network storage selection with explicit, non-destructive legacy compatibility.

use crate::{
    AppendOnlyStorage, Checkpoint, CommitBatch, FileBackedStorage, NodeStorage, SnapshotSink,
    SnapshotSource, StorageError,
};
use state::InMemoryState;
use std::{fs::File, io::Read, path::Path};
use types::{Block, Hash256};

#[derive(Debug)]
enum Backend {
    Log(AppendOnlyStorage),
    Archive(FileBackedStorage),
}

/// New network directories use an append-only log. Existing `ASTSTORE` archives
/// retain their original format and limits; opening never silently migrates them.
#[derive(Debug)]
pub struct ChainStorage(Backend);

macro_rules! dispatch {
    ($this:expr, $store:ident => $call:expr) => {
        match $this {
            Backend::Log($store) => $call,
            Backend::Archive($store) => $call,
        }
    };
}

impl ChainStorage {
    /// Opens the detected format, or creates a new log in an existing directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        let mut prefix = [0; 8];
        let archive = match File::open(path) {
            Ok(mut file) => {
                file.read_exact(&mut prefix)
                    .map_err(|_| StorageError::Corrupt)?;
                prefix == *b"ASTSTORE"
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(StorageError::Io),
        };
        if archive {
            let mut head = path.as_os_str().to_owned();
            head.push(".head");
            match std::fs::symlink_metadata(Path::new(&head)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(StorageError::Corrupt),
            }
            FileBackedStorage::open(path)
                .map(Backend::Archive)
                .map(Self)
        } else {
            AppendOnlyStorage::open(path).map(Backend::Log).map(Self)
        }
    }
    /// Whether this directory still uses the bounded legacy archive.
    #[must_use]
    pub const fn is_legacy_archive(&self) -> bool {
        matches!(self.0, Backend::Archive(_))
    }
    /// Latest published checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        dispatch!(&self.0, s => s.checkpoint())
    }
    /// Latest committed state.
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        dispatch!(&self.0, s => s.state())
    }

    /// Reads an exact historical state within the backend's retained index window.
    pub fn read_state_at(
        &self,
        height: u64,
    ) -> Result<Option<(Checkpoint, InMemoryState)>, StorageError> {
        dispatch!(&self.0, s => s.read_state_at(height))
    }
    /// Retained block body count.
    #[must_use]
    pub fn block_count(&self) -> usize {
        dispatch!(&self.0, s => s.block_count())
    }
    /// Reads retained history, propagating on-disk corruption and I/O errors.
    pub fn read_finalized(&self, height: u64) -> Result<Option<(Block, Vec<u8>)>, StorageError> {
        dispatch!(&self.0, s => s.read_finalized(height))
    }
    /// Finds a recent finalized transaction; explicit-height receipt reads bypass eviction.
    #[must_use]
    pub fn transaction_location(&self, id: Hash256) -> Option<(u64, usize)> {
        dispatch!(&self.0, s => s.transaction_location(id))
    }
    /// Reads ordered execution receipts retained at an exact height.
    pub fn read_receipts(
        &self,
        height: u64,
    ) -> Result<Option<crate::StoredReceipts>, StorageError> {
        dispatch!(&self.0, s => s.read_receipts(height))
    }
    /// Installs a trusted genesis anchor only in an empty store.
    pub fn initialize_genesis(
        &mut self,
        hash: Hash256,
        state: InMemoryState,
    ) -> Result<Checkpoint, StorageError> {
        dispatch!(&mut self.0, s => s.initialize_genesis(hash, state))
    }
}
impl NodeStorage for ChainStorage {
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError> {
        dispatch!(&mut self.0, s => s.recover())
    }
    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError> {
        dispatch!(&mut self.0, s => s.commit(batch))
    }
    fn export_snapshot(
        &self,
        cp: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError> {
        dispatch!(&self.0, s => s.export_snapshot(cp, sink))
    }
    fn import_snapshot(
        &mut self,
        cp: Checkpoint,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError> {
        dispatch!(&mut self.0, s => s.import_snapshot(cp, source))
    }
    fn prune(&mut self, before: u64) -> Result<(), StorageError> {
        dispatch!(&mut self.0, s => s.prune(before))
    }
}
