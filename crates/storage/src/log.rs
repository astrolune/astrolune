// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Append-only bodies and state deltas, published through a small durable head file.

use crate::{
    Checkpoint, CommitBatch, NodeStorage, SnapshotSink, SnapshotSource, StorageError,
    log_record::{self, MAX_RECORD_BYTES, Record},
    map_state_error, snapshot,
};
use state::InMemoryState;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use types::{Block, Hash256, hash::domain_hash};

const MAGIC: &[u8; 8] = b"ASTLOG01";
const HEADER_SIZE: usize = 40;
const HEADER_BYTES: u64 = HEADER_SIZE as u64;
const HEAD_BYTES: usize = 80;
const FRAME_OVERHEAD: u64 = 40;
const DOMAIN: &[u8] = b"astrolune.storage.log.v1";
const HEAD_DOMAIN: &[u8] = b"astrolune.storage.head.v1";

#[derive(Clone, Copy, Debug)]
struct Location {
    offset: u64,
    end: u64,
    previous: Hash256,
    hash: Hash256,
}

/// Single-writer chain log retaining bodies on disk and only a height index in memory.
///
/// Commits sync the appended delta before atomically publishing `.head`. Recovery
/// verifies every published record and replays ordered deltas. Only unpublished
/// tail bytes may be discarded. The latest state still uses the bounded reference
/// in-memory state engine. This backend does not prune or replace existing history.
#[derive(Debug)]
pub struct AppendOnlyStorage {
    path: PathBuf,
    file: File,
    _lock: File,
    end: u64,
    tip: Hash256,
    state: InMemoryState,
    checkpoint: Option<Checkpoint>,
    index: BTreeMap<u64, Location>,
    transactions: crate::receipts::RecentTransactions,
    history: crate::history::StateHistory,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    AppendSynced,
    HeadRenamed,
    Rollback,
}

impl AppendOnlyStorage {
    /// Opens a log, verifies committed bytes, and discards only an unpublished tail.
    /// The parent must exist; `.lock`, `.head`, and `.pending` are reserved sidecars.
    /// Missing/invalid heads for existing logs fail closed, never reset to genesis.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = canonical_path(path.as_ref())?;
        for candidate in [&path, &sidecar(&path, ".lock"), &sidecar(&path, ".head")] {
            reject_symlink(candidate)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(&path, ".lock"))
            .map_err(|_| StorageError::Io)?;
        lock.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => StorageError::Locked,
            TryLockError::Error(_) => StorageError::Io,
        })?;
        let (mut file, create) = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => (file, false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // An orphan head is evidence of missing committed history, not an empty store.
                match fs::symlink_metadata(sidecar(&path, ".head")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(StorageError::Corrupt),
                }
                (
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|_| StorageError::Io)?,
                    true,
                )
            }
            Err(_) => return Err(StorageError::Io),
        };
        let initial_tip = domain_hash(DOMAIN, MAGIC);
        if create {
            file.write_all(MAGIC)
                .and_then(|()| file.write_all(initial_tip.as_bytes()))
                .and_then(|()| file.sync_all())
                .map_err(|_| StorageError::Io)?;
        } else {
            let mut header = [0; HEADER_SIZE];
            file.read_exact(&mut header)
                .map_err(|_| StorageError::Corrupt)?;
            if &header[..8] != MAGIC || header[8..] != initial_tip.0 {
                return Err(StorageError::Corrupt);
            }
        }
        let mut log = Self {
            path,
            file,
            _lock: lock,
            end: HEADER_BYTES,
            tip: initial_tip,
            state: InMemoryState::new(),
            checkpoint: None,
            index: BTreeMap::new(),
            transactions: crate::receipts::RecentTransactions::default(),
            history: crate::history::StateHistory::default(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        if create {
            log.prepare_pending()?;
            log.publish_head(HEADER_BYTES, initial_tip)?;
        } else {
            let (end, tip) = read_head(&log.path)?;
            if end < HEADER_BYTES || log.file.metadata().map_err(|_| StorageError::Io)?.len() < end
            {
                return Err(StorageError::Corrupt);
            }
            while log.end < end {
                let (record, location) = read_record(&mut log.file, log.end, end, log.tip)?;
                log.index_record(&record, location);
                let (cp, state) = log.replay_record(&record)?;
                log.state = state;
                log.checkpoint = Some(cp);
                log.end = location.end;
                log.tip = location.hash;
            }
            if log.end != end || log.tip != tip {
                return Err(StorageError::Corrupt);
            }
            // Verify the entire published prefix BEFORE touching any tail.
            log.file
                .set_len(end)
                .and_then(|()| log.file.sync_all())
                .map_err(|_| StorageError::Io)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(sidecar(&log.path, ".head"))
                .and_then(|head| head.sync_all())
                .and_then(|()| sync_parent(&log.path))
                .map_err(|_| StorageError::Io)?;
        }
        Ok(log)
    }

    /// Latest durably published checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }
    /// Latest committed state, without historical state copies.
    #[must_use]
    pub const fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Reconstructs recent state using a bounded reverse index rebuilt from committed records.
    /// Missing history means unavailable, never an authenticated absent value.
    pub fn read_state_at(
        &self,
        height: u64,
    ) -> Result<Option<(Checkpoint, InMemoryState)>, StorageError> {
        self.ready()?;
        self.history.read(height, self.checkpoint, &self.state)
    }
    /// Number of retained block bodies (excludes an imported/genesis anchor).
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.index.len()
    }

    /// Reads the committed anchor independently of recent-index eviction.
    /// Structural integrity is checked; authentication requires an independent trust pin.
    pub fn read_anchor(&self) -> Result<Option<(Checkpoint, InMemoryState)>, StorageError> {
        self.ready()?;
        if self.end == HEADER_BYTES {
            return Ok(None);
        }
        let mut file = File::open(&self.path).map_err(|_| StorageError::Io)?;
        let (record, _) = read_record(
            &mut file,
            HEADER_BYTES,
            self.end,
            domain_hash(DOMAIN, MAGIC),
        )?;
        match record {
            Record::Anchor(cp, state) if cp.state_root == state.root() => Ok(Some((cp, state))),
            _ => Err(StorageError::Corrupt),
        }
    }

    /// Installs a trusted genesis anchor into an empty log.
    pub fn initialize_genesis(
        &mut self,
        hash: Hash256,
        state: InMemoryState,
    ) -> Result<Checkpoint, StorageError> {
        self.install_anchor(
            Checkpoint {
                height: 0,
                block: hash,
                state_root: state.root(),
            },
            state,
        )
    }

    pub(crate) fn install_anchor(
        &mut self,
        cp: Checkpoint,
        state: InMemoryState,
    ) -> Result<Checkpoint, StorageError> {
        self.ready()?;
        if self.checkpoint.is_some() {
            return Err(StorageError::InvalidOrder);
        }
        if cp.block.is_zero() || cp.state_root != state.root() {
            return Err(StorageError::VerificationFailed);
        }
        self.append(&log_record::anchor(cp, &state)?)?;
        self.checkpoint = Some(cp);
        self.state = state;
        Ok(cp)
    }

    /// Reads and rechecks one block and certificate on demand. Disk errors propagate.
    pub fn read_finalized(&self, height: u64) -> Result<Option<(Block, Vec<u8>)>, StorageError> {
        self.ready()?;
        let Some(location) = self.index.get(&height) else {
            return Ok(None);
        };
        let mut file = File::open(&self.path).map_err(|_| StorageError::Io)?;
        let (record, actual) =
            read_record(&mut file, location.offset, location.end, location.previous)?;
        if actual.hash != location.hash || actual.end != location.end {
            return Err(StorageError::Corrupt);
        }
        match record {
            Record::Batch(batch) if batch.block.header.height == height => {
                Ok(Some((batch.block, batch.finality_certificate)))
            }
            _ => Err(StorageError::Corrupt),
        }
    }

    /// Finds a recent transaction without scanning retained history.
    #[must_use]
    pub fn transaction_location(&self, id: Hash256) -> Option<(u64, usize)> {
        self.transactions.get(id)
    }

    /// Reads receipts atomically retained with the finalized block at this height.
    pub fn read_receipts(
        &self,
        height: u64,
    ) -> Result<Option<crate::StoredReceipts>, StorageError> {
        self.ready()?;
        let Some(location) = self.index.get(&height) else {
            return Ok(None);
        };
        let mut file = File::open(&self.path).map_err(|_| StorageError::Io)?;
        let (record, actual) =
            read_record(&mut file, location.offset, location.end, location.previous)?;
        if actual.hash != location.hash || actual.end != location.end {
            return Err(StorageError::Corrupt);
        }
        match record {
            Record::Batch(batch) if batch.block.header.height == height => {
                let batch = *batch;
                Ok(batch.effects.map(|effects| crate::StoredReceipts {
                    header: batch.block.header,
                    certificate: batch.finality_certificate,
                    effects,
                }))
            }
            _ => Err(StorageError::Corrupt),
        }
    }
    fn index_record(&mut self, record: &Record, location: Location) {
        if let Record::Batch(batch) = record {
            self.transactions.insert(&batch.block);
            self.index.insert(batch.block.header.height, location);
        }
    }

    fn replay_record(
        &mut self,
        record: &Record,
    ) -> Result<(Checkpoint, InMemoryState), StorageError> {
        let (checkpoint, state) = apply(record, self.checkpoint, &self.state)?;
        if let Record::Batch(batch) = record {
            self.history
                .record(self.checkpoint, checkpoint, &self.state, &batch.state_diffs);
        }
        Ok((checkpoint, state))
    }

    fn ready(&self) -> Result<(), StorageError> {
        if self.poisoned {
            Err(StorageError::DurabilityUnknown)
        } else {
            Ok(())
        }
    }

    fn prepare_pending(&self) -> Result<(), StorageError> {
        match fs::remove_file(sidecar(&self.path, ".pending")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StorageError::Io),
        }
    }

    fn publish_head(&mut self, end: u64, tip: Hash256) -> Result<(), StorageError> {
        let pending = sidecar(&self.path, ".pending");
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(tip.as_bytes());
        bytes.extend_from_slice(domain_hash(HEAD_DOMAIN, &bytes).as_bytes());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|_| StorageError::Io)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| StorageError::Io)?;
        drop(file);
        fs::rename(pending, sidecar(&self.path, ".head")).map_err(|_| StorageError::Io)?;
        #[cfg(test)]
        if self.fault == Some(Fault::HeadRenamed) {
            self.poisoned = true;
            return Err(StorageError::DurabilityUnknown);
        }
        if sync_parent(&self.path).is_err() {
            self.poisoned = true;
            return Err(StorageError::DurabilityUnknown);
        }
        Ok(())
    }

    fn append(&mut self, payload: &[u8]) -> Result<Location, StorageError> {
        self.ready()?;
        self.prepare_pending()?;
        if self.file.metadata().map_err(|_| StorageError::Io)?.len() != self.end {
            self.poisoned = true;
            return Err(StorageError::Corrupt);
        }
        if read_head(&self.path)? != (self.end, self.tip) {
            self.poisoned = true;
            return Err(StorageError::Corrupt);
        }
        let end = self
            .end
            .checked_add(FRAME_OVERHEAD + payload.len() as u64)
            .ok_or(StorageError::LimitExceeded)?;
        let digest = frame_hash(self.tip, payload);
        let location = Location {
            offset: self.end,
            end,
            previous: self.tip,
            hash: digest,
        };
        let result = (|| {
            self.file
                .seek(SeekFrom::Start(self.end))
                .and_then(|_| self.file.write_all(&(payload.len() as u64).to_le_bytes()))
                .and_then(|()| self.file.write_all(payload))
                .and_then(|()| self.file.write_all(digest.as_bytes()))
                .and_then(|()| self.file.sync_all())
                .map_err(|_| StorageError::Io)?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::AppendSynced | Fault::Rollback)) {
                return Err(StorageError::Io);
            }
            self.publish_head(end, digest)
        })();
        if let Err(error) = result {
            #[cfg(test)]
            if self.fault == Some(Fault::Rollback) {
                self.poisoned = true;
            }
            // Never roll back after the new head may have been published.
            if self.poisoned
                || self
                    .file
                    .set_len(self.end)
                    .and_then(|()| self.file.sync_all())
                    .is_err()
            {
                self.poisoned = true;
                return Err(StorageError::DurabilityUnknown);
            }
            return Err(error);
        }
        self.end = end;
        self.tip = digest;
        Ok(location)
    }
}

impl NodeStorage for AppendOnlyStorage {
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError> {
        self.ready()?;
        Ok(self.checkpoint)
    }
    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError> {
        self.ready()?;
        let payload = log_record::batch(batch)?;
        let (cp, state) = prepare_batch(batch, self.checkpoint, &self.state)?;
        let location = self.append(&payload)?;
        self.history
            .record(self.checkpoint, cp, &self.state, &batch.state_diffs);
        self.index.insert(cp.height, location);
        self.transactions.insert(&batch.block);
        self.checkpoint = Some(cp);
        self.state = state;
        Ok(cp)
    }
    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError> {
        self.ready()?;
        if self.checkpoint == Some(checkpoint) {
            return snapshot::export(checkpoint, &self.state, sink);
        }
        // Historical snapshots are reconstructed on demand, never retained per block in RAM.
        let mut file = File::open(&self.path).map_err(|_| StorageError::Io)?;
        let mut end = HEADER_BYTES;
        let mut tip = domain_hash(DOMAIN, MAGIC);
        let mut cp = None;
        let mut state = InMemoryState::new();
        while end < self.end {
            let (record, location) = read_record(&mut file, end, self.end, tip)?;
            let (next, next_state) = apply(&record, cp, &state)?;
            cp = Some(next);
            state = next_state;
            end = location.end;
            tip = location.hash;
            if next.height == checkpoint.height {
                if next != checkpoint {
                    return Err(StorageError::VerificationFailed);
                }
                return snapshot::export(checkpoint, &state, sink);
            }
        }
        Err(StorageError::VerificationFailed)
    }
    fn import_snapshot(
        &mut self,
        expected: Checkpoint,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError> {
        self.ready()?;
        if self.checkpoint.is_some() {
            return Err(StorageError::Unsupported);
        }
        let state = snapshot::import(expected, source)?;
        self.install_anchor(expected, state)
    }
    fn prune(&mut self, before_height: u64) -> Result<(), StorageError> {
        self.ready()?;
        if before_height == 0 || self.checkpoint.is_none() {
            Ok(())
        } else {
            Err(StorageError::Unsupported)
        }
    }
}

fn prepare_batch(
    batch: &CommitBatch,
    current: Option<Checkpoint>,
    state: &InMemoryState,
) -> Result<(Checkpoint, InMemoryState), StorageError> {
    let (height, parent) = match current {
        Some(cp) => (
            cp.height.checked_add(1).ok_or(StorageError::InvalidOrder)?,
            cp.block,
        ),
        None => (0, Hash256::ZERO),
    };
    if batch.block.header.height != height || batch.block.header.parent != parent {
        return Err(StorageError::InvalidOrder);
    }
    let next = state
        .prepare(state.root(), &batch.state_diffs)
        .map_err(map_state_error)?;
    if next.root() != batch.block.header.state_root {
        return Err(StorageError::VerificationFailed);
    }
    Ok((
        Checkpoint {
            height,
            block: batch.block.header.compute_hash(),
            state_root: next.root(),
        },
        next,
    ))
}

fn apply(
    record: &Record,
    current: Option<Checkpoint>,
    state: &InMemoryState,
) -> Result<(Checkpoint, InMemoryState), StorageError> {
    match record {
        Record::Anchor(cp, state) if current.is_none() => Ok((*cp, state.clone())),
        Record::Batch(batch) => prepare_batch(batch, current, state),
        Record::Anchor(..) => Err(StorageError::Corrupt),
    }
}

fn frame_hash(previous: Hash256, payload: &[u8]) -> Hash256 {
    let mut input = Vec::with_capacity(40 + payload.len());
    input.extend_from_slice(previous.as_bytes());
    input.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    input.extend_from_slice(payload);
    domain_hash(DOMAIN, &input)
}

fn read_record(
    file: &mut File,
    offset: u64,
    end: u64,
    previous: Hash256,
) -> Result<(Record, Location), StorageError> {
    if end.saturating_sub(offset) < FRAME_OVERHEAD {
        return Err(StorageError::Corrupt);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| StorageError::Io)?;
    let mut size = [0; 8];
    file.read_exact(&mut size)
        .map_err(|_| StorageError::Corrupt)?;
    let size = u64::from_le_bytes(size);
    if size > MAX_RECORD_BYTES as u64 || size > end - offset - FRAME_OVERHEAD {
        return Err(StorageError::Corrupt);
    }
    let mut payload = vec![0; usize::try_from(size).map_err(|_| StorageError::LimitExceeded)?];
    let mut hash = [0; 32];
    file.read_exact(&mut payload)
        .and_then(|()| file.read_exact(&mut hash))
        .map_err(|_| StorageError::Corrupt)?;
    if frame_hash(previous, &payload).0 != hash {
        return Err(StorageError::Corrupt);
    }
    Ok((
        log_record::decode(&payload)?,
        Location {
            offset,
            end: offset + size + FRAME_OVERHEAD,
            previous,
            hash: Hash256(hash),
        },
    ))
}

fn read_head(path: &Path) -> Result<(u64, Hash256), StorageError> {
    let mut bytes = Vec::new();
    File::open(sidecar(path, ".head"))
        .map_err(|_| StorageError::Corrupt)?
        .take(HEAD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StorageError::Io)?;
    if bytes.len() != HEAD_BYTES
        || &bytes[..8] != MAGIC
        || domain_hash(HEAD_DOMAIN, &bytes[..48]).as_bytes() != &bytes[48..]
    {
        return Err(StorageError::Corrupt);
    }
    Ok((
        u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| StorageError::Corrupt)?),
        Hash256(
            bytes[16..48]
                .try_into()
                .map_err(|_| StorageError::Corrupt)?,
        ),
    ))
}

fn canonical_path(path: &Path) -> Result<PathBuf, StorageError> {
    let name = path.file_name().ok_or(StorageError::Io)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)
        .map_err(|_| StorageError::Io)?
        .join(name))
}
fn reject_symlink(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => Err(StorageError::Io),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StorageError::Io),
    }
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn log_checksums_match_independent_python_blake2s_vectors() {
        let tip = domain_hash(DOMAIN, MAGIC);
        assert_eq!(
            tip.to_string(),
            "c683eefe66aab001a3e23eb4aaaba1d1ee70b24cc249b12063193bb358e1ce26"
        );
        let mut head = MAGIC.to_vec();
        head.extend_from_slice(&HEADER_BYTES.to_le_bytes());
        head.extend_from_slice(tip.as_bytes());
        assert_eq!(
            domain_hash(HEAD_DOMAIN, &head).to_string(),
            "45d91bab50ab8e03cadd44d5567c5cdf4bf78d200484fe66515ae5750a9efaee"
        );
        assert_eq!(
            frame_hash(tip, &[1, 2, 3]).to_string(),
            "e8f98622817897ec839ad89ea94291c537f86b18117d6ed0cba0e314d2efb217"
        );
    }

    #[test]
    fn uncertain_publication_and_rollback_require_reopen_without_losing_committed_head() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for fault in [Fault::AppendSynced, Fault::HeadRenamed, Fault::Rollback] {
            let directory = std::env::temp_dir().join(format!(
                "astrolune-log-fault-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("chain.bin");
            let mut log = AppendOnlyStorage::open(&path).unwrap();
            let cp = log
                .initialize_genesis(Hash256([1; 32]), InMemoryState::new())
                .unwrap();
            let batch = CommitBatch {
                effects: None,
                block: Block {
                    header: types::BlockHeader {
                        height: 1,
                        parent: cp.block,
                        state_root: cp.state_root,
                        transactions_root: Hash256::ZERO,
                        receipts_root: Hash256::ZERO,
                        committee_root: Hash256::ZERO,
                        capacity: types::Resources::ZERO,
                    },
                    transactions: vec![],
                },
                finality_certificate: vec![1],
                state_diffs: vec![],
            };
            log.fault = Some(fault);
            let error = if fault == Fault::AppendSynced {
                StorageError::Io
            } else {
                StorageError::DurabilityUnknown
            };
            assert_eq!(log.commit(&batch), Err(error));
            assert_eq!(log.checkpoint(), Some(&cp));
            if fault == Fault::AppendSynced {
                assert!(log.read_state_at(1).unwrap().is_none());
                assert_eq!(log.read_state_at(0).unwrap().unwrap().0, cp);
            } else {
                assert!(matches!(
                    log.read_state_at(0),
                    Err(StorageError::DurabilityUnknown)
                ));
            }
            if fault != Fault::AppendSynced {
                assert_eq!(log.commit(&batch), Err(StorageError::DurabilityUnknown));
                assert_eq!(log.recover(), Err(StorageError::DurabilityUnknown));
                assert_eq!(log.read_finalized(1), Err(StorageError::DurabilityUnknown));
            }
            drop(log);
            let mut recovered = AppendOnlyStorage::open(&path).unwrap();
            if fault == Fault::HeadRenamed {
                assert_eq!(recovered.checkpoint().unwrap().height, 1);
                assert_eq!(recovered.read_state_at(0).unwrap().unwrap().0, cp);
                assert_eq!(recovered.read_finalized(1).unwrap().unwrap().0, batch.block);
            } else {
                assert_eq!(recovered.checkpoint(), Some(&cp));
                recovered.commit(&batch).unwrap();
            }
            drop(recovered);
            fs::remove_dir_all(&directory).unwrap(); // Unique fixture owned by this test.
        }
    }
}
