// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Append-only bodies and state deltas, published through a small durable head file.

use crate::{
    Checkpoint, CommitBatch, NodeStorage, SnapshotSink, SnapshotSource, StorageError,
    log_record::{self, MAX_RECORD_BYTES, Record},
    map_state_error,
    retention::{
        MAX_COMPACTION_BYTES, MIN_RETAINED_BLOCKS, RETENTION_RECORD_BYTES, RetentionPolicy,
        RetentionRecord, RetentionState,
    },
    snapshot,
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
/// in-memory state engine. A configured [`RetentionPolicy`] may replace the log
/// with its own authenticated anchor plus a bounded suffix; the replacement is
/// published atomically and never resets history to genesis. Compaction supplies
/// no trust: it neither authenticates finality nor accepts a shortened history
/// written by any other process.
#[derive(Debug)]
pub struct AppendOnlyStorage {
    path: PathBuf,
    file: File,
    _lock: File,
    end: u64,
    tip: Hash256,
    state: InMemoryState,
    checkpoint: Option<Checkpoint>,
    anchor: Option<Checkpoint>,
    index: BTreeMap<u64, Location>,
    transactions: crate::receipts::RecentTransactions,
    history: crate::history::StateHistory,
    policy: RetentionPolicy,
    retention: Option<RetentionRecord>,
    retention_error: Option<StorageError>,
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
    CompactionWritten,
    CompactionCommitted,
}

impl AppendOnlyStorage {
    /// Opens a log, verifies committed bytes, and discards only an unpublished tail.
    /// The parent must exist; `.lock`, `.head`, `.pending`, `.compact`, `.swap`,
    /// `.retain` and `.retain.pending` are reserved sidecars.
    /// Missing/invalid heads for existing logs fail closed, never reset to genesis.
    /// An interrupted compaction is completed or discarded before any replay.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = canonical_path(path.as_ref())?;
        for candidate in [
            &path,
            &sidecar(&path, ".lock"),
            &sidecar(&path, ".head"),
            &sidecar(&path, ".compact"),
            &sidecar(&path, ".swap"),
            &sidecar(&path, ".retain"),
            &sidecar(&path, ".retain.pending"),
        ] {
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
        // Resolve an interrupted compaction before the header or head is trusted.
        finish_compaction(&path)?;
        let retention = read_retention(&path)?;
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
            anchor: None,
            index: BTreeMap::new(),
            transactions: crate::receipts::RecentTransactions::default(),
            history: crate::history::StateHistory::default(),
            policy: RetentionPolicy::disabled(),
            retention,
            retention_error: None,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        if create {
            log.prepare_pending()?;
            log.publish_head(HEADER_BYTES, initial_tip)?;
        } else {
            log.replay_published()?;
        }
        Ok(log)
    }

    /// Streams and rechecks exactly the published prefix, then trims any tail.
    fn replay_published(&mut self) -> Result<(), StorageError> {
        let (end, tip) = read_head(&self.path)?;
        if end < HEADER_BYTES || self.file.metadata().map_err(|_| StorageError::Io)?.len() < end {
            return Err(StorageError::Corrupt);
        }
        while self.end < end {
            let (record, location) = read_record(&mut self.file, self.end, end, self.tip)?;
            self.index_record(&record, location);
            let (cp, state) = self.replay_record(&record)?;
            self.state = state;
            if self.checkpoint.is_none() {
                self.anchor = Some(cp);
            }
            self.checkpoint = Some(cp);
            self.end = location.end;
            self.tip = location.hash;
        }
        if self.end != end || self.tip != tip {
            return Err(StorageError::Corrupt);
        }
        self.check_retention()?;
        // Verify the entire published prefix BEFORE touching any tail.
        self.file
            .set_len(end)
            .and_then(|()| self.file.sync_all())
            .map_err(|_| StorageError::Io)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(sidecar(&self.path, ".head"))
            .and_then(|head| head.sync_all())
            .and_then(|()| sync_parent(&self.path))
            .map_err(|_| StorageError::Io)
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

    /// Height of the oldest retained checkpoint; bodies start one height above it.
    /// Zero means complete history from genesis. Absence means an empty store.
    /// A floor states local availability, never that a height was not finalized.
    #[must_use]
    pub fn retained_floor(&self) -> Option<u64> {
        self.anchor.map(|cp| cp.height)
    }

    /// Lowest height whose exact state the bounded reverse index can still rebuild.
    /// Equals the lowest height for which `read_state_at` returns a value.
    #[must_use]
    pub fn history_floor(&self) -> Option<u64> {
        self.checkpoint.map(|cp| self.history.floor(cp.height))
    }

    /// Installs the automated retention policy evaluated after every commit.
    /// A disabled policy, the default, retains every finalized block.
    pub fn set_retention_policy(&mut self, policy: RetentionPolicy) {
        self.policy = policy;
    }

    /// Current policy, floors and last automatic evaluation outcome.
    #[must_use]
    pub fn retention_state(&self) -> RetentionState {
        RetentionState {
            policy: self.policy,
            retained_floor: self.retained_floor(),
            history_floor: self.history_floor(),
            self_compacted: self.local_retention_anchor().is_some(),
            compactions: self.retention.map_or(0, |record| record.compactions),
            last_error: self.retention_error,
        }
    }

    /// The anchor this writer durably recorded compacting to, if any.
    ///
    /// `Some` means the shortening was performed in place by a writer holding this
    /// directory's exclusive lock, so the node's own continuity is the trust root
    /// on restart. `None` for complete history and for any shortened directory
    /// without that record, which still requires an independently held pin.
    #[must_use]
    pub fn local_retention_anchor(&self) -> Option<Checkpoint> {
        let anchor = self.anchor?;
        let record = self.retention?;
        (anchor.height > 0 && record.floor >= anchor.height).then_some(anchor)
    }

    /// Rejects a durable record that disagrees with the log it describes.
    /// A record below the log anchor, or naming a different anchor at the same
    /// height, is evidence of an inconsistent directory and fails closed.
    fn check_retention(&self) -> Result<(), StorageError> {
        let Some(record) = self.retention else {
            return Ok(());
        };
        let Some(anchor) = self.anchor else {
            return Err(StorageError::Corrupt);
        };
        if record.floor < anchor.height {
            return Err(StorageError::Corrupt);
        }
        if record.floor == anchor.height
            && (record.block != anchor.block || record.state_root != anchor.state_root)
        {
            return Err(StorageError::Corrupt);
        }
        Ok(())
    }

    /// Evaluates the configured policy once after a published commit.
    /// Work is bounded by the policy; a failure never unpublishes the commit.
    fn evaluate_retention(&mut self) {
        if !self.policy.is_enabled() {
            return;
        }
        let Some((head, floor)) = self.checkpoint.zip(self.retained_floor()) else {
            return;
        };
        let Some(target) = self.policy.target_floor(floor, head.height) else {
            return;
        };
        self.retention_error = self
            .compact(target, self.policy.max_compaction_bytes())
            .err();
    }

    /// Replaces the log with an anchor at `floor` plus the bodies above it.
    ///
    /// The replacement is built in `.compact`, recorded in `.retain`, committed by
    /// creating `.swap`, and only then renamed over the published files. A crash
    /// at any point leaves either the previous log or the replacement completely
    /// recoverable. Reclaiming bytes requires no new trust: every retained record
    /// was already authenticated and published by this writer.
    fn compact(&mut self, floor: u64, budget: u64) -> Result<(), StorageError> {
        self.ready()?;
        let head = self.checkpoint.ok_or(StorageError::InvalidOrder)?;
        let anchor = self.anchor.ok_or(StorageError::Corrupt)?;
        if floor > head.height {
            return Err(StorageError::InvalidOrder);
        }
        if floor <= anchor.height {
            return Ok(());
        }
        if head.height - floor < MIN_RETAINED_BLOCKS {
            return Err(StorageError::LimitExceeded);
        }
        let (cp, state) = self
            .history
            .read(floor, self.checkpoint, &self.state)?
            .ok_or(StorageError::LimitExceeded)?;
        let compact = sidecar(&self.path, ".compact");
        let swap = sidecar(&self.path, ".swap");
        let retain = sidecar(&self.path, ".retain");
        let retain_pending = sidecar(&self.path, ".retain.pending");
        // `open` always resolves a swap marker, so one here means a foreign writer.
        if fs::symlink_metadata(&swap).is_ok() {
            return Err(StorageError::Corrupt);
        }
        remove_absent_ok(&compact)?;
        remove_absent_ok(&retain_pending)?;
        let record = RetentionRecord {
            floor,
            compactions: self
                .retention
                .map_or(0, |r| r.compactions)
                .saturating_add(1),
            block: cp.block,
            state_root: cp.state_root,
        };
        let result = (|| {
            let (file, end, tip, index) = self.write_replacement(&compact, cp, &state, budget)?;
            write_new_synced(&retain_pending, &record.to_bytes())?;
            sync_parent(&self.path).map_err(|_| StorageError::Io)?;
            #[cfg(test)]
            if self.fault == Some(Fault::CompactionWritten) {
                return Err(StorageError::Io);
            }
            write_new_synced(&swap, &head_bytes(end, tip))?;
            sync_parent(&self.path).map_err(|_| StorageError::Io)?;
            Ok((file, end, tip, index))
        })();
        let (file, end, tip, index) = match result {
            Ok(value) => value,
            Err(error) => {
                // The commit marker is absent, so the published log is still authoritative.
                remove_absent_ok(&compact)?;
                remove_absent_ok(&retain_pending)?;
                return Err(error);
            }
        };
        // Past this point the replacement is committed; `open` finishes any gap.
        drop(std::mem::replace(&mut self.file, file));
        #[cfg(test)]
        if self.fault == Some(Fault::CompactionCommitted) {
            self.poisoned = true;
            return Err(StorageError::DurabilityUnknown);
        }
        if fs::rename(&compact, &self.path)
            .and_then(|()| fs::rename(&retain_pending, &retain))
            .and_then(|()| fs::rename(&swap, sidecar(&self.path, ".head")))
            .and_then(|()| sync_parent(&self.path))
            .is_err()
        {
            self.poisoned = true;
            return Err(StorageError::DurabilityUnknown);
        }
        self.end = end;
        self.tip = tip;
        self.index = index;
        self.anchor = Some(cp);
        self.retention = Some(record);
        self.history.truncate_below(floor);
        self.transactions.prune(floor + 1);
        Ok(())
    }

    /// Streams the anchor and the retained bodies into a new unpublished file.
    /// Every copied payload is rechecked against its published frame digest.
    fn write_replacement(
        &self,
        compact: &Path,
        cp: Checkpoint,
        state: &InMemoryState,
        budget: u64,
    ) -> Result<(File, u64, Hash256, BTreeMap<u64, Location>), StorageError> {
        let head = self.checkpoint.ok_or(StorageError::InvalidOrder)?;
        let initial = domain_hash(DOMAIN, MAGIC);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(compact)
            .map_err(|_| StorageError::Io)?;
        file.write_all(MAGIC)
            .and_then(|()| file.write_all(initial.as_bytes()))
            .map_err(|_| StorageError::Io)?;
        let mut end = HEADER_BYTES;
        let mut tip = initial;
        let mut index = BTreeMap::new();
        append_frame(
            &mut file,
            &mut end,
            &mut tip,
            &log_record::anchor(cp, state)?,
            budget,
        )?;
        let mut source = File::open(&self.path).map_err(|_| StorageError::Io)?;
        for height in cp.height + 1..=head.height {
            let location = *self.index.get(&height).ok_or(StorageError::Corrupt)?;
            let (payload, actual) = read_frame(
                &mut source,
                location.offset,
                location.end,
                location.previous,
            )?;
            if actual.hash != location.hash || actual.end != location.end {
                return Err(StorageError::Corrupt);
            }
            let offset = end;
            let previous = tip;
            append_frame(&mut file, &mut end, &mut tip, &payload, budget)?;
            index.insert(
                height,
                Location {
                    offset,
                    end,
                    previous,
                    hash: tip,
                },
            );
        }
        file.sync_all().map_err(|_| StorageError::Io)?;
        sync_parent(&self.path).map_err(|_| StorageError::Io)?;
        Ok((file, end, tip, index))
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
        self.anchor = Some(cp);
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
        let bytes = head_bytes(end, tip);
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
        if self.checkpoint.is_none() {
            self.anchor = Some(cp);
        }
        self.checkpoint = Some(cp);
        self.state = state;
        self.evaluate_retention();
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
        if self.checkpoint.is_none() {
            return Ok(());
        }
        self.compact(before_height, MAX_COMPACTION_BYTES)
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
    let (payload, location) = read_frame(file, offset, end, previous)?;
    Ok((log_record::decode(&payload)?, location))
}

/// Reads and rechecks one framed payload without decoding its record.
fn read_frame(
    file: &mut File,
    offset: u64,
    end: u64,
    previous: Hash256,
) -> Result<(Vec<u8>, Location), StorageError> {
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
        payload,
        Location {
            offset,
            end: offset + size + FRAME_OVERHEAD,
            previous,
            hash: Hash256(hash),
        },
    ))
}

/// Appends one framed payload to an unpublished replacement within its budget.
fn append_frame(
    file: &mut File,
    end: &mut u64,
    tip: &mut Hash256,
    payload: &[u8],
    budget: u64,
) -> Result<(), StorageError> {
    let frame = FRAME_OVERHEAD + payload.len() as u64;
    let next = end.checked_add(frame).ok_or(StorageError::LimitExceeded)?;
    if next.saturating_sub(HEADER_BYTES) > budget {
        return Err(StorageError::LimitExceeded);
    }
    let digest = frame_hash(*tip, payload);
    file.write_all(&(payload.len() as u64).to_le_bytes())
        .and_then(|()| file.write_all(payload))
        .and_then(|()| file.write_all(digest.as_bytes()))
        .map_err(|_| StorageError::Io)?;
    *end = next;
    *tip = digest;
    Ok(())
}

/// Verifies that a candidate file is exactly the published prefix named by a head.
fn verify_frames(path: &Path, end: u64, tip: Hash256) -> Result<(), StorageError> {
    if end < HEADER_BYTES {
        return Err(StorageError::Corrupt);
    }
    let mut file = File::open(path).map_err(|_| StorageError::Corrupt)?;
    if file.metadata().map_err(|_| StorageError::Io)?.len() < end {
        return Err(StorageError::Corrupt);
    }
    let initial = domain_hash(DOMAIN, MAGIC);
    let mut header = [0; HEADER_SIZE];
    file.read_exact(&mut header)
        .map_err(|_| StorageError::Corrupt)?;
    if &header[..8] != MAGIC || header[8..] != initial.0 {
        return Err(StorageError::Corrupt);
    }
    let mut offset = HEADER_BYTES;
    let mut previous = initial;
    while offset < end {
        let (_, location) = read_frame(&mut file, offset, end, previous)?;
        offset = location.end;
        previous = location.hash;
    }
    if offset != end || previous != tip {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}

/// Completes or discards an interrupted in-place compaction.
///
/// A readable `.swap` marker is the commit point: the replacement is published
/// even if the rename did not finish. Without a readable marker the previous log
/// stays authoritative and the unpublished replacement bytes are discarded.
fn finish_compaction(path: &Path) -> Result<(), StorageError> {
    let swap = sidecar(path, ".swap");
    let compact = sidecar(path, ".compact");
    let staged_record = sidecar(path, ".retain.pending");
    let Ok((end, tip)) = read_head_at(&swap) else {
        remove_absent_ok(&compact)?;
        remove_absent_ok(&swap)?;
        return remove_absent_ok(&staged_record);
    };
    let staged = fs::symlink_metadata(&compact).is_ok();
    verify_frames(if staged { &compact } else { path }, end, tip)?;
    if staged {
        fs::rename(&compact, path).map_err(|_| StorageError::Io)?;
    }
    if fs::symlink_metadata(&staged_record).is_ok() {
        fs::rename(&staged_record, sidecar(path, ".retain")).map_err(|_| StorageError::Io)?;
    }
    fs::rename(&swap, sidecar(path, ".head")).map_err(|_| StorageError::Io)?;
    sync_parent(path).map_err(|_| StorageError::Io)
}

/// Reads the durable local compaction record, treating a damaged one as absent.
fn read_retention(path: &Path) -> Result<Option<RetentionRecord>, StorageError> {
    let mut bytes = Vec::new();
    match File::open(sidecar(path, ".retain")) {
        Ok(file) => file
            .take(RETENTION_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::Io)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StorageError::Io),
    };
    Ok(RetentionRecord::from_bytes(&bytes).ok())
}

fn head_bytes(end: u64, tip: Hash256) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&end.to_le_bytes());
    bytes.extend_from_slice(tip.as_bytes());
    bytes.extend_from_slice(domain_hash(HEAD_DOMAIN, &bytes).as_bytes());
    bytes
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| StorageError::Io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| StorageError::Io)
}

fn remove_absent_ok(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StorageError::Io),
    }
}

fn read_head(path: &Path) -> Result<(u64, Hash256), StorageError> {
    read_head_at(&sidecar(path, ".head"))
}

fn read_head_at(path: &Path) -> Result<(u64, Hash256), StorageError> {
    let mut bytes = Vec::new();
    File::open(path)
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

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "astrolune-log-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique fixture directory");
        path
    }

    fn empty_batch(parent: Checkpoint) -> CommitBatch {
        CommitBatch {
            effects: None,
            block: Block {
                header: types::BlockHeader {
                    height: parent.height + 1,
                    parent: parent.block,
                    state_root: parent.state_root,
                    transactions_root: Hash256::ZERO,
                    receipts_root: Hash256::ZERO,
                    committee_root: Hash256::ZERO,
                    capacity: types::Resources::ZERO,
                },
                transactions: vec![],
            },
            finality_certificate: vec![1],
            state_diffs: vec![],
        }
    }

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
        for fault in [Fault::AppendSynced, Fault::HeadRenamed, Fault::Rollback] {
            let directory = directory("fault");
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

    #[test]
    fn an_interrupted_compaction_recovers_exactly_one_complete_log() {
        for (fault, torn) in [
            (Fault::CompactionWritten, false),
            (Fault::CompactionCommitted, false),
            (Fault::CompactionCommitted, true),
        ] {
            let directory = directory("compact");
            let path = directory.join("chain.bin");
            let mut log = AppendOnlyStorage::open(&path).unwrap();
            let mut cp = log
                .initialize_genesis(Hash256([2; 32]), InMemoryState::new())
                .unwrap();
            for _ in 0..20 {
                cp = log.commit(&empty_batch(cp)).unwrap();
            }
            let floor = cp.height - MIN_RETAINED_BLOCKS;
            let before = fs::read(&path).unwrap();
            log.fault = Some(fault);
            let expected = if fault == Fault::CompactionWritten {
                StorageError::Io
            } else {
                StorageError::DurabilityUnknown
            };
            assert_eq!(log.prune(floor), Err(expected), "fault {fault:?}");
            // A failure before the marker leaves the published log authoritative.
            if fault == Fault::CompactionWritten {
                assert_eq!(log.retained_floor(), Some(0));
                assert_eq!(fs::read(&path).unwrap(), before);
                assert!(!sidecar(&path, ".compact").exists());
                assert!(!sidecar(&path, ".swap").exists());
            } else {
                assert_eq!(log.recover(), Err(StorageError::DurabilityUnknown));
            }
            drop(log);
            if torn {
                // A torn marker is unreadable, so the commit point was never crossed.
                let marker = fs::read(sidecar(&path, ".swap")).unwrap();
                fs::write(sidecar(&path, ".swap"), &marker[..40]).unwrap();
            }
            let mut recovered = AppendOnlyStorage::open(&path).unwrap();
            assert_eq!(recovered.recover().unwrap(), Some(cp), "fault {fault:?}");
            assert!(!sidecar(&path, ".swap").exists());
            assert!(!sidecar(&path, ".compact").exists());
            assert!(!sidecar(&path, ".retain.pending").exists());
            if fault == Fault::CompactionCommitted && !torn {
                assert_eq!(recovered.retained_floor(), Some(floor));
                assert_eq!(
                    recovered.local_retention_anchor().map(|cp| cp.height),
                    Some(floor)
                );
                assert_eq!(recovered.read_finalized(floor).unwrap(), None);
                assert!(recovered.read_finalized(floor + 1).unwrap().is_some());
            } else {
                assert_eq!(recovered.retained_floor(), Some(0));
                assert_eq!(recovered.local_retention_anchor(), None);
                assert_eq!(fs::read(&path).unwrap(), before);
            }
            recovered.commit(&empty_batch(cp)).unwrap();
            drop(recovered);
            fs::remove_dir_all(&directory).unwrap(); // Unique fixture owned by this test.
        }
    }

    #[test]
    fn a_compaction_exceeding_its_byte_budget_refuses_without_touching_the_log() {
        let directory = directory("budget");
        let path = directory.join("chain.bin");
        let mut log = AppendOnlyStorage::open(&path).unwrap();
        let mut cp = log
            .initialize_genesis(Hash256([3; 32]), InMemoryState::new())
            .unwrap();
        for _ in 0..20 {
            cp = log.commit(&empty_batch(cp)).unwrap();
        }
        let before = fs::read(&path).unwrap();
        let floor = cp.height - MIN_RETAINED_BLOCKS;
        for budget in [0, 1, FRAME_OVERHEAD] {
            assert_eq!(
                log.compact(floor, budget),
                Err(StorageError::LimitExceeded),
                "accepted a compaction within {budget} bytes"
            );
            assert_eq!(log.retained_floor(), Some(0));
            assert_eq!(fs::read(&path).unwrap(), before);
            assert!(!sidecar(&path, ".compact").exists());
        }
        assert_eq!(log.compact(floor, MAX_COMPACTION_BYTES), Ok(()));
        assert_eq!(log.retained_floor(), Some(floor));
        drop(log);
        fs::remove_dir_all(&directory).unwrap(); // Unique fixture owned by this test.
    }
}
