// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Single-writer reference persistence using verified snapshots and atomic replacement.
//!
//! A synchronized staging file is renamed only after the complete next state is ready.
//! Recovery ignores incomplete staging files and validates the published snapshot. On
//! Unix the containing directory is synchronized too. Windows directory power-loss
//! durability remains filesystem-dependent; this is not a production database engine.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use types::{Hash256, StateKey};

use crate::{
    InMemoryState, MAX_SNAPSHOT_BYTES, StateAbsenceProof, StateDatabase, StateDiff, StateError,
    StateProof, StateSnapshot,
};

/// File-backed state with an OS lock held until the database is dropped.
#[derive(Debug)]
pub struct FileBackedState {
    state: InMemoryState,
    path: PathBuf,
    // The sidecar's inode must remain stable; do not unlink it when unlocking.
    lock: File,
    recovery_required: bool,
}

impl Drop for FileBackedState {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

impl FileBackedState {
    /// Opens a verified snapshot or initializes an empty database.
    ///
    /// Existing unversioned files are rejected; they require explicit migration.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let requested = path.as_ref();
        let file_name = requested.file_name().ok_or(StateError::Io)?;
        let parent = requested
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = fs::canonicalize(parent)
            .map_err(|_| StateError::Io)?
            .join(file_name);
        // Reject aliases to the data file so a symlink cannot bypass its writer lock.
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(StateError::Io);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(&path, ".lock"))
            .map_err(|_| StateError::Io)?;
        lock.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => StateError::Locked,
            TryLockError::Error(_) => StateError::Io,
        })?;
        let (state, create) = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_SNAPSHOT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| StateError::Io)?;
                (InMemoryState::decode_snapshot(&bytes)?, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (InMemoryState::new(), true)
            }
            Err(_) => return Err(StateError::Io),
        };
        let mut database = Self {
            state,
            path,
            lock,
            recovery_required: false,
        };
        if create {
            database.publish(database.state.clone())?;
        }
        Ok(database)
    }

    /// Returns the currently published root.
    #[must_use]
    pub fn root(&self) -> Hash256 {
        self.state.root()
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Returns whether the state contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// Borrows an entry in the currently published state.
    #[must_use]
    pub fn get(&self, key: &StateKey) -> Option<&[u8]> {
        self.state.get(key)
    }

    /// Verifies a proposed root before writing or publishing any changes.
    pub fn commit_verified(
        &mut self,
        parent: Hash256,
        diffs: &[StateDiff],
        expected: Hash256,
    ) -> Result<Hash256, StateError> {
        let next = self.state.prepare(parent, diffs)?;
        if next.root() != expected {
            return Err(StateError::RootMismatch);
        }
        self.publish(next)?;
        Ok(self.root())
    }

    fn publish(&mut self, next: InMemoryState) -> Result<(), StateError> {
        if self.recovery_required {
            return Err(StateError::DurabilityUnknown);
        }
        let temporary = sidecar(&self.path, ".pending");
        // Only the lock owner may remove an interrupted write from a previous process.
        match fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(StateError::Io),
        }
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| StateError::Io)?;
            file.write_all(&next.export_snapshot())
                .map_err(|_| StateError::Io)?;
            file.sync_all().map_err(|_| StateError::Io)?;
            drop(file);
            fs::rename(&temporary, &self.path).map_err(|_| StateError::Io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return result;
        }
        // Rename is the publication point. In-memory readers must now see that version.
        self.state = next;
        if sync_parent(&self.path).is_err() {
            self.recovery_required = true;
            return Err(StateError::DurabilityUnknown);
        }
        Ok(())
    }
}

impl StateSnapshot for FileBackedState {
    fn root(&self) -> Hash256 {
        self.root()
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        StateSnapshot::get(&self.state, key)
    }

    fn prove(&self, key: &StateKey) -> Result<Option<StateProof>, StateError> {
        self.state.prove(key)
    }

    fn prove_absence(&self, key: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
        self.state.prove_absence(key)
    }
}

impl StateDatabase for FileBackedState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        self.state.snapshot()
    }

    fn prefetch(&self, _keys: &[StateKey]) -> Result<(), StateError> {
        Ok(())
    }

    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
        self.publish(self.state.prepare(parent, diffs)?)?;
        Ok(self.root())
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::StateDiff;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("astrolune_state_test_{}", std::process::id()));
        fs::create_dir_all(&dir).ok();
        dir.join(name)
    }

    fn cleanup(path: &Path) {
        fs::remove_file(path).ok();
        fs::remove_file(sidecar(path, ".pending")).ok();
    }

    fn key(b: u8) -> StateKey {
        StateKey(vec![b])
    }

    #[test]
    fn open_creates_new_file() {
        let path = temp_path("test_new.dat");
        cleanup(&path);

        let state = FileBackedState::open(&path).unwrap();
        assert!(state.is_empty());
        assert_eq!(state.root(), crate::commitment::empty_root());
        assert!(path.exists());

        cleanup(&path);
    }

    #[test]
    fn open_loads_existing_file() {
        let path = temp_path("test_load.dat");
        cleanup(&path);

        {
            let mut state = FileBackedState::open(&path).unwrap();
            let mut diff = StateDiff::new();
            diff.put(key(1), vec![10, 20]);
            state.commit(state.root(), &[diff]).unwrap();
        }

        let state = FileBackedState::open(&path).unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.get(&key(1)), Some(&[10, 20][..]));

        cleanup(&path);
    }

    #[test]
    fn commit_persists_to_disk() {
        let path = temp_path("test_persist.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        diff.put(key(2), vec![20]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        // Reopening requires releasing the exclusive writer lock.
        drop(state);
        let state2 = FileBackedState::open(&path).unwrap();
        assert_eq!(state2.root(), root1);
        assert_eq!(state2.len(), 2);
        assert_eq!(state2.get(&key(1)), Some(&[10][..]));
        assert_eq!(state2.get(&key(2)), Some(&[20][..]));

        cleanup(&path);
    }

    #[test]
    fn commit_rejects_stale_parent() {
        let path = temp_path("test_stale.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let bad_root = Hash256([0xFF; 32]);

        let diff = StateDiff::new();
        assert_eq!(
            state.commit(bad_root, &[diff]),
            Err(StateError::StaleSnapshot)
        );

        cleanup(&path);
    }

    #[test]
    fn snapshot_isolation() {
        let path = temp_path("test_snapshot.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        state.commit(root0, &[diff]).unwrap();

        let snapshot = state.snapshot().unwrap();

        let mut diff2 = StateDiff::new();
        diff2.put(key(2), vec![20]);
        state.commit(state.root(), &[diff2]).unwrap();

        assert_eq!(snapshot.get(&key(1)).unwrap(), Some(vec![10]));
        assert_eq!(snapshot.get(&key(2)).unwrap(), None);

        cleanup(&path);
    }

    #[test]
    fn delete_through_commit() {
        let path = temp_path("test_delete.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        let mut diff2 = StateDiff::new();
        diff2.delete(key(1));
        state.commit(root1, &[diff2]).unwrap();

        assert!(state.is_empty());

        cleanup(&path);
    }

    #[test]
    fn root_deterministic() {
        let path = temp_path("test_deterministic.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        // Reload and commit the same data
        drop(state);
        let mut state2 = FileBackedState::open(&path).unwrap();
        let mut diff2 = StateDiff::new();
        diff2.put(key(1), vec![10]);
        let root2 = state2.commit(state2.root(), &[diff2]).unwrap();

        assert_eq!(root1, root2);

        cleanup(&path);
    }
}
