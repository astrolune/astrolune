// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Persistence failure and process-recovery checks using isolated temporary directories.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use state::{FileBackedState, InMemoryState, StateDatabase, StateDiff, StateError, StateSnapshot};
use types::{Hash256, StateKey};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-recovery-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("state.bin")
    }
    fn pending(&self) -> PathBuf {
        self.0.join("state.bin.pending")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The fixture owns this unique directory; no repository or user data is removed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn update(byte: u8) -> StateDiff {
    let mut diff = StateDiff::new();
    diff.put(StateKey(vec![1]), vec![byte; 128]);
    diff
}

#[test]
fn absence_proofs_survive_restart_and_preserve_old_snapshots() {
    let fixture = Fixture::new();
    let key = StateKey(vec![0]);
    let mut database = FileBackedState::open(fixture.path()).unwrap();
    database.commit(database.root(), &[update(4)]).unwrap();
    let snapshot = database.snapshot().unwrap();
    let proof = database.prove_absence(&key).unwrap().unwrap();
    assert!(proof.verify(database.root(), &key));
    drop(database);

    let mut database = FileBackedState::open(fixture.path()).unwrap();
    assert_eq!(database.prove_absence(&key).unwrap(), Some(proof.clone()));
    let mut insert = StateDiff::new();
    insert.put(key.clone(), vec![9]);
    database.commit(database.root(), &[insert]).unwrap();
    assert!(database.prove_absence(&key).unwrap().is_none());
    assert!(!proof.verify(database.root(), &key));
    assert!(proof.verify(snapshot.root(), &key));
    assert_eq!(snapshot.prove_absence(&key).unwrap(), Some(proof.clone()));
    let mut delete = StateDiff::new();
    delete.delete(key.clone());
    database.commit(database.root(), &[delete]).unwrap();
    drop(database);

    let recovered = FileBackedState::open(fixture.path()).unwrap();
    assert_eq!(recovered.prove_absence(&key).unwrap(), Some(proof));
}

fn child(path: &Path, mode: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_probe", "--nocapture"])
        .env("ASTROLUNE_STATE_TEST_PATH", path)
        .env("ASTROLUNE_STATE_TEST_MODE", mode)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn process_probe() {
    let Some(path) = std::env::var_os("ASTROLUNE_STATE_TEST_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    if std::env::var("ASTROLUNE_STATE_TEST_MODE").unwrap() == "locked" {
        assert_eq!(FileBackedState::open(path).unwrap_err(), StateError::Locked);
        return;
    }
    let mut state = FileBackedState::open(&path).unwrap();
    state.commit(state.root(), &[update(4)]).unwrap();
    let mut pending = path.into_os_string();
    pending.push(".pending");
    fs::write(PathBuf::from(pending), b"interrupted next snapshot").unwrap();
    // Simulate process exit before Rust destructors run; the OS must release the lock.
    std::process::exit(0);
}

#[test]
fn writer_lock_is_exclusive_and_released_on_process_exit() {
    let fixture = Fixture::new();
    let state = FileBackedState::open(fixture.path()).unwrap();
    assert_eq!(
        FileBackedState::open(fixture.path()).unwrap_err(),
        StateError::Locked
    );
    child(&fixture.path(), "locked");
    drop(state);
    child(&fixture.path(), "crash");
    let mut recovered = FileBackedState::open(fixture.path()).unwrap();
    assert_eq!(recovered.get(&StateKey(vec![1])), Some([4; 128].as_slice()));
    recovered.commit(recovered.root(), &[update(5)]).unwrap();
    assert!(!fixture.pending().exists());
}

#[test]
fn failed_disk_write_leaves_memory_and_published_file_unchanged() {
    let fixture = Fixture::new();
    let mut state = FileBackedState::open(fixture.path()).unwrap();
    state.commit(state.root(), &[update(1)]).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let root = state.root();
    let snapshot = state.snapshot().unwrap();
    // A directory at the staging path makes the next write fail on every platform.
    fs::create_dir(fixture.pending()).unwrap();
    assert_eq!(state.commit(root, &[update(2)]), Err(StateError::Io));
    assert_eq!(state.root(), root);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(
        snapshot.get(&StateKey(vec![1])).unwrap(),
        Some(vec![1; 128])
    );
    fs::remove_dir(fixture.pending()).unwrap();
    state.commit(root, &[update(2)]).unwrap();
    drop(state);
    let recovered = FileBackedState::open(fixture.path()).unwrap();
    assert_eq!(recovered.get(&StateKey(vec![1])), Some([2; 128].as_slice()));
}

#[test]
fn failed_rename_keeps_memory_unchanged_and_allows_retry() {
    let fixture = Fixture::new();
    let mut state = FileBackedState::open(fixture.path()).unwrap();
    let root = state.root();
    let saved = fixture.0.join("saved.bin");
    fs::rename(fixture.path(), &saved).unwrap();
    fs::create_dir(fixture.path()).unwrap();
    assert_eq!(state.commit(root, &[update(2)]), Err(StateError::Io));
    assert_eq!(state.root(), root);
    assert!(state.is_empty());
    assert!(!fixture.pending().exists());
    fs::remove_dir(fixture.path()).unwrap();
    fs::rename(saved, fixture.path()).unwrap();
    state.commit(root, &[update(2)]).unwrap();
}

#[test]
fn proposed_root_is_verified_before_any_disk_change() {
    let fixture = Fixture::new();
    let mut state = FileBackedState::open(fixture.path()).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let root = state.root();
    assert_eq!(
        state.commit_verified(root, &[update(1)], Hash256::ZERO),
        Err(StateError::RootMismatch)
    );
    assert_eq!(state.root(), root);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert!(!fixture.pending().exists());
}

#[test]
fn corrupt_or_legacy_files_are_rejected_without_overwrite() {
    let fixture = Fixture::new();
    let cases = [vec![], vec![0; 16], b"ASTSTATE\x02\x00".to_vec()];
    for bytes in cases {
        fs::write(fixture.path(), &bytes).unwrap();
        assert!(FileBackedState::open(fixture.path()).is_err());
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    }
    let mut state = InMemoryState::new();
    state.commit(state.root(), &[update(1)]).unwrap();
    let mut bytes = state.export_snapshot();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(fixture.path(), bytes).unwrap();
    assert_eq!(
        FileBackedState::open(fixture.path()).unwrap_err(),
        StateError::RootMismatch
    );
}

#[test]
fn memory_and_disk_backends_agree_through_restarts() {
    let fixture = Fixture::new();
    let mut disk = FileBackedState::open(fixture.path()).unwrap();
    let mut memory = InMemoryState::new();
    for height in 0..30u8 {
        let key = StateKey(vec![height % 7]);
        let mut diff = StateDiff::new();
        if height % 3 == 0 {
            diff.delete(key);
        } else {
            diff.put(key, vec![height; usize::from(height) * 3]);
        }
        let expected = memory.commit(memory.root(), &[diff.clone()]).unwrap();
        assert_eq!(
            disk.commit_verified(disk.root(), &[diff], expected)
                .unwrap(),
            expected
        );
        drop(disk);
        disk = FileBackedState::open(fixture.path()).unwrap();
        assert_eq!(disk.root(), expected);
        assert_eq!(fs::read(fixture.path()).unwrap(), memory.export_snapshot());
        for key in 0..7u8 {
            let key = StateKey(vec![key]);
            assert_eq!(disk.get(&key), memory.get(&key));
            assert_eq!(disk.prove(&key).unwrap(), memory.prove(&key).unwrap());
        }
    }
}
