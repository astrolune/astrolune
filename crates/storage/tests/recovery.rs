// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Whole-chain restart, atomic publication, and recovery conformance.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use state::{InMemoryState, StateDiff};
use storage::{
    Checkpoint, CommitBatch, FileBackedStorage, NodeStorage, SnapshotSink, SnapshotSource,
    StorageError,
};
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, Transaction};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-chain-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
    fn pending(&self) -> PathBuf {
        self.0.join("chain.bin.pending")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This fixture owns its unique temporary directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn batch(state: &InMemoryState, previous: Option<Checkpoint>) -> CommitBatch {
    let height = previous.map_or(0, |cp| cp.height + 1);
    let mut diff = StateDiff::new();
    diff.put(StateKey(vec![1]), height.to_le_bytes().to_vec());
    let root = state.prepare(state.root(), &[diff.clone()]).unwrap().root();
    let tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender: Address([1; 32]),
        nonce: height,
        access_list: vec![],
        resource_limit: Resources::ZERO,
        payload: height.to_le_bytes().to_vec(),
        signature: [7; 64],
    };
    CommitBatch {
        effects: None,
        block: Block {
            header: BlockHeader {
                height,
                parent: previous.map_or(Hash256::ZERO, |cp| cp.block),
                transactions_root: crypto::compute_transactions_root(&[
                    transaction::compute_tx_id(&tx),
                ]),
                state_root: root,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: Resources::ZERO,
            },
            transactions: vec![tx],
        },
        finality_certificate: vec![3; 80],
        state_diffs: vec![diff],
    }
}

#[derive(Default)]
struct Chunks(Vec<Vec<u8>>);
impl SnapshotSink for Chunks {
    fn write_chunk(&mut self, index: u32, bytes: &[u8]) -> Result<(), StorageError> {
        assert_eq!(index as usize, self.0.len());
        self.0.push(bytes.to_vec());
        Ok(())
    }
}
impl SnapshotSource for Chunks {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        })
    }
}

#[test]
fn restarts_preserve_bodies_certificates_and_historical_snapshots() {
    let fixture = Fixture::new();
    let mut history = Vec::new();
    for _ in 0..6 {
        let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
        let next = batch(storage.state(), storage.checkpoint().copied());
        let checkpoint = storage.commit(&next).unwrap();
        history.push((checkpoint, next));
    }
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.recover().unwrap(), Some(history.last().unwrap().0));
    for (checkpoint, next) in &history {
        assert_eq!(storage.get_block(&checkpoint.block), Some(&next.block));
        assert_eq!(
            storage.get_certificate(&checkpoint.block),
            Some(next.finality_certificate.as_slice())
        );
        let mut chunks = Chunks::default();
        storage.export_snapshot(*checkpoint, &mut chunks).unwrap();
        let mut imported = storage::InMemoryStorage::new();
        imported.import_snapshot(*checkpoint, &mut chunks).unwrap();
        assert_eq!(
            imported.state().get(&StateKey(vec![1])),
            Some(checkpoint.height.to_le_bytes().as_slice())
        );
    }
    storage.prune(4).unwrap();
    drop(storage);
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.block_count(), 2);
    assert!(storage.get_block(&history[0].0.block).is_none());
    storage.prune(u64::MAX).unwrap();
    drop(storage);
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.block_count(), 1);
    let next = batch(storage.state(), storage.checkpoint().copied());
    assert_eq!(storage.commit(&next).unwrap().height, 6);
}

#[test]
fn rejected_or_failed_updates_preserve_disk_and_memory() {
    let fixture = Fixture::new();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let first = batch(storage.state(), None);
    let checkpoint = storage.commit(&first).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let next = batch(storage.state(), Some(checkpoint));
    let mut invalid = next.clone();
    invalid.block.transactions[0].payload.push(1);
    assert_eq!(
        storage.commit(&invalid),
        Err(StorageError::VerificationFailed)
    );
    invalid = next.clone();
    invalid.block.header.state_root = Hash256::ZERO;
    assert_eq!(
        storage.commit(&invalid),
        Err(StorageError::VerificationFailed)
    );
    invalid = next.clone();
    invalid.block.header.parent = Hash256::ZERO;
    assert_eq!(storage.commit(&invalid), Err(StorageError::InvalidOrder));
    invalid = next.clone();
    invalid.finality_certificate.resize(1024 * 1024 + 1, 0);
    assert_eq!(storage.commit(&invalid), Err(StorageError::LimitExceeded));
    fs::create_dir(fixture.pending()).unwrap();
    assert_eq!(storage.commit(&next), Err(StorageError::Io));
    assert_eq!(storage.prune(u64::MAX), Err(StorageError::Io));
    assert_eq!(storage.recover().unwrap(), Some(checkpoint));
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    fs::remove_dir(fixture.pending()).unwrap();
    assert_eq!(storage.commit(&next).unwrap().height, 1);
}

#[test]
fn snapshot_import_is_durable_and_atomic() {
    let source_fixture = Fixture::new();
    let destination_fixture = Fixture::new();
    let mut source = FileBackedStorage::open(source_fixture.path()).unwrap();
    for _ in 0..3 {
        let next = batch(source.state(), source.checkpoint().copied());
        source.commit(&next).unwrap();
    }
    let checkpoint = *source.checkpoint().unwrap();
    let mut chunks = Chunks::default();
    source.export_snapshot(checkpoint, &mut chunks).unwrap();
    let mut destination = FileBackedStorage::open(destination_fixture.path()).unwrap();
    let before = fs::read(destination_fixture.path()).unwrap();
    let mut broken = Chunks(chunks.0.clone());
    broken.0.last_mut().unwrap().push(0);
    assert!(
        destination
            .import_snapshot(checkpoint, &mut broken)
            .is_err()
    );
    fs::create_dir(destination_fixture.pending()).unwrap();
    assert_eq!(
        destination.import_snapshot(checkpoint, &mut Chunks(chunks.0.clone())),
        Err(StorageError::Io)
    );
    assert_eq!(destination.recover().unwrap(), None);
    assert_eq!(fs::read(destination_fixture.path()).unwrap(), before);
    fs::remove_dir(destination_fixture.pending()).unwrap();
    destination
        .import_snapshot(checkpoint, &mut chunks)
        .unwrap();
    drop(destination);
    let mut destination = FileBackedStorage::open(destination_fixture.path()).unwrap();
    assert_eq!(destination.recover().unwrap(), Some(checkpoint));
    assert_eq!(destination.block_count(), 0);
    let next = batch(destination.state(), Some(checkpoint));
    destination.commit(&next).unwrap();
    drop(destination);
    let mut destination = FileBackedStorage::open(destination_fixture.path()).unwrap();
    assert_eq!(destination.recover().unwrap().unwrap().height, 3);
    assert_eq!(destination.block_count(), 1);
}

#[test]
fn corrupt_archive_fails_closed_and_pending_bytes_do_not_replace_it() {
    let fixture = Fixture::new();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let next = batch(storage.state(), None);
    storage.commit(&next).unwrap();
    drop(storage);
    let original = fs::read(fixture.path()).unwrap();
    fs::write(fixture.pending(), &original).unwrap();
    for at in [0, 8, 10, 25, 85, original.len() - 1] {
        let mut altered = original.clone();
        altered[at] ^= 1;
        fs::write(fixture.path(), &altered).unwrap();
        assert_eq!(
            FileBackedStorage::open(fixture.path()).unwrap_err(),
            StorageError::Corrupt
        );
        assert_eq!(fs::read(fixture.path()).unwrap(), altered);
    }
    fs::write(fixture.path(), &original).unwrap();
    fs::write(fixture.pending(), b"interrupted").unwrap();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.recover().unwrap().unwrap().height, 0);
    let next = batch(storage.state(), storage.checkpoint().copied());
    storage.commit(&next).unwrap();
    assert!(!fixture.pending().exists());
}

fn child(fixture: &Fixture, mode: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_probe", "--nocapture"])
        .env("ASTROLUNE_CHAIN_TEST_PATH", fixture.path())
        .env("ASTROLUNE_CHAIN_TEST_MODE", mode)
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
    let Some(path) = std::env::var_os("ASTROLUNE_CHAIN_TEST_PATH") else {
        return;
    };
    if std::env::var("ASTROLUNE_CHAIN_TEST_MODE").unwrap() == "locked" {
        assert_eq!(
            FileBackedStorage::open(path).unwrap_err(),
            StorageError::Locked
        );
    } else {
        let mut storage = FileBackedStorage::open(path).unwrap();
        let next = batch(storage.state(), storage.checkpoint().copied());
        storage.commit(&next).unwrap();
        // Exit without destructors: synchronized publication must already be complete.
        std::process::exit(0);
    }
}

#[test]
fn process_lock_and_abrupt_exit_recovery() {
    let fixture = Fixture::new();
    let storage = FileBackedStorage::open(fixture.path()).unwrap();
    child(&fixture, "locked");
    drop(storage);
    child(&fixture, "commit");
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.recover().unwrap().unwrap().height, 0);
    assert_eq!(storage.block_count(), 1);
}

#[test]
fn rename_failure_retains_the_published_version_for_retry() {
    let fixture = Fixture::new();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let next = batch(storage.state(), None);
    let before = fs::read(fixture.path()).unwrap();
    let backup = fixture.0.join("backup.bin");
    fs::rename(fixture.path(), &backup).unwrap();
    fs::create_dir(fixture.path()).unwrap();
    assert_eq!(storage.commit(&next), Err(StorageError::Io));
    assert_eq!(storage.recover().unwrap(), None);
    assert_eq!(fs::read(&backup).unwrap(), before);
    fs::remove_dir(fixture.path()).unwrap();
    fs::rename(&backup, fixture.path()).unwrap();
    storage.commit(&next).unwrap();
    drop(storage);
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    assert_eq!(storage.recover().unwrap().unwrap().height, 0);
}

#[test]
fn unsupported_transaction_version_cannot_publish_an_unrecoverable_archive() {
    let fixture = Fixture::new();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let mut invalid = batch(storage.state(), None);
    invalid.block.transactions[0].version = 2;
    invalid.block.header.transactions_root =
        crypto::compute_transactions_root(&[transaction::compute_tx_id(
            &invalid.block.transactions[0],
        )]);
    assert!(storage.commit(&invalid).is_err());
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert!(storage.checkpoint().is_none());
}

#[test]
fn legacy_empty_archive_is_rejected_without_rewriting() {
    let fixture = Fixture::new();
    let mut legacy = b"ASTSTORE".to_vec();
    legacy.extend_from_slice(&1_u16.to_le_bytes());
    legacy.extend_from_slice(&0_u64.to_le_bytes());
    let checksum = types::hash::domain_hash(b"astrolune.storage.archive.v1", &legacy);
    legacy.extend_from_slice(checksum.as_bytes());
    fs::write(fixture.path(), &legacy).unwrap();
    assert!(FileBackedStorage::open(fixture.path()).is_err());
    assert_eq!(fs::read(fixture.path()).unwrap(), legacy);
}
