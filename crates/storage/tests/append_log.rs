// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Append publication, bounded replay, legacy compatibility, and crash-tail recovery.
use state::{InMemoryState, StateDiff};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::{
    AppendOnlyStorage, ChainStorage, Checkpoint, CommitBatch, FileBackedStorage, InMemoryStorage,
    NodeStorage, SnapshotSink, SnapshotSource, StorageError,
};
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, Transaction};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-log-{}-{}",
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
fn delta_replay_matches_reference_and_reconstructs_historical_snapshots() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let mut reference = InMemoryStorage::new();
    let mut checkpoints = Vec::new();
    for height in 0..32 {
        let mut batch = batch(log.state(), log.checkpoint().copied());
        let mut repeated = StateDiff::new();
        repeated.put(StateKey(vec![2]), vec![8]);
        repeated.delete(StateKey(vec![1]));
        repeated.put(StateKey(vec![1]), vec![height]);
        repeated.delete(StateKey(vec![2]));
        batch.state_diffs.push(repeated);
        batch.block.header.state_root = log
            .state()
            .prepare(log.state().root(), &batch.state_diffs)
            .unwrap()
            .root();
        let cp = log.commit(&batch).unwrap();
        assert_eq!(reference.commit(&batch), Ok(cp));
        checkpoints.push(cp);
        assert_eq!(
            log.read_finalized(cp.height).unwrap(),
            Some((batch.block, batch.finality_certificate))
        );
        drop(log);
        log = AppendOnlyStorage::open(fixture.path()).unwrap();
        assert_eq!(log.recover().unwrap(), Some(cp));
        assert_eq!(
            log.state().export_snapshot(),
            reference.state().export_snapshot()
        );
    }
    for cp in checkpoints {
        let (indexed, historical) = log.read_state_at(cp.height).unwrap().unwrap();
        let (_, expected_state) = reference.read_state_at(cp.height).unwrap().unwrap();
        assert_eq!(indexed, cp);
        assert_eq!(
            historical.export_snapshot(),
            expected_state.export_snapshot()
        );
        let mut actual = Chunks::default();
        let mut expected = Chunks::default();
        log.export_snapshot(cp, &mut actual).unwrap();
        reference.export_snapshot(cp, &mut expected).unwrap();
        assert_eq!(actual.0, expected.0);
    }
    assert_eq!(log.read_finalized(u64::MAX).unwrap(), None);
}

#[test]
fn historical_index_evicts_a_bounded_window_and_rebuilds_only_published_changes() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let genesis = log
        .initialize_genesis(Hash256([5; 32]), InMemoryState::new())
        .unwrap();
    assert_eq!(log.read_state_at(0).unwrap().unwrap().0, genesis);
    let mut reference = Vec::new();
    for _ in 0..storage::MAX_STATE_HISTORY_BLOCKS + 4 {
        let next = batch(log.state(), log.checkpoint().copied());
        let checkpoint = log.commit(&next).unwrap();
        reference.push((checkpoint, log.state().export_snapshot()));
    }
    assert!(log.read_state_at(3).unwrap().is_none());
    assert!(log.read_state_at(u64::MAX).unwrap().is_none());
    let head = *log.checkpoint().unwrap();
    let mut invalid = batch(log.state(), Some(head));
    invalid.block.header.state_root = Hash256::ZERO;
    assert_eq!(log.commit(&invalid), Err(StorageError::VerificationFailed));
    assert_eq!(log.checkpoint(), Some(&head));
    drop(log);
    let log = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert!(log.read_state_at(3).unwrap().is_none());
    for (checkpoint, bytes) in reference.into_iter().filter(|(cp, _)| cp.height >= 4) {
        let (restored, state) = log.read_state_at(checkpoint.height).unwrap().unwrap();
        assert_eq!(restored, checkpoint);
        assert_eq!(state.export_snapshot(), bytes);
    }
    // Eviction of a derived index must not remove certified historical block bodies.
    assert!(log.read_finalized(1).unwrap().is_some());
}

#[test]
fn grows_linearly_past_legacy_checkpoint_limit_without_rewriting_prefix() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    log.initialize_genesis(Hash256([1; 32]), InMemoryState::new())
        .unwrap();
    let prefix = fs::read(fixture.path()).unwrap();
    let mut last = None;
    for _ in 0..=storage::MAX_ARCHIVE_CHECKPOINTS {
        last = Some(
            log.commit(&batch(log.state(), log.checkpoint().copied()))
                .unwrap(),
        );
    }
    let bytes = fs::read(fixture.path()).unwrap();
    assert_eq!(&bytes[..prefix.len()], prefix);
    assert!(
        bytes.len() < 4 * 1024 * 1024,
        "history must store deltas, not snapshots"
    );
    drop(log);
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(log.recover().unwrap(), last);
    assert_eq!(log.block_count(), storage::MAX_ARCHIVE_CHECKPOINTS + 1);
    assert_eq!(log.read_finalized(1).unwrap().unwrap().0.header.height, 1);
    assert_eq!(
        log.read_finalized(last.unwrap().height)
            .unwrap()
            .unwrap()
            .0
            .header
            .compute_hash(),
        last.unwrap().block
    );
}

#[test]
fn rejected_and_failed_commits_preserve_published_prefix_and_state() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let first = batch(log.state(), None);
    let cp = log.commit(&first).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let head = fs::read(fixture.0.join("chain.bin.head")).unwrap();
    let next = batch(log.state(), Some(cp));
    let mut bad = next.clone();
    bad.block.header.state_root = Hash256::ZERO;
    assert_eq!(log.commit(&bad), Err(StorageError::VerificationFailed));
    bad = next.clone();
    bad.block.header.height += 1;
    assert_eq!(log.commit(&bad), Err(StorageError::InvalidOrder));
    bad = next.clone();
    bad.block.transactions[0].nonce += 1;
    assert_eq!(log.commit(&bad), Err(StorageError::VerificationFailed));
    fs::create_dir(fixture.pending()).unwrap();
    assert_eq!(log.commit(&next), Err(StorageError::Io));
    assert_eq!(log.checkpoint(), Some(&cp));
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(fs::read(fixture.0.join("chain.bin.head")).unwrap(), head);
    fs::remove_dir(fixture.pending()).unwrap();
    assert_eq!(log.commit(&next).unwrap().height, 1);
}

#[test]
fn every_unpublished_partial_or_complete_tail_is_discarded() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let cp = log.commit(&batch(log.state(), None)).unwrap();
    let prefix = fs::read(fixture.path()).unwrap();
    let old_head = fs::read(fixture.0.join("chain.bin.head")).unwrap();
    log.commit(&batch(log.state(), Some(cp))).unwrap();
    let all = fs::read(fixture.path()).unwrap();
    let new_head = fs::read(fixture.0.join("chain.bin.head")).unwrap();
    drop(log);
    fs::write(fixture.0.join("chain.bin.head"), &old_head).unwrap();
    for end in prefix.len()..=all.len() {
        fs::write(fixture.path(), &all[..end]).unwrap();
        fs::write(fixture.pending(), &new_head).unwrap();
        let recovered = AppendOnlyStorage::open(fixture.path()).unwrap();
        assert_eq!(recovered.checkpoint(), Some(&cp));
        assert_eq!(recovered.read_finalized(1).unwrap(), None);
        assert_eq!(fs::read(fixture.path()).unwrap(), prefix);
    }
}

#[test]
fn every_committed_truncation_or_byte_mutation_fails_without_repairing_data() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    log.commit(&batch(log.state(), None)).unwrap();
    let bytes = fs::read(fixture.path()).unwrap();
    drop(log);
    for end in 0..bytes.len() {
        fs::write(fixture.path(), &bytes[..end]).unwrap();
        assert!(
            AppendOnlyStorage::open(fixture.path()).is_err(),
            "truncation {end}"
        );
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes[..end]);
        let mut changed = bytes.clone();
        changed[end] ^= 1;
        fs::write(fixture.path(), &changed).unwrap();
        assert!(
            AppendOnlyStorage::open(fixture.path()).is_err(),
            "mutation {end}"
        );
        assert_eq!(fs::read(fixture.path()).unwrap(), changed);
    }
}

#[test]
fn corrupt_missing_or_orphan_head_never_resets_the_chain() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    log.commit(&batch(log.state(), None)).unwrap();
    let bytes = fs::read(fixture.path()).unwrap();
    let path = fixture.0.join("chain.bin.head");
    let head = fs::read(&path).unwrap();
    drop(log);
    for end in 0..head.len() {
        fs::write(&path, &head[..end]).unwrap();
        assert!(AppendOnlyStorage::open(fixture.path()).is_err());
        let mut bad = head.clone();
        bad[end] ^= 1;
        fs::write(&path, bad).unwrap();
        assert!(AppendOnlyStorage::open(fixture.path()).is_err());
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    }
    fs::remove_file(&path).unwrap();
    assert!(AppendOnlyStorage::open(fixture.path()).is_err());
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    fs::write(&path, &head).unwrap();
    fs::remove_file(fixture.path()).unwrap();
    assert!(AppendOnlyStorage::open(fixture.path()).is_err());
    assert!(!fixture.path().exists());
}

#[test]
fn historical_reads_detect_corruption_after_startup() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let cp = log.commit(&batch(log.state(), None)).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(fixture.path())
        .unwrap();
    file.seek(SeekFrom::Start(55)).unwrap();
    file.write_all(&[128]).unwrap();
    file.sync_all().unwrap();
    assert_eq!(log.read_finalized(cp.height), Err(StorageError::Corrupt));
    drop(log);
    assert!(AppendOnlyStorage::open(fixture.path()).is_err());
}

#[test]
fn incompatible_retention_or_import_is_explicit_and_non_destructive() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    let cp = log
        .initialize_genesis(Hash256([8; 32]), InMemoryState::new())
        .unwrap();
    let mut chunks = Chunks::default();
    log.export_snapshot(cp, &mut chunks).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    assert_eq!(
        log.import_snapshot(cp, &mut chunks),
        Err(StorageError::Unsupported)
    );
    assert_eq!(log.prune(1), Err(StorageError::Unsupported));
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    let imported = Fixture::new();
    let mut other = AppendOnlyStorage::open(imported.path()).unwrap();
    assert_eq!(other.import_snapshot(cp, &mut chunks), Ok(cp));
    let next = batch(log.state(), Some(cp));
    assert_eq!(other.commit(&next), log.commit(&next));
    drop(other);
    assert_eq!(
        AppendOnlyStorage::open(imported.path())
            .unwrap()
            .checkpoint(),
        log.checkpoint()
    );
}

#[test]
fn legacy_detection_preserves_existing_archives_and_uses_shared_writer_lock() {
    let legacy = Fixture::new();
    let mut archive = FileBackedStorage::open(legacy.path()).unwrap();
    let cp = archive.commit(&batch(archive.state(), None)).unwrap();
    assert!(matches!(
        ChainStorage::open(legacy.path()),
        Err(StorageError::Locked)
    ));
    drop(archive);
    let bytes = fs::read(legacy.path()).unwrap();
    let store = ChainStorage::open(legacy.path()).unwrap();
    assert!(store.is_legacy_archive());
    assert_eq!(
        store
            .read_finalized(cp.height)
            .unwrap()
            .unwrap()
            .0
            .header
            .compute_hash(),
        cp.block
    );
    assert_eq!(fs::read(legacy.path()).unwrap(), bytes);
    let fresh = Fixture::new();
    let store = ChainStorage::open(fresh.path()).unwrap();
    assert!(!store.is_legacy_archive());
    assert!(matches!(
        ChainStorage::open(fresh.path()),
        Err(StorageError::Locked)
    ));
    assert!(matches!(
        FileBackedStorage::open(fresh.path()),
        Err(StorageError::Locked)
    ));
}

#[test]
fn process_child() {
    let Ok(path) = std::env::var("ASTROLUNE_LOG_PROCESS") else {
        return;
    };
    let mut log = AppendOnlyStorage::open(&path).unwrap();
    log.commit(&batch(log.state(), log.checkpoint().copied()))
        .unwrap();
    // No Rust destructors run. OS handle release must suffice after durable publication.
    std::process::exit(0);
}

#[test]
fn abrupt_process_exit_preserves_publication_and_releases_writer_lock() {
    let fixture = Fixture::new();
    for height in 0..3 {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process_child"])
            .env("ASTROLUNE_LOG_PROCESS", fixture.path())
            .status()
            .unwrap();
        assert!(status.success());
        let log = AppendOnlyStorage::open(fixture.path()).unwrap();
        assert_eq!(log.checkpoint().unwrap().height, height);
    }
}
