// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Automated in-place retention: bounded compaction, restart, idempotence and refusals.
//!
//! These tests observe local disk occupancy only. They establish no finality claim
//! and never treat an absent height as proof that the height was not finalized.

use state::{InMemoryState, StateDiff};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::{
    AppendOnlyStorage, ChainStorage, Checkpoint, CommitBatch, FileBackedStorage,
    MIN_RETAINED_BLOCKS, NodeStorage, RetentionPolicy, SnapshotSink, StorageError,
};
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, Transaction};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-retention-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
    fn sidecar(&self, suffix: &str) -> PathBuf {
        self.0.join(format!("chain.bin{suffix}"))
    }
    fn length(&self) -> u64 {
        fs::metadata(self.path()).unwrap().len()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This fixture owns its unique temporary directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Chunks(Vec<Vec<u8>>);

impl SnapshotSink for Chunks {
    fn write_chunk(&mut self, _index: u32, bytes: &[u8]) -> Result<(), StorageError> {
        self.0.push(bytes.to_vec());
        Ok(())
    }
}

fn batch(state: &InMemoryState, previous: Checkpoint) -> CommitBatch {
    let height = previous.height + 1;
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
                parent: previous.block,
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

/// Commits `count` blocks above the genesis anchor, returning each committed batch.
fn fill(log: &mut AppendOnlyStorage, count: u64) -> Vec<CommitBatch> {
    if log.checkpoint().is_none() {
        log.initialize_genesis(Hash256([9; 32]), InMemoryState::new())
            .unwrap();
    }
    let mut committed = Vec::new();
    for _ in 0..count {
        let next = batch(log.state(), *log.checkpoint().unwrap());
        log.commit(&next).unwrap();
        committed.push(next);
    }
    committed
}

fn enabled(retained: u64) -> RetentionPolicy {
    RetentionPolicy::bounded(retained, 1, storage::MIN_COMPACTION_BYTES).unwrap()
}

#[test]
fn automatic_evaluation_compacts_in_place_and_restart_resumes_from_the_recorded_anchor() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    log.set_retention_policy(enabled(MIN_RETAINED_BLOCKS));
    let committed = fill(&mut log, 24);
    let head = *log.checkpoint().unwrap();
    assert_eq!(head.height, 24);
    assert_eq!(
        log.retained_floor(),
        Some(head.height - MIN_RETAINED_BLOCKS)
    );
    assert_eq!(
        log.block_count(),
        usize::try_from(MIN_RETAINED_BLOCKS).unwrap()
    );
    let floor = log.retained_floor().unwrap();
    let state = log.retention_state();
    assert!(state.self_compacted, "compaction was not recorded durably");
    assert!(state.compactions > 0, "no compaction was counted");
    assert_eq!(state.last_error, None);
    assert_eq!(state.retained_floor, Some(floor));

    drop(log);
    let mut reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(reopened.recover().unwrap(), Some(head));
    assert_eq!(reopened.retained_floor(), Some(floor));
    assert_eq!(
        reopened.local_retention_anchor().map(|cp| cp.height),
        Some(floor)
    );
    let (anchor, anchor_state) = reopened.read_anchor().unwrap().unwrap();
    assert_eq!(anchor.height, floor);
    assert_eq!(anchor.state_root, anchor_state.root());
    for height in 0..=head.height {
        let body = reopened.read_finalized(height).unwrap();
        assert_eq!(
            body.is_some(),
            height > floor,
            "unexpected body availability at height {height}"
        );
        if let Some((block, certificate)) = body {
            let expected = &committed[usize::try_from(height).unwrap() - 1];
            assert_eq!(block, expected.block, "wrong body at height {height}");
            assert_eq!(certificate, expected.finality_certificate);
        }
    }
    for (index, committed) in committed.iter().enumerate() {
        let height = u64::try_from(index).unwrap() + 1;
        let id = transaction::compute_tx_id(&committed.block.transactions[0]);
        assert_eq!(
            reopened.transaction_location(id).is_some(),
            height > floor,
            "unexpected transaction index entry for height {height}"
        );
    }
    reopened
        .export_snapshot(anchor, &mut Chunks::default())
        .unwrap();
    reopened
        .export_snapshot(head, &mut Chunks::default())
        .unwrap();
    let pruned = Checkpoint {
        height: floor - 1,
        ..anchor
    };
    assert_eq!(
        reopened.export_snapshot(pruned, &mut Chunks::default()),
        Err(StorageError::VerificationFailed)
    );
}

#[test]
fn compaction_physically_reclaims_bytes_and_leaves_the_log_extendable() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 40);
    let before = fixture.length();
    let head = *log.checkpoint().unwrap();
    log.prune(head.height - MIN_RETAINED_BLOCKS).unwrap();
    let after = fixture.length();
    assert!(
        after < before,
        "compaction did not reclaim bytes: {after} is not below {before}"
    );
    assert_eq!(
        log.retained_floor(),
        Some(head.height - MIN_RETAINED_BLOCKS)
    );
    fill(&mut log, 3);
    assert_eq!(log.checkpoint().unwrap().height, head.height + 3);
    drop(log);
    let reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(reopened.checkpoint().unwrap().height, head.height + 3);
    assert_eq!(
        reopened.retained_floor(),
        Some(head.height - MIN_RETAINED_BLOCKS)
    );
}

#[test]
fn repeated_pruning_to_the_same_or_lower_floor_leaves_every_byte_unchanged() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 32);
    let head = *log.checkpoint().unwrap();
    let floor = head.height - MIN_RETAINED_BLOCKS;
    log.prune(floor).unwrap();
    let bytes = fs::read(fixture.path()).unwrap();
    let record = fs::read(fixture.sidecar(".retain")).unwrap();
    for repeat in [floor, floor - 1, 1, 0] {
        assert_eq!(
            log.prune(repeat),
            Ok(()),
            "re-prune to {repeat} was refused"
        );
        assert_eq!(
            fs::read(fixture.path()).unwrap(),
            bytes,
            "re-prune to {repeat} rewrote the log"
        );
        assert_eq!(
            fs::read(fixture.sidecar(".retain")).unwrap(),
            record,
            "re-prune to {repeat} rewrote the durable record"
        );
        assert_eq!(log.retained_floor(), Some(floor));
    }
}

#[test]
fn retention_refuses_a_floor_above_the_head_or_below_the_minimum_suffix() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 20);
    let head = log.checkpoint().unwrap().height;
    let bytes = fs::read(fixture.path()).unwrap();
    for above in [head + 1, head + 2, u64::MAX] {
        assert_eq!(
            log.prune(above),
            Err(StorageError::InvalidOrder),
            "accepted a floor of {above} above head {head}"
        );
    }
    for short in head - MIN_RETAINED_BLOCKS + 1..=head {
        assert_eq!(
            log.prune(short),
            Err(StorageError::LimitExceeded),
            "accepted a floor of {short} retaining fewer than the minimum"
        );
    }
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    assert_eq!(log.retained_floor(), Some(0));
    assert!(!fixture.sidecar(".retain").exists());
    assert_eq!(log.prune(head - MIN_RETAINED_BLOCKS), Ok(()));
}

#[test]
fn a_floor_outside_the_bounded_state_index_is_refused_without_changing_the_log() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, storage::MAX_STATE_HISTORY_BLOCKS as u64 + 12);
    let bytes = fs::read(fixture.path()).unwrap();
    let index_floor = log.history_floor().unwrap();
    assert!(index_floor > 1, "state index did not evict any transition");
    for below in 1..index_floor {
        assert_eq!(
            log.prune(below),
            Err(StorageError::LimitExceeded),
            "accepted a floor of {below} below the state index floor {index_floor}"
        );
    }
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    assert_eq!(log.prune(index_floor), Ok(()));
    assert_eq!(log.retained_floor(), Some(index_floor));
}

#[test]
fn a_disabled_policy_retains_every_committed_block_and_records_nothing() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert!(!log.retention_state().policy.is_enabled());
    fill(&mut log, 48);
    assert_eq!(log.retained_floor(), Some(0));
    assert_eq!(log.block_count(), 48);
    let state = log.retention_state();
    assert!(!state.self_compacted);
    assert_eq!(state.compactions, 0);
    assert_eq!(state.last_error, None);
    assert_eq!(log.local_retention_anchor(), None);
    assert!(!fixture.sidecar(".retain").exists());
    assert!(!fixture.sidecar(".compact").exists());
    assert!(!fixture.sidecar(".swap").exists());
}

#[test]
fn the_history_floor_accessor_agrees_with_every_historical_state_read() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    log.set_retention_policy(enabled(16));
    fill(&mut log, 44);
    let head = log.checkpoint().unwrap().height;
    for stage in [head, head + 7] {
        let floor = log.history_floor().unwrap();
        assert_eq!(log.read_state_at(floor).unwrap().unwrap().0.height, floor);
        for height in 0..=stage + 3 {
            assert_eq!(
                log.read_state_at(height).unwrap().is_some(),
                (floor..=stage).contains(&height),
                "state availability at height {height} disagrees with floor {floor}"
            );
        }
        assert!(
            floor >= log.retained_floor().unwrap(),
            "state index floor {floor} precedes the retained floor"
        );
        fill(&mut log, 7);
    }
}

#[test]
fn the_legacy_archive_backend_refuses_automated_retention() {
    let fixture = Fixture::new();
    FileBackedStorage::open(fixture.path())
        .unwrap()
        .initialize_genesis(Hash256([4; 32]), InMemoryState::new())
        .unwrap();
    let mut storage = ChainStorage::open(fixture.path()).unwrap();
    assert!(storage.is_legacy_archive());
    assert_eq!(
        storage.set_retention_policy(enabled(MIN_RETAINED_BLOCKS)),
        Err(StorageError::Unsupported)
    );
    let state = storage.retention_state();
    assert!(!state.policy.is_enabled());
    assert!(!state.self_compacted);
    assert_eq!(state.compactions, 0);
    assert_eq!(storage.local_retention_anchor(), None);
    assert_eq!(storage.retained_floor(), Some(0));
}

#[test]
fn an_unpublished_replacement_without_a_readable_marker_is_discarded_on_restart() {
    for torn in [false, true] {
        let fixture = Fixture::new();
        let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
        fill(&mut log, 20);
        let head = *log.checkpoint().unwrap();
        drop(log);
        let bytes = fs::read(fixture.path()).unwrap();
        let head_bytes = fs::read(fixture.sidecar(".head")).unwrap();
        fs::write(
            fixture.sidecar(".compact"),
            b"unpublished replacement bytes",
        )
        .unwrap();
        if torn {
            fs::write(fixture.sidecar(".swap"), &head_bytes[..40]).unwrap();
        }
        fs::write(fixture.sidecar(".retain.pending"), b"staged record").unwrap();
        let mut reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
        assert_eq!(reopened.recover().unwrap(), Some(head), "torn={torn}");
        assert_eq!(reopened.retained_floor(), Some(0), "torn={torn}");
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes, "torn={torn}");
        assert!(!fixture.sidecar(".compact").exists(), "torn={torn}");
        assert!(!fixture.sidecar(".swap").exists(), "torn={torn}");
        assert!(!fixture.sidecar(".retain.pending").exists(), "torn={torn}");
    }
}

#[test]
fn a_committed_marker_naming_the_published_log_is_completed_on_restart() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 20);
    let head = *log.checkpoint().unwrap();
    let floor = head.height - MIN_RETAINED_BLOCKS;
    log.prune(floor).unwrap();
    drop(log);
    // The replacement was renamed into place but its head rename did not run.
    let published = fs::read(fixture.sidecar(".head")).unwrap();
    fs::write(fixture.sidecar(".swap"), &published).unwrap();
    fs::remove_file(fixture.sidecar(".head")).unwrap();
    let mut reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(reopened.recover().unwrap(), Some(head));
    assert_eq!(reopened.retained_floor(), Some(floor));
    assert!(!fixture.sidecar(".swap").exists());
    assert_eq!(fs::read(fixture.sidecar(".head")).unwrap(), published);
}

#[test]
fn a_committed_marker_whose_replacement_does_not_verify_fails_closed() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 12);
    let head = *log.checkpoint().unwrap();
    drop(log);
    let bytes = fs::read(fixture.path()).unwrap();
    fs::write(
        fixture.sidecar(".swap"),
        fs::read(fixture.sidecar(".head")).unwrap(),
    )
    .unwrap();
    fs::write(fixture.sidecar(".compact"), b"bytes that chain to nothing").unwrap();
    // The marker is committed, so the staged replacement is required to verify.
    assert_eq!(
        AppendOnlyStorage::open(fixture.path()).err(),
        Some(StorageError::Corrupt)
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    fs::remove_file(fixture.sidecar(".compact")).unwrap();
    let mut reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(reopened.recover().unwrap(), Some(head));
}

#[test]
fn a_shortened_log_without_its_local_record_is_not_reported_as_self_compacted() {
    let fixture = Fixture::new();
    let mut log = AppendOnlyStorage::open(fixture.path()).unwrap();
    fill(&mut log, 24);
    let head = *log.checkpoint().unwrap();
    let floor = head.height - MIN_RETAINED_BLOCKS;
    log.prune(floor).unwrap();
    drop(log);
    let record = fs::read(fixture.sidecar(".retain")).unwrap();
    for damage in [None, Some(0), Some(8), Some(119)] {
        match damage {
            None => fs::remove_file(fixture.sidecar(".retain")).unwrap(),
            Some(at) => {
                let mut mutated = record.clone();
                mutated[at] ^= 1;
                fs::write(fixture.sidecar(".retain"), &mutated).unwrap();
            }
        }
        let mut reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
        assert_eq!(reopened.recover().unwrap(), Some(head), "damage {damage:?}");
        assert_eq!(reopened.retained_floor(), Some(floor), "damage {damage:?}");
        assert_eq!(
            reopened.local_retention_anchor(),
            None,
            "a directory without a readable record claimed self-compaction ({damage:?})"
        );
        assert!(!reopened.retention_state().self_compacted);
    }
    fs::write(fixture.sidecar(".retain"), &record).unwrap();
    let reopened = AppendOnlyStorage::open(fixture.path()).unwrap();
    assert_eq!(
        reopened.local_retention_anchor().map(|cp| cp.height),
        Some(floor)
    );
}

#[test]
fn chain_storage_drives_automatic_retention_and_reports_its_floors() {
    let fixture = Fixture::new();
    let mut storage = ChainStorage::open(fixture.path()).unwrap();
    assert!(!storage.is_legacy_archive());
    storage
        .initialize_genesis(Hash256([6; 32]), InMemoryState::new())
        .unwrap();
    storage
        .set_retention_policy(enabled(MIN_RETAINED_BLOCKS))
        .unwrap();
    for _ in 0..30 {
        let next = batch(storage.state(), *storage.checkpoint().unwrap());
        storage.commit(&next).unwrap();
    }
    let head = storage.checkpoint().unwrap().height;
    let floor = head - MIN_RETAINED_BLOCKS;
    assert_eq!(storage.retained_floor(), Some(floor));
    assert_eq!(
        storage.local_retention_anchor().map(|cp| cp.height),
        Some(floor)
    );
    assert_eq!(storage.history_floor(), Some(floor));
    let state = storage.retention_state();
    assert!(state.policy.is_enabled());
    assert!(state.self_compacted);
    assert_eq!(state.last_error, None);
}
