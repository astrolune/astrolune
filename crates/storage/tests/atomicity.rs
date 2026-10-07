// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Atomic checkpoint publication and authenticated snapshot exchange.

use state::{StateDatabase, StateDiff, StateSnapshot};
use storage::{
    Checkpoint, CommitBatch, InMemoryStorage, NodeStorage, SNAPSHOT_CHUNK_BYTES, SnapshotSink,
    SnapshotSource, StorageError,
};
use types::{Block, BlockHeader, Hash256, Resources, StateKey};

fn batch(storage: &InMemoryStorage, value: u8, size: usize) -> CommitBatch {
    let mut diff = StateDiff::new();
    diff.put(StateKey(vec![value]), vec![value; size]);
    let root = storage
        .state()
        .prepare(storage.state().root(), &[diff.clone()])
        .unwrap()
        .root();
    CommitBatch {
        effects: None,
        block: Block {
            header: BlockHeader {
                height: storage.checkpoint().map_or(0, |cp| cp.height + 1),
                parent: storage.checkpoint().map_or(Hash256::ZERO, |cp| cp.block),
                state_root: root,
                transactions_root: Hash256::ZERO,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: Resources::ZERO,
            },
            transactions: vec![],
        },
        finality_certificate: vec![1],
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

struct Source(std::vec::IntoIter<Vec<u8>>);
impl SnapshotSource for Source {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.next())
    }
}

fn export(storage: &InMemoryStorage, cp: Checkpoint) -> Vec<Vec<u8>> {
    let mut chunks = Chunks::default();
    storage.export_snapshot(cp, &mut chunks).unwrap();
    chunks.0
}

#[test]
fn rejected_commit_does_not_change_state_history_or_certificates() {
    let mut storage = InMemoryStorage::new();
    let cp = storage.commit(&batch(&storage, 1, 80)).unwrap();
    let snapshot = storage.state().snapshot().unwrap();
    let before = storage.state().export_snapshot();
    let valid = batch(&storage, 2, 40);
    let mut invalid = valid.clone();
    invalid.block.header.state_root = Hash256::ZERO;
    assert_eq!(
        storage.commit(&invalid),
        Err(StorageError::VerificationFailed)
    );
    assert_eq!(storage.checkpoint(), Some(&cp));
    assert_eq!(storage.block_count(), 1);
    assert_eq!(storage.state().export_snapshot(), before);
    assert!(
        storage
            .get_certificate(&invalid.block.header.compute_hash())
            .is_none()
    );
    assert_eq!(snapshot.root(), cp.state_root);
    assert!(snapshot.get(&StateKey(vec![2])).unwrap().is_none());
    invalid = valid.clone();
    invalid.block.header.parent = Hash256::ZERO;
    assert_eq!(storage.commit(&invalid), Err(StorageError::InvalidOrder));
    assert_eq!(storage.state().export_snapshot(), before);
    storage.commit(&valid).unwrap();
}

#[test]
fn historical_snapshot_roundtrip_restores_entries_and_allows_extension() {
    let mut source = InMemoryStorage::new();
    let first = source
        .commit(&batch(&source, 1, SNAPSHOT_CHUNK_BYTES * 2))
        .unwrap();
    source.commit(&batch(&source, 2, 80)).unwrap();
    let chunks = export(&source, first);
    assert!(chunks.len() >= 4);
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.len() <= SNAPSHOT_CHUNK_BYTES)
    );
    let mut restored = InMemoryStorage::new();
    assert_eq!(
        restored.import_snapshot(first, &mut Source(chunks.into_iter())),
        Ok(first)
    );
    assert_eq!(
        restored.state().get(&StateKey(vec![1])).unwrap().len(),
        SNAPSHOT_CHUNK_BYTES * 2
    );
    assert!(restored.state().get(&StateKey(vec![2])).is_none());
    let proof = restored.state().prove(&StateKey(vec![1])).unwrap().unwrap();
    assert!(proof.verify(
        first.state_root,
        &StateKey(vec![1]),
        &vec![1; SNAPSHOT_CHUNK_BYTES * 2]
    ));
    assert_eq!(
        restored.commit(&batch(&restored, 3, 10)).unwrap().height,
        first.height + 1
    );
}

#[test]
fn invalid_snapshot_import_preserves_existing_checkpoint_and_state() {
    let mut source = InMemoryStorage::new();
    source.commit(&batch(&source, 1, 10)).unwrap();
    let expected = source
        .commit(&batch(&source, 2, SNAPSHOT_CHUNK_BYTES * 2))
        .unwrap();
    let valid = export(&source, expected);
    let mut target = InMemoryStorage::new();
    let before_cp = target.commit(&batch(&target, 8, 10)).unwrap();
    let before = target.state().export_snapshot();
    let mut cases = vec![vec![]];
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap().last_mut().unwrap() ^= 1;
    cases.push(corrupt);
    let mut wrong_cp = valid.clone();
    wrong_cp[0][10] ^= 1;
    cases.push(wrong_cp);
    let mut truncated = valid.clone();
    truncated.pop();
    cases.push(truncated);
    let mut reordered = valid.clone();
    reordered.swap(1, 2);
    cases.push(reordered);
    let mut appended = valid.clone();
    appended.push(vec![1]);
    cases.push(appended);
    let mut oversized = valid.clone();
    oversized[1] = vec![0; SNAPSHOT_CHUNK_BYTES + 1];
    cases.push(oversized);
    for chunks in cases {
        assert!(
            target
                .import_snapshot(expected, &mut Source(chunks.into_iter()))
                .is_err()
        );
        assert_eq!(target.checkpoint(), Some(&before_cp));
        assert_eq!(target.block_count(), 1);
        assert_eq!(target.state().export_snapshot(), before);
    }
    target
        .import_snapshot(expected, &mut Source(valid.into_iter()))
        .unwrap();
    assert_eq!(target.state().root(), expected.state_root);
    assert_eq!(target.block_count(), 0);
}

#[test]
fn caller_must_supply_the_exact_authenticated_checkpoint() {
    let mut source = InMemoryStorage::new();
    let cp = source.commit(&batch(&source, 1, 1)).unwrap();
    let chunks = export(&source, cp);
    let mut target = InMemoryStorage::new();
    for expected in [
        Checkpoint { height: 1, ..cp },
        Checkpoint {
            block: Hash256::ZERO,
            ..cp
        },
        Checkpoint {
            state_root: Hash256::ZERO,
            ..cp
        },
    ] {
        assert_eq!(
            target.import_snapshot(expected, &mut Source(chunks.clone().into_iter())),
            Err(StorageError::VerificationFailed)
        );
    }
    assert_eq!(target.recover().unwrap(), None);
    assert!(
        source
            .export_snapshot(
                Checkpoint {
                    state_root: Hash256::ZERO,
                    ..cp
                },
                &mut Chunks::default()
            )
            .is_err()
    );
}

#[test]
fn source_io_error_cannot_publish_a_partial_import() {
    struct FailingSource {
        chunks: Source,
        calls: usize,
    }
    impl SnapshotSource for FailingSource {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError> {
            self.calls += 1;
            if self.calls == 3 {
                return Err(StorageError::Io);
            }
            self.chunks.next_chunk()
        }
    }
    let mut source = InMemoryStorage::new();
    let cp = source.commit(&batch(&source, 1, 1)).unwrap();
    let mut target = InMemoryStorage::new();
    let root = target.state().root();
    let mut failing = FailingSource {
        chunks: Source(export(&source, cp).into_iter()),
        calls: 0,
    };
    assert_eq!(
        target.import_snapshot(cp, &mut failing),
        Err(StorageError::Io)
    );
    assert_eq!(target.recover().unwrap(), None);
    assert_eq!(target.state().root(), root);
}

#[test]
fn pruning_preserves_latest_checkpoint_snapshot_and_next_height() {
    let mut storage = InMemoryStorage::new();
    let first = storage.commit(&batch(&storage, 1, 1)).unwrap();
    let last = storage.commit(&batch(&storage, 2, 1)).unwrap();
    storage.prune(u64::MAX).unwrap();
    assert_eq!(storage.recover().unwrap(), Some(last));
    assert!(storage.get_block(&first.block).is_none());
    assert!(
        storage
            .export_snapshot(first, &mut Chunks::default())
            .is_err()
    );
    assert_ne!(export(&storage, last), [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(
        storage.commit(&batch(&storage, 3, 1)).unwrap().height,
        last.height + 1
    );
}

#[test]
fn exhausted_checkpoint_height_never_wraps_to_genesis() {
    let mut source = InMemoryStorage::new();
    let cp = source.commit(&batch(&source, 1, 1)).unwrap();
    let mut chunks = export(&source, cp);
    chunks[0][10..18].copy_from_slice(&u64::MAX.to_le_bytes());
    let trusted = Checkpoint {
        height: u64::MAX,
        ..cp
    };
    let mut target = InMemoryStorage::new();
    target
        .import_snapshot(trusted, &mut Source(chunks.into_iter()))
        .unwrap();
    assert_eq!(
        target.commit(&batch(&source, 2, 1)),
        Err(StorageError::InvalidOrder)
    );
    assert_eq!(target.recover().unwrap(), Some(trusted));
}
