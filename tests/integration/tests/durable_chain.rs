// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Producer-to-durable-storage conformance across repeated storage reopen.

use std::fs;
use std::path::PathBuf;

use node::{BlockProducer, FullNodeService, NodeService, ProducerConfig, ProducerError};
use storage::{Checkpoint, FileBackedStorage, NodeStorage, StorageError};
use types::{Address, Hash256, Resources, Transaction};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        // The test owns this unique temporary directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn restarted_service_matches_uninterrupted_execution() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("astrolune-service-restart-{}", std::process::id())),
    );
    fs::create_dir(&fixture.0).unwrap();

    let path = fixture.0.join("chain.bin");
    let mut reference = FullNodeService::new(ProducerConfig::default());

    for height in 0..20u8 {
        let mut service = FullNodeService::open(ProducerConfig::default(), &path).unwrap();
        assert_eq!(service.height(), u64::from(height));
        assert_eq!(service.pending_transactions(), 0);
        assert_eq!(service.finalized_block(), reference.finalized_block());

        let transaction = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: Address([height; 32]),
            nonce: 0,
            access_list: vec![],
            resource_limit: Resources::ZERO,
            payload: vec![height],
            signature: [1; 64],
        };
        reference.submit_transaction(transaction.clone()).unwrap();
        service.submit_transaction(transaction).unwrap();

        for _ in 0..5 {
            reference.advance().unwrap();
            service.advance().unwrap();
        }

        let checkpoint = service.storage().checkpoint().unwrap();
        assert_eq!(Some(checkpoint), reference.storage().checkpoint());
        assert_eq!(
            service.storage().get_block(&checkpoint.block),
            reference.storage().get_block(&checkpoint.block)
        );
        assert_eq!(
            service.storage().state().export_snapshot(),
            reference.storage().state().export_snapshot()
        );
        assert!(!service.storage().state().is_empty());
    }
}

#[test]
fn recovery_rejects_mismatched_state_and_exhausted_height() {
    let state = state::InMemoryState::new();
    let checkpoint = Checkpoint {
        height: 10,
        block: Hash256([1; 32]),
        state_root: Hash256::ZERO,
    };
    assert!(matches!(
        BlockProducer::from_checkpoint(ProducerConfig::default(), Some(checkpoint), state.clone()),
        Err(ProducerError::Storage(StorageError::VerificationFailed))
    ));

    let checkpoint = Checkpoint {
        height: u64::MAX,
        state_root: state.root(),
        ..checkpoint
    };
    assert!(matches!(
        BlockProducer::from_checkpoint(ProducerConfig::default(), Some(checkpoint), state),
        Err(ProducerError::Storage(StorageError::InvalidOrder))
    ));

    let mut diff = state::StateDiff::new();
    diff.put(types::StateKey::new(vec![1]).unwrap(), vec![2]);
    let empty = state::InMemoryState::new();
    let populated = empty.prepare(empty.root(), &[diff]).unwrap();
    assert!(matches!(
        BlockProducer::from_checkpoint(ProducerConfig::default(), None, populated),
        Err(ProducerError::Storage(StorageError::VerificationFailed))
    ));
}

#[test]
fn produced_blocks_recover_with_identical_bodies_certificates_and_state() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("astrolune-producer-durable-{}", std::process::id())),
    );
    fs::create_dir(&fixture.0).unwrap();

    let path = fixture.0.join("chain.bin");
    let mut producer =
        BlockProducer::with_account(Address([1; 32]), 0, 1000, ProducerConfig::default());

    for height in 0..4 {
        producer
            .submit_transaction(Transaction {
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
                payload: vec![1, 2, 3],
                signature: [1; 64],
            })
            .unwrap();

        let proposal = producer.produce_block().unwrap();

        let mut storage = FileBackedStorage::open(&path).unwrap();
        let checkpoint = producer
            .commit_block(&proposal, vec![2; 64], &mut storage)
            .unwrap();
        drop(storage);

        let mut storage = FileBackedStorage::open(&path).unwrap();
        assert_eq!(storage.recover().unwrap(), Some(checkpoint));
        assert_eq!(storage.get_block(&checkpoint.block), Some(&proposal.block));
        assert_eq!(
            storage.get_certificate(&checkpoint.block),
            Some([2; 64].as_slice())
        );
        assert_eq!(
            storage.state().export_snapshot(),
            producer.state().export_snapshot()
        );
        assert_eq!(producer.pending_count(), 0);
    }
}
