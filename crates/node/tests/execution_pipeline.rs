// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached execution remains equivalent to the serial producer and publishes only on commit.

#[path = "../../consensus/tests/support/potb.rs"]
mod potb_support;
#[allow(dead_code)]
#[path = "../../consensus/tests/support/rotation.rs"]
mod rotation_support;

use consensus::{AuthenticatedCommittee, Committee, CommitteeMember, PotbWeight};
use node::{
    BlockProducer, BlockProposal, ProducerConfig, ProducerError,
    execution_pipeline::{CompletedExecution, ExecutionWorker},
};
use state::{InMemoryState, StateDatabase, StateDiff};
use std::time::{Duration, Instant};
use storage::{Checkpoint, InMemoryStorage, StorageError};
use types::{Address, Hash256, Resources, StateKey, Transaction, TransactionLane, ValidatorId};

fn transaction(index: u64) -> Transaction {
    let mut sender = [1; 32];
    sender[..8].copy_from_slice(&index.to_le_bytes());
    Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id: 7,
        sender: Address(sender),
        nonce: 0,
        expires_at: u64::MAX,
        lane: TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        access_list: vec![],
        resource_limit: Resources {
            compute: 10,
            memory: 1,
            io: 1,
            bandwidth: 1,
        },
        payload: vec![1],
        signature: [0xff; 64],
    }
}

fn producer() -> BlockProducer {
    BlockProducer::new(ProducerConfig::default())
}

fn committee(height: u64) -> AuthenticatedCommittee {
    let key = crypto::blake2s::ed25519_public_key(&[1; 32]);
    AuthenticatedCommittee::new(
        7,
        &Committee {
            height,
            members: vec![CommitteeMember {
                id: ValidatorId(crypto::blake2s_hash(&key).0),
                power: PotbWeight(1),
            }],
        },
        &[key],
    )
    .unwrap()
}

fn complete(worker: &mut ExecutionWorker) -> Result<CompletedExecution, ProducerError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(result) = worker.try_complete() {
            return result;
        }
        assert!(
            Instant::now() < deadline,
            "execution worker did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn received(producer: &BlockProducer, proposal: &BlockProposal) -> CompletedExecution {
    producer
        .prepare_block_execution(proposal.block.clone())
        .execute()
        .unwrap()
}

#[test]
fn detached_production_matches_serial_and_preserves_pending_state() {
    let mut serial = producer();
    let mut detached = producer();
    for nonce in 0..4 {
        serial.submit_transaction(transaction(nonce)).unwrap();
        detached.submit_transaction(transaction(nonce)).unwrap();
    }
    let committee = committee(0);
    let expected = serial.produce_block_for_committee(&committee).unwrap();
    let parent = detached.state().root();
    let mut worker = ExecutionWorker::spawn().unwrap();
    worker
        .submit(detached.prepare_block_production(committee.root()).unwrap())
        .unwrap();
    let actual = detached
        .accept_execution(complete(&mut worker).unwrap())
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        detached.produce_block_for_committee(&committee).unwrap(),
        expected
    );
    assert_eq!(detached.state().root(), parent);
    assert_eq!(detached.pending_count(), 4);
    assert_eq!(detached.height(), 0);

    let mut serial_storage = InMemoryStorage::new();
    let mut detached_storage = InMemoryStorage::new();
    let expected_checkpoint = serial
        .commit_block(&expected, vec![1], &mut serial_storage)
        .unwrap();
    let actual_checkpoint = detached
        .commit_block(&actual, vec![1], &mut detached_storage)
        .unwrap();
    assert_eq!(actual_checkpoint, expected_checkpoint);
    assert_eq!(detached.state().root(), serial.state().root());
    assert_eq!(
        detached_storage.state().root(),
        serial_storage.state().root()
    );
    assert_eq!(detached.pending_count(), 0);
}

#[test]
fn production_is_stale_after_admission_but_received_execution_is_independent_of_pool() {
    let mut local = producer();
    let committee = committee(0);
    let stale = local
        .prepare_block_production(committee.root())
        .unwrap()
        .execute()
        .unwrap();
    let mut remote = producer();
    let empty = remote.produce_block_for_committee(&committee).unwrap();
    let imported = received(&local, &empty);
    local.submit_transaction(transaction(0)).unwrap();
    assert!(local.accept_execution(stale).is_err());
    assert_eq!(local.accept_execution(imported).unwrap(), empty);
    // An imported empty block cannot stand in for local production with pending work.
    assert_eq!(
        local
            .produce_block_for_committee(&committee)
            .unwrap()
            .block
            .transactions
            .len(),
        1
    );

    let current = local
        .prepare_block_production(committee.root())
        .unwrap()
        .execute()
        .unwrap();
    let accepted = local.accept_execution(current).unwrap();
    local.submit_transaction(transaction(1)).unwrap();
    let updated = local.produce_block_for_committee(&committee).unwrap();
    assert_ne!(updated, accepted);
    assert_eq!(updated.block.transactions.len(), 2);
}

#[test]
fn exact_snapshot_rejects_every_config_change() {
    let mut original = producer();
    let proposal = original.produce_block().unwrap();
    let base = ProducerConfig::default();
    let mut configurations = vec![];
    let mut changed = base.clone();
    changed.chain_id += 1;
    configurations.push(changed);
    changed = base.clone();
    changed.max_block_transactions += 1;
    configurations.push(changed);
    changed = base.clone();
    changed.max_transaction_bytes += 1;
    configurations.push(changed);
    changed = base.clone();
    changed.pool_limits.max_transactions += 1;
    configurations.push(changed);
    changed = base.clone();
    changed.pool_limits.max_bytes += 1;
    configurations.push(changed);
    changed = base;
    changed.block_capacity.compute += 1;
    configurations.push(changed);
    for config in configurations {
        let other = BlockProducer::new(config);
        assert!(
            other
                .accept_execution(received(&original, &proposal))
                .is_err()
        );
    }
}

#[test]
fn exact_snapshot_rejects_state_parent_and_height_changes() {
    let mut original = producer();
    let proposal = original.produce_block().unwrap();
    let pending = received(&original, &proposal);
    original
        .commit_block(&proposal, vec![1], &mut InMemoryStorage::new())
        .unwrap();
    assert!(original.accept_execution(pending).is_err());

    let state = InMemoryState::new();
    let checkpoint = Checkpoint {
        height: 0,
        block: Hash256([4; 32]),
        state_root: state.root(),
    };
    let mut source =
        BlockProducer::from_checkpoint(ProducerConfig::default(), Some(checkpoint), state.clone())
            .unwrap();
    let proposal = source.produce_block().unwrap();
    let different_parent = BlockProducer::from_checkpoint(
        ProducerConfig::default(),
        Some(Checkpoint {
            block: Hash256([5; 32]),
            ..checkpoint
        }),
        state.clone(),
    )
    .unwrap();
    assert!(
        different_parent
            .accept_execution(received(&source, &proposal))
            .is_err()
    );
    let mut changed_state = state;
    let mut diff = StateDiff::new();
    diff.put(StateKey(vec![44]), vec![7]);
    changed_state.commit(changed_state.root(), &[diff]).unwrap();
    let different_state = BlockProducer::from_checkpoint(
        ProducerConfig::default(),
        Some(Checkpoint {
            state_root: changed_state.root(),
            ..checkpoint
        }),
        changed_state,
    )
    .unwrap();
    assert!(
        different_state
            .accept_execution(received(&source, &proposal))
            .is_err()
    );
}

#[test]
fn changing_public_proposal_cannot_change_accepted_execution() {
    let mut source = producer();
    source.submit_transaction(transaction(0)).unwrap();
    let proposal = source.produce_block().unwrap();
    let mut receiver = producer();
    let accepted = receiver
        .accept_execution(received(&receiver, &proposal))
        .unwrap();
    let root = receiver.state().root();
    let mut changed = accepted.clone();
    changed.outputs[0].diff.put(StateKey(vec![99]), vec![42]);
    changed.outputs[0].receipt.output_root = changed.outputs[0].diff.commitment();
    changed.block.header.receipts_root =
        node::compute_receipts_root(&[changed.outputs[0].receipt.clone()]);
    changed.state_root = receiver
        .state()
        .prepare(root, &[changed.outputs[0].diff.clone()])
        .unwrap()
        .root();
    changed.block.header.state_root = changed.state_root;
    assert!(receiver.validate_proposal(&changed).is_err());
    let mut storage = InMemoryStorage::new();
    assert!(
        receiver
            .commit_block(&changed, vec![1], &mut storage)
            .is_err()
    );
    assert_eq!(receiver.state().root(), root);
    assert!(storage.checkpoint().is_none());
    receiver
        .commit_block(&accepted, vec![1], &mut storage)
        .unwrap();
}

#[test]
fn storage_failure_keeps_detached_execution_retryable() {
    let mut source = producer();
    source.submit_transaction(transaction(0)).unwrap();
    let expected = source.produce_block().unwrap();
    let proposal = source
        .accept_execution(received(&source, &expected))
        .unwrap();
    let mut occupied = InMemoryStorage::new();
    let mut other = producer();
    let empty = other.produce_block().unwrap();
    other.commit_block(&empty, vec![1], &mut occupied).unwrap();
    let root = source.state().root();
    assert!(matches!(
        source.commit_block(&proposal, vec![1], &mut occupied),
        Err(ProducerError::Storage(StorageError::InvalidOrder))
    ));
    assert_eq!(source.state().root(), root);
    assert_eq!(source.pending_count(), 1);
    source.validate_proposal(&proposal).unwrap();
    source
        .commit_block(&proposal, vec![1], &mut InMemoryStorage::new())
        .unwrap();
    assert_eq!(source.state().root(), expected.state_root);
    assert_eq!(source.pending_count(), 0);
}

#[test]
fn worker_has_one_slot_and_continues_after_execution_failure() {
    let mut source = producer();
    let first = source.produce_block().unwrap();
    let mut worker = ExecutionWorker::spawn().unwrap();
    assert!(!worker.busy());
    assert!(worker.try_complete().is_none());
    worker
        .submit(source.prepare_block_execution(first.block.clone()))
        .unwrap();
    assert!(worker.busy());
    assert!(
        worker
            .submit(source.prepare_block_execution(first.block.clone()))
            .is_err()
    );
    assert_eq!(
        source
            .accept_execution(complete(&mut worker).unwrap())
            .unwrap(),
        first
    );
    assert!(!worker.busy());

    let mut invalid = first.block.clone();
    invalid.header.state_root = Hash256([99; 32]);
    worker
        .submit(source.prepare_block_execution(invalid))
        .unwrap();
    assert!(complete(&mut worker).is_err());
    assert!(!worker.busy());

    source.submit_transaction(transaction(0)).unwrap();
    let second = source.produce_block().unwrap();
    worker
        .submit(source.prepare_block_execution(second.block.clone()))
        .unwrap();
    assert_eq!(
        source
            .accept_execution(complete(&mut worker).unwrap())
            .unwrap(),
        second
    );
    assert_ne!(first, second);
    // Drop also joins an in-flight real job with an uncollected completion.
    worker
        .submit(source.prepare_block_execution(second.block))
        .unwrap();
    drop(worker);
    assert_eq!(source.height(), 0);
    assert_eq!(source.pending_count(), 1);
}

#[test]
fn received_rotation_job_uses_prepared_transition_snapshot() {
    let (genesis, keys) = rotation_support::fixture();
    let trusted = consensus::rotation::HandoffVerifier::new(&genesis, &keys).unwrap();
    let state = genesis.materialize().unwrap();
    let checkpoint = Checkpoint {
        height: 0,
        block: trusted.parent(),
        state_root: state.root(),
    };
    let create = || {
        BlockProducer::from_checkpoint(
            ProducerConfig {
                block_capacity: genesis.capacity,
                ..ProducerConfig::default()
            },
            Some(checkpoint),
            state.clone(),
        )
        .unwrap()
        .with_rotation(&trusted)
        .unwrap()
    };
    let mut source = create();
    source
        .set_vrf_batch(rotation_support::batch(trusted.current()))
        .unwrap();
    let proposal = source.produce_block().unwrap();
    let mut receiver = create();
    let prepared = received(&receiver, &proposal);
    assert!(receiver.accept_execution(prepared).is_err());
    let prepared = received(&receiver, &proposal);
    receiver.prepare_received_vrf(&proposal.block).unwrap();
    assert_eq!(receiver.accept_execution(prepared).unwrap(), proposal);
    assert_eq!(
        receiver
            .execute_received_block(proposal.block.clone())
            .unwrap(),
        proposal
    );
    assert_eq!(receiver.state().root(), state.root());
}

#[test]
fn received_potb_job_uses_prepared_transition_snapshot() {
    let (profile, keys) = potb_support::fixture();
    let trusted = consensus::potb_transition::PotbVerifier::new(&profile, &keys).unwrap();
    let state = profile.materialize(&keys).unwrap();
    let checkpoint = Checkpoint {
        height: 0,
        block: trusted.parent(),
        state_root: state.root(),
    };
    let create = || {
        BlockProducer::from_checkpoint(
            ProducerConfig {
                block_capacity: profile.genesis().capacity,
                chain_id: profile.genesis().chain_id,
                ..ProducerConfig::default()
            },
            Some(checkpoint),
            state.clone(),
        )
        .unwrap()
        .with_potb(&trusted)
        .unwrap()
    };
    let mut source = create();
    source
        .set_potb_batch(potb_support::batch(trusted.current()))
        .unwrap();
    let proposal = source.produce_block().unwrap();
    let mut receiver = create();
    let prepared = received(&receiver, &proposal);
    assert!(receiver.accept_execution(prepared).is_err());
    let prepared = received(&receiver, &proposal);
    receiver.prepare_received_vrf(&proposal.block).unwrap();
    assert_eq!(receiver.accept_execution(prepared).unwrap(), proposal);
    assert_eq!(receiver.state().root(), state.root());
}
