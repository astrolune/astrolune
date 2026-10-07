// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit rotating execution, reserved resources, atomic publication and recovery.

#[path = "../../consensus/tests/support/rotation.rs"]
mod support;

use consensus::rotation::{HandoffVerifier, VrfBatch, committee_state_key};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use node::{BlockProducer, ProducerConfig};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::{ChainStorage, FileBackedStorage};
use transaction::{
    ContractAction, ContractPayload, Payment, address_from_public_key, contract_address,
    contract_code_key, signing_hash,
};
use types::{Address, Resources, Transaction, TransactionLane};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn funded() -> (genesis::Genesis, Vec<[u8; 32]>) {
    let (mut genesis, keys) = support::fixture();
    genesis.runtime_version = 2;
    genesis.allocations = [98, 99]
        .map(|seed| genesis::Allocation {
            address: address_from_public_key(&ed25519_public_key(&[seed; 32])),
            amount: 1_000_000,
        })
        .to_vec();
    genesis
        .allocations
        .sort_by_key(|allocation| allocation.address);
    (genesis, keys)
}
fn storage(genesis: &genesis::Genesis, archive: bool) -> (Fixture, ChainStorage) {
    let dir = Fixture(std::env::temp_dir().join(format!(
        "astrolune-rotation-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let path = dir.0.join("chain.bin");
    if archive {
        FileBackedStorage::open(&path)
            .unwrap()
            .initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap(),
            )
            .unwrap();
    }
    let mut storage = ChainStorage::open(path).unwrap();
    if storage.checkpoint().is_none() {
        storage
            .initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap(),
            )
            .unwrap();
    }
    (dir, storage)
}
fn config(genesis: &genesis::Genesis) -> ProducerConfig {
    ProducerConfig {
        chain_id: genesis.chain_id,
        block_capacity: genesis.capacity,
        ..ProducerConfig::default()
    }
}
fn open_producer(
    genesis: &genesis::Genesis,
    storage: &ChainStorage,
    trusted: &HandoffVerifier,
) -> BlockProducer {
    BlockProducer::from_checkpoint(
        config(genesis),
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap()
    .with_rotation(trusted)
    .unwrap()
}
fn payment(seed: u8) -> Transaction {
    let public_key = ed25519_public_key(&[seed; 32]);
    let sender = address_from_public_key(&public_key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 7,
        sender,
        nonce: 0,
        expires_at: 100,
        lane: TransactionLane::Payments,
        resource_prices: execution::PAYMENT_PRICES,
        access_list,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[seed; 32], &signing_hash(&tx).0);
    tx
}
fn deployment() -> Transaction {
    let mut tx = payment(98);
    let code = wat::parse_str("(module (memory (export \"memory\") 1 1) (func (export \"call\") (result i32) i32.const 0))").unwrap();
    tx.lane = TransactionLane::Contracts;
    tx.payload = ContractPayload {
        public_key: ed25519_public_key(&[98; 32]),
        action: ContractAction::Deploy(code),
    }
    .to_bytes();
    tx.access_list = vec![
        state::account_key(tx.sender),
        contract_code_key(contract_address(7, tx.sender, 0)),
    ];
    tx.access_list.sort();
    tx.resource_limit = Resources {
        compute: 10_000,
        memory: 65_568,
        io: 10_000,
        bandwidth: 4096,
    };
    tx.signature = ed25519_sign(&[98; 32], &signing_hash(&tx).0);
    tx
}

#[test]
fn system_payment_and_contract_commit_together_and_recover_after_rotations() {
    for archive in [false, true] {
        let (genesis, keys) = funded();
        let (dir, mut storage) = storage(&genesis, archive);
        let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
        let mut producer = open_producer(&genesis, &storage, &trusted);
        let payment = payment(99);
        let deployment = deployment();
        producer.submit_transaction(payment.clone()).unwrap();
        producer.submit_transaction(deployment.clone()).unwrap();
        for height in 1..=3 {
            assert!(
                producer.produce_block().is_err(),
                "fresh height needs all VRF proofs"
            );
            let contributions = support::batch(trusted.current());
            let partial = VrfBatch::new(contributions.entries()[..3].to_vec()).unwrap();
            assert!(producer.set_vrf_batch(partial).is_err());
            producer.set_vrf_batch(contributions).unwrap();
            let before = producer.state().root();
            let context = trusted.current().context().unwrap();
            let proposal = producer.produce_block_for_committee(&context).unwrap();
            assert_eq!(proposal, producer.produce_block().unwrap());
            assert_eq!(producer.state().root(), before);
            assert_eq!(proposal.block.transactions[0].lane, TransactionLane::System);
            assert_eq!(
                proposal,
                producer
                    .execute_received_block(proposal.block.clone())
                    .unwrap()
            );
            if height == 1 {
                assert_eq!(proposal.block.transactions.len(), 3);
                assert!(
                    producer
                        .submit_transaction(proposal.block.transactions[0].clone())
                        .is_err()
                );
            }
            let certificate = support::sign(trusted.current(), &proposal.block.header);
            let handoff = producer.rotation_handoff(&proposal, &certificate).unwrap();
            assert!(
                producer
                    .commit_block(&proposal, vec![0; 1], &mut storage)
                    .is_err()
            );
            producer
                .commit_certified_block(&proposal, &certificate, &context, &mut storage)
                .unwrap();
            assert_eq!(
                node::handoff::read_handoff(&storage, height).unwrap(),
                Some(handoff.clone())
            );
            trusted.apply(&handoff).unwrap();
            assert_eq!(producer.rotation_state(), Some(trusted.current()));
            assert_eq!(
                producer.state().get(&committee_state_key()),
                Some(trusted.current().to_bytes().unwrap().as_slice())
            );
            assert_eq!(storage.state().root(), producer.state().root());
        }
        assert_eq!(producer.pending_count(), 0);
        assert!(
            storage
                .state()
                .get(&contract_code_key(contract_address(
                    7,
                    deployment.sender,
                    0
                )))
                .is_some()
        );
        let snapshot = state::StateDatabase::snapshot(storage.state()).unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            123
        );
        drop(producer);
        drop(storage);
        let storage = ChainStorage::open(dir.0.join("chain.bin")).unwrap();
        let mut unbound = BlockProducer::from_checkpoint(
            config(&genesis),
            storage.checkpoint().copied(),
            storage.state().clone(),
        )
        .unwrap();
        assert!(unbound.produce_block().is_err());
        assert!(unbound.submit_transaction(payment.clone()).is_err());
        let (mut restored, recovered) =
            BlockProducer::recover_rotation(config(&genesis), &genesis, &keys, &storage).unwrap();
        assert_eq!(recovered, trusted);
        assert_eq!(restored.rotation_state(), Some(trusted.current()));
        assert_eq!(restored.height(), 4);
        verify_recovered_batch(&mut restored, &recovered, &storage);
        verify_retained_stream(&genesis, &keys, &storage, &trusted);
    }
}

#[test]
fn failed_publication_preserves_committee_state_batch_and_pending_transactions() {
    let (genesis, keys) = funded();
    let (dir, mut storage) = storage(&genesis, true);
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut producer = open_producer(&genesis, &storage, &trusted);
    producer.submit_transaction(payment(99)).unwrap();
    producer
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    let certificate = support::sign(trusted.current(), &proposal.block.header);
    let before = producer.state().root();
    std::fs::create_dir(dir.0.join("chain.bin.pending")).unwrap();
    assert!(
        producer
            .commit_block(&proposal, certificate.encode().unwrap(), &mut storage)
            .is_err()
    );
    assert_eq!(producer.height(), 1);
    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.rotation_state(), Some(trusted.current()));
    assert_eq!(producer.pending_count(), 1);
    assert_eq!(producer.produce_block().unwrap(), proposal);
    assert_eq!(storage.checkpoint().unwrap().height, 0);
    assert!(node::handoff::read_handoff(&storage, 1).unwrap().is_none());
    std::fs::remove_dir(dir.0.join("chain.bin.pending")).unwrap();
    producer
        .commit_block(&proposal, certificate.encode().unwrap(), &mut storage)
        .unwrap();
    assert_eq!(producer.height(), 2);
}

#[test]
fn system_envelope_budget_and_recovery_anchor_cannot_be_substituted() {
    let (genesis, keys) = funded();
    let (_dir, storage) = storage(&genesis, false);
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut producer = open_producer(&genesis, &storage, &trusted);
    producer
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    for mutation in 0..7 {
        let mut block = proposal.block.clone();
        match mutation {
            0 => block.transactions[0].nonce += 1,
            1 => block.transactions[0].signature[0] ^= 1,
            2 => block.transactions[0].resource_limit.compute -= 1,
            3 => block.transactions[0].payload.pop().map_or((), |_| ()),
            4 => block.transactions[0].access_list.clear(),
            5 => block.transactions.clear(),
            _ => block.transactions.push(block.transactions[0].clone()),
        }
        block.header.transactions_root = node::compute_transactions_root(&block.transactions);
        assert!(producer.execute_received_block(block).is_err());
    }
    let mut advanced = trusted.clone();
    advanced
        .apply(&support::handoff(&genesis, &trusted))
        .unwrap();
    assert!(
        BlockProducer::from_checkpoint(
            config(&genesis),
            storage.checkpoint().copied(),
            storage.state().clone()
        )
        .unwrap()
        .with_rotation(&advanced)
        .is_err()
    );
    let mut insufficient = genesis.clone();
    insufficient.capacity.compute = 39_999;
    let fresh = HandoffVerifier::new(&insufficient, &keys).unwrap();
    let checkpoint = storage::Checkpoint {
        height: 0,
        block: insufficient.commitment().unwrap(),
        state_root: insufficient.materialize().unwrap().root(),
    };
    assert!(
        BlockProducer::from_checkpoint(
            config(&insufficient),
            Some(checkpoint),
            insufficient.materialize().unwrap()
        )
        .unwrap()
        .with_rotation(&fresh)
        .is_err()
    );
}

#[test]
fn rotating_recovery_rejects_a_well_formed_storage_record_without_a_quorum() {
    use storage::NodeStorage;
    let (genesis, keys) = funded();
    let (_dir, mut storage) = storage(&genesis, false);
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut producer = open_producer(&genesis, &storage, &trusted);
    producer
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    storage
        .commit(&storage::CommitBatch {
            block: proposal.block,
            finality_certificate: vec![1],
            effects: None,
            state_diffs: proposal
                .outputs
                .into_iter()
                .map(|output| output.diff)
                .collect(),
        })
        .unwrap();
    assert_eq!(storage.checkpoint().unwrap().height, 1);
    assert!(BlockProducer::recover_rotation(config(&genesis), &genesis, &keys, &storage).is_err());
}

#[test]
fn application_admission_cannot_spend_reserved_system_capacity_or_the_system_slot() {
    for dimension in 0..5 {
        let (mut genesis, keys) = funded();
        match dimension {
            0 => genesis.capacity.compute = 40_000,
            1 => genesis.capacity.memory = 16 * 1024,
            2 => genesis.capacity.io = 4096,
            3 => genesis.capacity.bandwidth = 12 * 1024,
            _ => {}
        }
        let (_dir, storage) = storage(&genesis, false);
        let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
        let mut config = config(&genesis);
        if dimension == 4 {
            config.max_block_transactions = 1;
        }
        let mut producer = BlockProducer::from_checkpoint(
            config,
            storage.checkpoint().copied(),
            storage.state().clone(),
        )
        .unwrap()
        .with_rotation(&trusted)
        .unwrap();
        assert!(
            producer.submit_transaction(payment(99)).is_err(),
            "dimension {dimension}"
        );
        assert_eq!(producer.pending_count(), 0);
        producer
            .set_vrf_batch(support::batch(trusted.current()))
            .unwrap();
        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
        assert!(proposal.resources_used.fits_in(genesis.capacity));
        assert_eq!(
            producer
                .execute_received_block(proposal.block.clone())
                .unwrap(),
            proposal
        );
    }
}

fn verify_retained_stream(
    genesis: &genesis::Genesis,
    keys: &[[u8; 32]],
    storage: &ChainStorage,
    trusted: &HandoffVerifier,
) {
    let mut stream = HandoffVerifier::new(genesis, keys).unwrap();
    assert!(node::handoff::read_handoff(storage, 0).unwrap().is_none());
    assert!(node::handoff::read_handoff(storage, 4).unwrap().is_none());
    for height in 1..=3 {
        let handoff = node::handoff::read_handoff(storage, height)
            .unwrap()
            .unwrap();
        stream.apply(&handoff).unwrap();
    }
    assert_eq!(&stream, trusted);
}

#[test]
fn verified_transition_cache_matches_revalidation_and_cannot_cross_a_height() {
    let (genesis, keys) = funded();
    let (_dir, mut storage) = storage(&genesis, false);
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut cached = open_producer(&genesis, &storage, &trusted);
    let reference = open_producer(&genesis, &storage, &trusted);
    cached.submit_transaction(payment(99)).unwrap();
    cached
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = cached.produce_block().unwrap();
    assert_eq!(
        cached
            .execute_received_block(proposal.block.clone())
            .unwrap(),
        reference
            .execute_received_block(proposal.block.clone())
            .unwrap()
    );
    let mut imported = open_producer(&genesis, &storage, &trusted);
    imported.prepare_received_vrf(&proposal.block).unwrap();
    assert_eq!(
        imported
            .execute_received_block(proposal.block.clone())
            .unwrap(),
        proposal
    );
    for mutation in 0..4 {
        let mut changed = proposal.block.clone();
        match mutation {
            0 => changed.header.parent.0[0] ^= 1,
            1 => changed.header.height += 1,
            2 => changed.transactions[0].payload[60] ^= 1,
            _ => {
                changed.transactions[0].payload.pop();
            }
        }
        assert!(imported.prepare_received_vrf(&changed).is_err());
        assert!(imported.execute_received_block(changed.clone()).is_err());
        assert!(reference.execute_received_block(changed).is_err());
        assert_eq!(
            imported
                .execute_received_block(proposal.block.clone())
                .unwrap(),
            proposal
        );
    }
    let certificate = support::sign(trusted.current(), &proposal.block.header);
    let handoff = cached.rotation_handoff(&proposal, &certificate).unwrap();
    cached
        .commit_certified_block(
            &proposal,
            &certificate,
            &trusted.current().context().unwrap(),
            &mut storage,
        )
        .unwrap();
    trusted.apply(&handoff).unwrap();
    assert!(cached.produce_block().is_err());
    assert!(cached.prepare_received_vrf(&proposal.block).is_err());
    cached
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    assert_eq!(cached.produce_block().unwrap().block.header.height, 2);
}

#[test]
#[ignore = "local comparative measurement; correctness is checked separately without timing assumptions"]
fn measure_verified_transition_cache() {
    let (genesis, keys) = funded();
    let (_dir, storage) = storage(&genesis, false);
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut cached = open_producer(&genesis, &storage, &trusted);
    let reference = open_producer(&genesis, &storage, &trusted);
    cached.submit_transaction(payment(99)).unwrap();
    cached.submit_transaction(deployment()).unwrap();
    cached
        .set_vrf_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = cached.produce_block().unwrap();
    for (name, producer) in [("reference", &reference), ("cached", &cached)] {
        let start = std::time::Instant::now();
        for _ in 0..20 {
            let actual = producer
                .execute_received_block(proposal.block.clone())
                .unwrap();
            assert_eq!(actual, proposal);
            std::hint::black_box(actual);
        }
        println!(
            "{name}: {} microseconds for 20 identical mixed-lane blocks",
            start.elapsed().as_micros()
        );
    }
}

fn verify_recovered_batch(
    restored: &mut BlockProducer,
    recovered: &HandoffVerifier,
    storage: &ChainStorage,
) {
    assert!(restored.produce_block().is_err());
    let last = node::handoff::read_handoff(storage, 3).unwrap().unwrap();
    assert!(restored.set_vrf_batch(last.contributions).is_err());
    restored
        .set_vrf_batch(support::batch(recovered.current()))
        .unwrap();
    assert_eq!(restored.produce_block().unwrap().block.header.height, 4);
}
