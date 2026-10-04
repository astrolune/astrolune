// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! System policy and application state share one verified durable commit.

#![allow(clippy::too_many_lines)]

#[path = "../../consensus/tests/support/potb.rs"]
mod support;

use consensus::potb_transition::{PotbBatch, PotbConfiguration, PotbVerifier};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use node::{BlockProducer, ProducerConfig};
use state::StateDatabase;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::{ChainStorage, FileBackedStorage, NodeStorage};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{Address, Resources, Transaction, TransactionLane};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
fn fixture() -> (PotbConfiguration, Vec<[u8; 32]>) {
    let (base, keys) = support::fixture();
    let mut genesis = base.genesis().clone();
    genesis.allocations.push(genesis::Allocation {
        address: address_from_public_key(&ed25519_public_key(&[98; 32])),
        amount: 100_000,
    });
    (
        PotbConfiguration::new(genesis, base.policy()).unwrap(),
        keys,
    )
}
fn config(profile: &PotbConfiguration) -> ProducerConfig {
    ProducerConfig {
        chain_id: profile.genesis().chain_id,
        block_capacity: profile.genesis().capacity,
        ..ProducerConfig::default()
    }
}
fn storage(
    profile: &PotbConfiguration,
    keys: &[[u8; 32]],
    archive: bool,
) -> (Directory, ChainStorage) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = Directory(std::env::temp_dir().join(format!(
        "astrolune-potb-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let path = dir.0.join("chain.bin");
    if archive {
        FileBackedStorage::open(&path)
            .unwrap()
            .initialize_genesis(profile.commitment(), profile.materialize(keys).unwrap())
            .unwrap();
    }
    let mut storage = ChainStorage::open(path).unwrap();
    if storage.checkpoint().is_none() {
        storage
            .initialize_genesis(profile.commitment(), profile.materialize(keys).unwrap())
            .unwrap();
    }
    (dir, storage)
}
fn producer(
    profile: &PotbConfiguration,
    storage: &ChainStorage,
    trusted: &PotbVerifier,
) -> BlockProducer {
    BlockProducer::from_checkpoint(
        config(profile),
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap()
    .with_potb(trusted)
    .unwrap()
}
fn payment(profile: &PotbConfiguration, nonce: u64) -> Transaction {
    let key = ed25519_public_key(&[98; 32]);
    let sender = address_from_public_key(&key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: profile.genesis().chain_id,
        sender,
        nonce,
        expires_at: 100,
        lane: TransactionLane::Payments,
        resource_prices: execution::PAYMENT_PRICES,
        access_list,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key: key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[98; 32], &signing_hash(&tx).0);
    tx
}

#[test]
fn governed_fees_capacity_boundary_and_recovery_match_serial_and_parallel() {
    for archive in [false, true] {
        let (base, keys) = fixture();
        let profile = support::governed(base);
        let (dir, mut store) = storage(&profile, &keys, archive);
        let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
        let mut producer = producer(&profile, &store, &trusted);
        let certificate = support::parameters(trusted.current(), trusted.parent());
        let prices = certificate.request().prices;
        let capacity = certificate.request().capacity;
        let mut spent = 0;
        for height in 1..=4 {
            let active_prices = if height < 3 {
                execution::PAYMENT_PRICES
            } else {
                prices
            };
            assert_eq!(producer.current_prices(), active_prices);
            let mut tx = payment(&profile, height - 1);
            if height >= 3 {
                assert!(producer.submit_transaction(tx.clone()).is_err());
                tx.resource_prices = prices;
                tx.signature = ed25519_sign(&[98; 32], &signing_hash(&tx).0);
            }
            spent += 123
                + execution::payment_resources(&tx)
                    .unwrap()
                    .checked_cost(active_prices)
                    .unwrap();
            let context = transaction::ValidationContext {
                chain_id: profile.genesis().chain_id,
                next_height: height,
                max_transaction_bytes: 65536,
            };
            let mut outputs = None;
            for workers in [1, 2, 8] {
                let mut state = producer.state().clone();
                let root = state.root();
                let result = execution::execute_parallel(
                    &mut state,
                    &[tx.clone()],
                    root,
                    context,
                    execution::ExecutionPolicy {
                        capacity,
                        prices: active_prices,
                        contracts: true,
                    },
                    workers,
                )
                .unwrap();
                if let Some(expected) = &outputs {
                    assert_eq!(&result, expected);
                } else {
                    outputs = Some(result);
                }
            }
            producer.submit_transaction(tx).unwrap();
            let mut batch = support::batch(trusted.current());
            if height == 1 {
                batch = batch.with_governance(certificate.clone()).unwrap();
            }
            producer.set_potb_batch(batch).unwrap();
            let proposal = producer.produce_block().unwrap();
            assert_eq!(proposal.block.transactions.len(), 2);
            assert_eq!(
                proposal.block.header.capacity,
                if height < 3 {
                    profile.genesis().capacity
                } else {
                    capacity
                }
            );
            let finality =
                support::certificate(trusted.current().committee(), &proposal.block.header);
            let handoff = producer.potb_handoff(&proposal, &finality).unwrap();
            producer
                .commit_certified_block(
                    &proposal,
                    &finality,
                    &trusted.current().committee().context().unwrap(),
                    &mut store,
                )
                .unwrap();
            trusted.apply(&handoff).unwrap();
            assert_eq!(producer.potb_state(), Some(trusted.current()));
            let account = state::read_account(
                producer.state().snapshot().unwrap().as_ref(),
                address_from_public_key(&ed25519_public_key(&[98; 32])),
            )
            .unwrap()
            .unwrap();
            assert_eq!(account.balance, 100_000 - spent);
            let (recovered, authority) =
                BlockProducer::recover_potb(config(&profile), &profile, &keys, &store).unwrap();
            assert_eq!(recovered.current_prices(), producer.current_prices());
            assert_eq!(recovered.state().root(), producer.state().root());
            assert_eq!(authority, trusted);
            producer = recovered;
        }
        drop(store);
        let reopened = ChainStorage::open(dir.0.join("chain.bin")).unwrap();
        let (recovered, authority) =
            BlockProducer::recover_potb(config(&profile), &profile, &keys, &reopened).unwrap();
        assert_eq!(recovered.current_prices(), prices);
        assert_eq!(authority.current().committee().capacity(), capacity);
    }
}

#[test]
fn payments_policy_admission_and_evidence_recover_from_both_storage_backends() {
    for archive in [false, true] {
        let (profile, keys) = fixture();
        let (dir, mut storage) = storage(&profile, &keys, archive);
        let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
        let mut producer = producer(&profile, &storage, &trusted);
        let first = trusted.current().committee().clone();
        let mut roots = vec![];
        for height in 1..=4 {
            let mut evidence = vec![];
            let mut admissions = vec![];
            if height == 2 {
                evidence.push(support::evidence(trusted.current(), &first, &roots, 1));
                admissions.push(support::admission(trusted.current(), trusted.parent(), 99));
            }
            let batch = PotbBatch::new(
                support::contributions(trusted.current()),
                evidence,
                admissions,
            )
            .unwrap();
            producer
                .submit_transaction(payment(&profile, height - 1))
                .unwrap();
            producer.set_potb_batch(batch).unwrap();
            let before = producer.state().root();
            let proposal = producer.produce_block().unwrap();
            assert_eq!(proposal.block.transactions.len(), 2);
            assert_eq!(proposal.block.transactions[0].lane, TransactionLane::System);
            assert_eq!(producer.state().root(), before);
            assert_eq!(producer.potb_state(), Some(trusted.current()));
            let reference = BlockProducer::from_checkpoint(
                config(&profile),
                storage.checkpoint().copied(),
                storage.state().clone(),
            )
            .unwrap()
            .with_potb(&trusted)
            .unwrap();
            assert_eq!(
                reference
                    .execute_received_block(proposal.block.clone())
                    .unwrap(),
                proposal
            );
            let certificate =
                support::certificate(trusted.current().committee(), &proposal.block.header);
            let handoff = producer.potb_handoff(&proposal, &certificate).unwrap();
            roots.push(trusted.current().committee().context().unwrap().root());
            producer
                .commit_certified_block(
                    &proposal,
                    &certificate,
                    &trusted.current().committee().context().unwrap(),
                    &mut storage,
                )
                .unwrap();
            trusted.apply(&handoff).unwrap();
            assert_eq!(producer.potb_state(), Some(trusted.current()));
            assert_eq!(storage.state().root(), producer.state().root());
            assert_eq!(producer.pending_count(), 0);
            assert!(producer.produce_block().is_err());
            assert_eq!(
                storage
                    .read_receipts(height)
                    .unwrap()
                    .unwrap()
                    .effects
                    .receipts
                    .len(),
                2
            );
        }
        let snapshot = producer.state().snapshot().unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            492
        );
        let expected = producer.state().root();
        drop(producer);
        drop(storage);
        let storage = ChainStorage::open(dir.0.join("chain.bin")).unwrap();
        let (recovered, authority) =
            BlockProducer::recover_potb(config(&profile), &profile, &keys, &storage).unwrap();
        assert_eq!(authority, trusted);
        assert_eq!(recovered.state().root(), expected);
        let mut unbound = BlockProducer::from_checkpoint(
            config(&profile),
            storage.checkpoint().copied(),
            storage.state().clone(),
        )
        .unwrap();
        assert!(unbound.produce_block().is_err());
        assert!(unbound.submit_transaction(payment(&profile, 4)).is_err());
        let legacy = consensus::rotation::HandoffVerifier::new(profile.genesis(), &keys).unwrap();
        assert!(unbound.with_rotation(&legacy).is_err());
        assert!(
            BlockProducer::recover_rotation(config(&profile), profile.genesis(), &keys, &storage)
                .is_err()
        );
        let mut changed = profile.policy();
        changed.age_increment += 1;
        let foreign = PotbConfiguration::new(profile.genesis().clone(), changed).unwrap();
        assert!(BlockProducer::recover_potb(config(&foreign), &foreign, &keys, &storage).is_err());
    }
}

#[test]
fn failed_write_preserves_authority_batch_and_pool_for_retry() {
    let (profile, keys) = fixture();
    let (dir, mut storage) = storage(&profile, &keys, true);
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let mut producer = producer(&profile, &storage, &trusted);
    producer.submit_transaction(payment(&profile, 0)).unwrap();
    producer
        .set_potb_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    let certificate = support::certificate(trusted.current().committee(), &proposal.block.header);
    let before = producer.state().root();
    std::fs::create_dir(dir.0.join("chain.bin.pending")).unwrap();
    assert!(
        producer
            .commit_block(&proposal, certificate.encode().unwrap(), &mut storage)
            .is_err()
    );
    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.potb_state(), Some(trusted.current()));
    assert_eq!(producer.parent_hash(), trusted.parent());
    assert_eq!(producer.pending_count(), 1);
    assert_eq!(producer.produce_block().unwrap(), proposal);
    assert_eq!(storage.checkpoint().unwrap().height, 0);
    std::fs::remove_dir(dir.0.join("chain.bin.pending")).unwrap();
    producer
        .commit_block(&proposal, certificate.encode().unwrap(), &mut storage)
        .unwrap();
    assert_eq!(producer.height(), 2);
    assert_eq!(producer.pending_count(), 0);
}

#[test]
fn canonical_system_envelope_and_reserved_capacity_cannot_be_bypassed() {
    let (profile, keys) = fixture();
    let (_dir, storage) = storage(&profile, &keys, false);
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let mut producer = producer(&profile, &storage, &trusted);
    producer
        .set_potb_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    for mutation in 0..8 {
        let mut block = proposal.block.clone();
        match mutation {
            0 => block.transactions[0].nonce += 1,
            1 => block.transactions[0].signature[0] ^= 1,
            2 => block.transactions[0].resource_limit.compute -= 1,
            3 => {
                block.transactions[0].payload.pop();
            }
            4 => block.transactions[0].access_list.clear(),
            5 => block.transactions.clear(),
            6 => block.transactions.push(block.transactions[0].clone()),
            _ => block.transactions[0].lane = TransactionLane::Payments,
        }
        block.header.transactions_root = node::compute_transactions_root(&block.transactions);
        assert!(producer.execute_received_block(block).is_err());
    }
    let mut partial = support::contributions(trusted.current()).entries().to_vec();
    partial.pop();
    let bad = PotbBatch::new(
        consensus::rotation::VrfBatch::new(partial).unwrap(),
        vec![],
        vec![],
    )
    .unwrap();
    assert!(producer.set_potb_batch(bad).is_err());
    assert_eq!(producer.produce_block().unwrap(), proposal);
    for dimension in 0..5 {
        let mut genesis = profile.genesis().clone();
        let used = proposal.resources_used;
        match dimension {
            0 => genesis.capacity.compute = used.compute,
            1 => genesis.capacity.memory = used.memory,
            2 => genesis.capacity.io = used.io,
            3 => genesis.capacity.bandwidth = used.bandwidth,
            _ => {}
        }
        let limited = PotbConfiguration::new(genesis, profile.policy()).unwrap();
        let (_dir, storage) = self::storage(&limited, &keys, false);
        let verifier = PotbVerifier::new(&limited, &keys).unwrap();
        let mut config = config(&limited);
        if dimension == 4 {
            config.max_block_transactions = 1;
        }
        let mut producer = BlockProducer::from_checkpoint(
            config,
            storage.checkpoint().copied(),
            storage.state().clone(),
        )
        .unwrap()
        .with_potb(&verifier)
        .unwrap();
        assert!(
            producer.submit_transaction(payment(&limited, 0)).is_err(),
            "dimension {dimension}"
        );
        producer
            .set_potb_batch(support::batch(verifier.current()))
            .unwrap();
        assert_eq!(
            producer.produce_block().unwrap().block.transactions.len(),
            1
        );
    }
}

#[test]
fn structurally_valid_disk_state_does_not_replace_a_quorum() {
    let (profile, keys) = fixture();
    let (_dir, mut storage) = storage(&profile, &keys, false);
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let mut producer = producer(&profile, &storage, &trusted);
    producer
        .set_potb_batch(support::batch(trusted.current()))
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    assert!(
        producer
            .commit_block(&proposal, vec![1], &mut storage)
            .is_err()
    );
    storage
        .commit(&storage::CommitBatch {
            block: proposal.block,
            finality_certificate: vec![1],
            effects: None,
            state_diffs: proposal.outputs.into_iter().map(|o| o.diff).collect(),
        })
        .unwrap();
    assert!(BlockProducer::recover_potb(config(&profile), &profile, &keys, &storage).is_err());
}
