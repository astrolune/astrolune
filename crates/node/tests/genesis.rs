// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Genesis activation, durable identity checks, and restart equivalence.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use genesis::{Allocation, Genesis, GenesisValidator};
use node::{FullNodeService, NodeService, ProducerConfig};
use state::{StateDatabase, read_account};
use storage::{FileBackedStorage, NodeStorage, StorageError};
use types::{AccountState, Address, Hash256, Resources, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-genesis-node-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn genesis() -> Genesis {
    Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 20,
            memory: 30,
            io: 40,
            bandwidth: 50,
        },
        committee_size: 2,
        rotation_count: 1,
        runtime_version: 1,
        validators: (1..=3)
            .map(|n| GenesisValidator {
                id: ValidatorId([n; 32]),
                weight: u128::from(n) << 80,
            })
            .collect(),
        allocations: vec![Allocation {
            address: Address([7; 32]),
            amount: 1234,
        }],
    }
}

fn config(genesis: &Genesis) -> ProducerConfig {
    ProducerConfig {
        chain_id: genesis.chain_id,
        block_capacity: genesis.capacity,
        ..ProducerConfig::default()
    }
}

fn advance(service: &mut FullNodeService<FileBackedStorage>, blocks: usize) {
    for _ in 0..blocks * 5 {
        service.advance().unwrap();
    }
}

#[test]
fn genesis_survives_restart_and_matches_uninterrupted_production() {
    let fixture = Fixture::new();
    let uninterrupted = Fixture::new();
    let genesis = genesis();
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 1);
    assert_eq!(service.storage().block_count(), 0);
    assert_eq!(
        service.finalized_block(),
        Some(genesis.commitment().unwrap())
    );
    assert_eq!(
        service.storage().state().root(),
        genesis.materialize().unwrap().root()
    );
    let committee = service.committee().unwrap();
    assert_eq!(committee.members.len(), genesis.committee_size);
    assert_eq!(committee.members[1].power.0, genesis.validators[1].weight);
    advance(&mut service, 1);
    let first = service.storage().checkpoint().unwrap();
    let block = service.storage().get_block(&first.block).unwrap();
    assert_eq!(block.header.height, 1);
    assert_eq!(block.header.parent, genesis.commitment().unwrap());
    assert_eq!(block.header.capacity, genesis.capacity);
    drop(service);
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 2);
    assert_eq!(service.committee().unwrap().height, 2);
    advance(&mut service, 2);
    let snapshot = service.storage().state().snapshot().unwrap();
    assert_eq!(
        read_account(snapshot.as_ref(), Address([7; 32])).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 1234
        })
    );
    let mut reference =
        FullNodeService::open_with_genesis(config(&genesis), uninterrupted.path(), &genesis)
            .unwrap();
    advance(&mut reference, 3);
    assert_eq!(
        service.storage().checkpoint(),
        reference.storage().checkpoint()
    );
    assert_eq!(
        fs::read(fixture.path()).unwrap(),
        fs::read(uninterrupted.path()).unwrap()
    );
}

#[test]
fn mismatches_missing_genesis_and_reinitialization_preserve_archive() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    for blocks in [0, 2] {
        advance(&mut service, blocks);
        drop(service);
        let before = fs::read(fixture.path()).unwrap();
        assert!(FullNodeService::open(config(&genesis), fixture.path()).is_err());
        for changed in [
            Genesis {
                chain_id: 43,
                ..genesis.clone()
            },
            Genesis {
                runtime_version: 2,
                ..genesis.clone()
            },
            Genesis {
                allocations: vec![],
                ..genesis.clone()
            },
        ] {
            assert!(
                FullNodeService::open_with_genesis(config(&changed), fixture.path(), &changed)
                    .is_err()
            );
        }
        let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
        assert_eq!(
            storage.initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap()
            ),
            Err(StorageError::InvalidOrder)
        );
        drop(storage);
        assert_eq!(before, fs::read(fixture.path()).unwrap());
        service =
            FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
        assert_eq!(before, fs::read(fixture.path()).unwrap());
    }
}

#[test]
fn existing_legacy_chain_is_not_converted() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut service = FullNodeService::open(config(&genesis), fixture.path()).unwrap();
    advance(&mut service, 1);
    drop(service);
    let before = fs::read(fixture.path()).unwrap();
    assert!(
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).is_err()
    );
    assert_eq!(before, fs::read(fixture.path()).unwrap());
}

#[test]
fn invalid_genesis_and_producer_config_fail_before_archive_creation() {
    let fixture = Fixture::new();
    let genesis = genesis();
    assert!(
        FullNodeService::open_with_genesis(ProducerConfig::default(), fixture.path(), &genesis)
            .is_err()
    );
    let invalid = Genesis {
        version: 2,
        ..genesis
    };
    assert!(
        FullNodeService::open_with_genesis(config(&invalid), fixture.path(), &invalid).is_err()
    );
    assert!(!fixture.path().exists());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}

#[test]
fn failed_genesis_publication_can_be_retried_without_partial_state() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    assert_eq!(
        storage.initialize_genesis(Hash256::ZERO, genesis.materialize().unwrap()),
        Err(StorageError::VerificationFailed)
    );
    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert_eq!(
        storage.initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap()
        ),
        Err(StorageError::Io)
    );
    assert!(storage.recover().unwrap().is_none());
    assert!(storage.state().is_empty());
    assert_eq!(before, fs::read(fixture.path()).unwrap());
    fs::remove_dir(pending).unwrap();
    storage
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    drop(storage);
    let service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 1);
}

fn payment_address(seed: u8) -> Address {
    transaction::address_from_public_key(&crypto::blake2s::ed25519_public_key(&[seed; 32]))
}

fn authenticated_context(genesis: &Genesis, height: u64) -> consensus::AuthenticatedCommittee {
    let committee = consensus::Committee {
        height,
        members: genesis
            .validators
            .iter()
            .map(|validator| consensus::CommitteeMember {
                id: validator.id,
                power: consensus::PotbWeight(validator.weight),
            })
            .collect(),
    };
    let keys = [1u8, 2, 3].map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]));
    consensus::AuthenticatedCommittee::new(genesis.chain_id, &committee, &keys).unwrap()
}

fn sign_certificate(
    context: &consensus::AuthenticatedCommittee,
    proposal: &node::BlockProposal,
) -> consensus::FinalityCertificate {
    let hash = proposal.block.header.compute_hash();
    let mut signatures: Vec<_> = [1u8, 2, 3]
        .iter()
        .map(|seed| {
            let voter = ValidatorId(
                crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&[*seed; 32])).0,
            );
            let vote = consensus::Vote {
                chain_id: context.chain_id(),
                committee_root: context.root(),
                height: context.height(),
                round: 0,
                phase: consensus::VotePhase::Precommit,
                block: Some(hash),
                voter,
                signature: [0; 64],
            };
            consensus::CertificateSignature {
                voter,
                signature: crypto::blake2s::ed25519_sign(&[*seed; 32], &vote.signing_hash().0),
            }
        })
        .collect();
    signatures.sort_by_key(|entry| entry.voter);
    consensus::FinalityCertificate {
        chain_id: context.chain_id(),
        height: context.height(),
        round: 0,
        committee_root: context.root(),
        block: hash,
        signatures,
    }
}

fn certified_genesis() -> Genesis {
    let mut genesis = payment_genesis();
    genesis.validators = [1u8, 2, 3]
        .iter()
        .map(|seed| GenesisValidator {
            id: ValidatorId(
                crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&[*seed; 32])).0,
            ),
            weight: 1,
        })
        .collect();
    genesis.validators.sort_by_key(|validator| validator.id);
    genesis.committee_size = 3;
    genesis
}

#[test]
fn certified_payments_verify_before_publication_and_survive_restart() {
    let fixture = Fixture::new();
    let genesis = certified_genesis();
    {
        let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
        storage
            .initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap(),
            )
            .unwrap();
    }
    for height in 1..=3 {
        let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
        let checkpoint = storage.recover().unwrap();
        let mut producer = node::BlockProducer::from_checkpoint(
            config(&genesis),
            checkpoint,
            storage.state().clone(),
        )
        .unwrap();
        let context = authenticated_context(&genesis, height);
        producer
            .submit_transaction(payment(1, 2, height - 1, 10))
            .unwrap();
        let before = producer.state().root();
        let archive = fs::read(fixture.path()).unwrap();
        let proposal = producer.produce_block_for_committee(&context).unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
        let certificate = sign_certificate(&context, &proposal);
        let mut forged = certificate.clone();
        forged.signatures[0].signature[0] ^= 1;
        assert!(matches!(
            producer.commit_certified_block(&proposal, &forged, &context, &mut storage),
            Err(node::ProducerError::Consensus(_))
        ));
        let mut invalid_execution = proposal.clone();
        invalid_execution.block.header.state_root = Hash256::ZERO;
        let signed_invalid = sign_certificate(&context, &invalid_execution);
        assert!(
            producer
                .commit_certified_block(&invalid_execution, &signed_invalid, &context, &mut storage)
                .is_err()
        );
        // A valid proof must not consume pending transactions on a failed durable write.
        let pending = fixture.0.join("chain.bin.pending");
        fs::create_dir(&pending).unwrap();
        assert!(matches!(
            producer.commit_certified_block(&proposal, &certificate, &context, &mut storage),
            Err(node::ProducerError::Storage(_))
        ));
        fs::remove_dir(&pending).unwrap();
        assert_eq!(producer.state().root(), before);
        assert_eq!(producer.height(), height);
        assert_eq!(producer.pending_count(), 1);
        assert_eq!(storage.checkpoint().copied(), checkpoint);
        assert_eq!(fs::read(fixture.path()).unwrap(), archive);
        let committed = producer
            .commit_certified_block(&proposal, &certificate, &context, &mut storage)
            .unwrap();
        assert_eq!(producer.height(), height + 1);
        assert_eq!(producer.pending_count(), 0);
        assert!(
            producer
                .commit_certified_block(&proposal, &certificate, &context, &mut storage)
                .is_err()
        );
        drop(storage);
        let storage = FileBackedStorage::open(fixture.path()).unwrap();
        let recovered = consensus::FinalityCertificate::decode(
            storage.get_certificate(&committed.block).unwrap(),
        )
        .unwrap();
        context
            .verify_certificate(
                &recovered,
                &storage.get_block(&committed.block).unwrap().header,
            )
            .unwrap();
        assert_eq!(recovered, certificate);
        assert_eq!(storage.state().root(), committed.state_root);
        let snapshot = storage.state().snapshot().unwrap();
        assert_eq!(
            read_account(snapshot.as_ref(), payment_address(1)).unwrap(),
            Some(AccountState {
                nonce: height,
                balance: 1000 - 11 * height
            })
        );
        assert_eq!(
            read_account(snapshot.as_ref(), payment_address(2)).unwrap(),
            Some(AccountState {
                nonce: 0,
                balance: 10 * height
            })
        );
    }
}

#[test]
fn certified_production_rejects_other_chains_and_heights() {
    let public_key = crypto::blake2s::ed25519_public_key(&[1; 32]);
    let mut producer = node::BlockProducer::new(ProducerConfig::default());
    let committee = |height| consensus::Committee {
        height,
        members: vec![consensus::CommitteeMember {
            id: ValidatorId(crypto::blake2s_hash(&public_key).0),
            power: consensus::PotbWeight(1),
        }],
    };
    for (chain, height) in [(8, 0), (7, 1)] {
        let context =
            consensus::AuthenticatedCommittee::new(chain, &committee(height), &[public_key])
                .unwrap();
        assert!(producer.produce_block_for_committee(&context).is_err());
        assert_eq!(producer.height(), 0);
    }
}

fn payment_genesis() -> Genesis {
    Genesis {
        capacity: Resources {
            compute: 100,
            memory: 1024,
            io: 100,
            bandwidth: 10000,
        },
        allocations: vec![Allocation {
            address: payment_address(1),
            amount: 1000,
        }],
        ..genesis()
    }
}

fn payment(seed: u8, recipient: u8, nonce: u64, amount: u64) -> types::Transaction {
    let mut access_list = vec![
        state::account_key(payment_address(seed)),
        state::account_key(payment_address(recipient)),
    ];
    access_list.sort();
    access_list.dedup();
    let mut tx = types::Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 42,
        sender: payment_address(seed),
        nonce,
        access_list,
        resource_limit: Resources::ZERO,
        payload: transaction::Payment {
            public_key: crypto::blake2s::ed25519_public_key(&[seed; 32]),
            recipient: payment_address(recipient),
            amount,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature =
        crypto::blake2s::ed25519_sign(&[seed; 32], transaction::signing_hash(&tx).as_bytes());
    tx
}

#[test]
fn signed_payments_survive_restart_and_replay_is_rejected() {
    let fixture = Fixture::new();
    let reference = Fixture::new();
    let genesis = payment_genesis();
    let first = payment(1, 2, 0, 100);
    {
        let mut service =
            FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
        let mut forged = first.clone();
        forged.signature[0] ^= 1;
        assert!(service.submit_transaction(forged).is_err());
        assert_eq!(service.pending_transactions(), 0);
        service.submit_transaction(first.clone()).unwrap();
        assert!(service.submit_transaction(payment(1, 3, 1, 1)).is_err());
        advance(&mut service, 1);
    }
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert!(service.submit_transaction(first.clone()).is_err());
    let second = payment(1, 3, 1, 50);
    let third = payment(2, 3, 0, 10);
    service.submit_transaction(second.clone()).unwrap();
    service.submit_transaction(third.clone()).unwrap();
    advance(&mut service, 1);
    let snapshot = service.storage().state().snapshot().unwrap();
    for (seed, nonce, balance) in [(1, 2, 848), (2, 1, 89), (3, 0, 60)] {
        assert_eq!(
            read_account(snapshot.as_ref(), payment_address(seed)).unwrap(),
            Some(AccountState { nonce, balance })
        );
    }
    assert_eq!(
        service.storage().state().get(&genesis::genesis_key()),
        Some(genesis.commitment().unwrap().as_bytes().as_slice())
    );
    let mut uninterrupted =
        FullNodeService::open_with_genesis(config(&genesis), reference.path(), &genesis).unwrap();
    uninterrupted.submit_transaction(first).unwrap();
    advance(&mut uninterrupted, 1);
    uninterrupted.submit_transaction(second).unwrap();
    uninterrupted.submit_transaction(third).unwrap();
    advance(&mut uninterrupted, 1);
    assert_eq!(
        fs::read(fixture.path()).unwrap(),
        fs::read(reference.path()).unwrap()
    );
}

#[test]
fn failed_payment_publication_keeps_balances_and_pending_proposal_for_retry() {
    let fixture = Fixture::new();
    let genesis = payment_genesis();
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    service.submit_transaction(payment(1, 2, 0, 100)).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    let root = service.storage().state().root();
    for _ in 0..4 {
        service.advance().unwrap();
    }
    assert_eq!(service.storage().state().root(), root);
    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert!(service.advance().is_err());
    assert_eq!(service.height(), 1);
    assert_eq!(service.pending_transactions(), 1);
    assert_eq!(service.storage().state().root(), root);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    fs::remove_dir(pending).unwrap();
    service.advance().unwrap();
    assert_eq!(service.height(), 2);
    assert_eq!(service.pending_transactions(), 0);
    assert_ne!(service.storage().state().root(), root);
}

#[test]
fn commit_rejects_consistent_but_forged_payment_outputs() {
    use node::{BlockProducer, compute_receipts_root, compute_transactions_root};
    let fixture = Fixture::new();
    let genesis = payment_genesis();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    storage
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    let mut producer = BlockProducer::from_checkpoint(
        config(&genesis),
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap();
    producer.submit_transaction(payment(1, 2, 0, 100)).unwrap();
    let valid = producer.produce_block().unwrap();
    assert_eq!(valid, producer.produce_block().unwrap());
    let mut forged = valid.clone();
    forged.block.transactions[0].signature[0] ^= 1;
    forged.outputs[0].receipt.transaction =
        transaction::compute_tx_id(&forged.block.transactions[0]);
    forged.block.header.transactions_root = compute_transactions_root(&forged.block.transactions);
    forged.block.header.receipts_root = compute_receipts_root(&[forged.outputs[0].receipt.clone()]);
    let before = fs::read(fixture.path()).unwrap();
    assert!(
        producer
            .commit_block(&forged, vec![1], &mut storage)
            .is_err()
    );
    let mut forged = valid.clone();
    forged.outputs[0]
        .diff
        .put(genesis::genesis_key(), vec![0; 32]);
    forged.outputs[0].receipt.output_root = forged.outputs[0].diff.commitment();
    forged.block.header.receipts_root = compute_receipts_root(&[forged.outputs[0].receipt.clone()]);
    forged.state_root = producer
        .state()
        .prepare(producer.state().root(), &[forged.outputs[0].diff.clone()])
        .unwrap()
        .root();
    forged.block.header.state_root = forged.state_root;
    assert!(
        producer
            .commit_block(&forged, vec![1], &mut storage)
            .is_err()
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(producer.pending_count(), 1);
    producer
        .commit_block(&valid, vec![1], &mut storage)
        .unwrap();
}

#[test]
fn conflicting_pool_payments_do_not_reserve_capacity_or_block_later_candidates() {
    let fixture = Fixture::new();
    let mut genesis = payment_genesis();
    genesis.allocations = [(1, 100), (2, 100), (3, 100), (4, u64::MAX - 1)]
        .into_iter()
        .map(|(seed, amount)| Allocation {
            address: payment_address(seed),
            amount,
        })
        .collect();
    genesis
        .allocations
        .sort_by_key(|allocation| allocation.address);
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    storage
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    let mut config = config(&genesis);
    config.max_block_transactions = 2;
    let mut producer = node::BlockProducer::from_checkpoint(
        config,
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap();
    let first = payment(1, 4, 0, 1);
    let conflicted = payment(2, 4, 0, 1);
    let last = payment(3, 5, 0, 1);
    for tx in [&first, &conflicted, &last] {
        producer.submit_transaction(tx.clone()).unwrap();
    }
    let proposal = producer.produce_block().unwrap();
    assert_eq!(proposal.block.transactions, [first, last]);
    assert_eq!(producer.pending_count(), 3);
    producer
        .commit_block(&proposal, vec![1], &mut storage)
        .unwrap();
    assert_eq!(producer.pending_count(), 1);
    assert_eq!(
        producer.produce_block().unwrap().block.transactions,
        [] as [types::Transaction; 0]
    );
    producer.submit_transaction(payment(4, 5, 0, 1)).unwrap();
    let proposal = producer.produce_block().unwrap();
    producer
        .commit_block(&proposal, vec![1], &mut storage)
        .unwrap();
    let proposal = producer.produce_block().unwrap();
    assert_eq!(proposal.block.transactions, [conflicted]);
    producer
        .commit_block(&proposal, vec![1], &mut storage)
        .unwrap();
    assert_eq!(producer.pending_count(), 0);
}

#[test]
fn expired_pool_entries_are_removed_only_after_successful_commit() {
    let fixture = Fixture::new();
    let mut genesis = payment_genesis();
    genesis.allocations.push(Allocation {
        address: payment_address(2),
        amount: 100,
    });
    genesis
        .allocations
        .sort_by_key(|allocation| allocation.address);
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    storage
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    let mut config = config(&genesis);
    config.max_block_transactions = 1;
    let mut producer = node::BlockProducer::from_checkpoint(
        config,
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap();
    producer.submit_transaction(payment(1, 3, 0, 1)).unwrap();
    let mut expiring = payment(2, 3, 0, 1);
    expiring.expires_at = 1;
    expiring.signature =
        crypto::blake2s::ed25519_sign(&[2; 32], transaction::signing_hash(&expiring).as_bytes());
    producer.submit_transaction(expiring.clone()).unwrap();
    let proposal = producer.produce_block().unwrap();
    assert_eq!(producer.pending_count(), 2);
    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert!(
        producer
            .commit_block(&proposal, vec![1], &mut storage)
            .is_err()
    );
    assert_eq!(producer.pending_count(), 2);
    assert_eq!(producer.height(), 1);
    fs::remove_dir(pending).unwrap();
    producer
        .commit_block(&proposal, vec![1], &mut storage)
        .unwrap();
    assert_eq!(producer.pending_count(), 0);
    assert!(producer.submit_transaction(expiring).is_err());
    producer.submit_transaction(payment(2, 3, 0, 1)).unwrap();
}
