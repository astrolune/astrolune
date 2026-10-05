// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signed account execution, durable local BFT voting, finality, and archive recovery.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, Committee, CommitteeMember, FinalityCertificate,
    FinalityEngine, LocalBft, PotbWeight, VotingStep,
};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{BlockProducer, ProducerConfig, RoundRobinValidator, ValidatorError};
use state::{StateDatabase, read_account};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::FileBackedStorage;
use types::{AccountState, Address, Hash256, Resources, Transaction, TransactionLane, ValidatorId};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-bft-pipeline-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();

        Self(path)
    }

    fn journal(&self, seed: u8) -> PathBuf {
        self.0.join(format!("signer-{seed}.bin"))
    }

    fn archive(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn public(seed: u8) -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&[seed; 32])
}

fn address(seed: u8) -> Address {
    transaction::address_from_public_key(&public(seed))
}

fn genesis() -> Genesis {
    let mut validators: Vec<_> = (1..=4)
        .map(|seed| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&public(seed)).0),
            weight: 1,
        })
        .collect();
    validators.sort_by_key(|validator| validator.id);

    Genesis {
        version: 1,
        chain_id: 7,
        capacity: ProducerConfig::default().block_capacity,
        committee_size: 4,
        rotation_count: 1,
        runtime_version: 1,
        validators,
        allocations: vec![Allocation {
            address: address(9),
            amount: 1000,
        }],
    }
}

fn context(genesis: &Genesis, height: u64) -> AuthenticatedCommittee {
    let members = genesis
        .validators
        .iter()
        .map(|validator| CommitteeMember {
            id: validator.id,
            power: PotbWeight(validator.weight),
        })
        .collect();

    AuthenticatedCommittee::new(
        genesis.chain_id,
        &Committee { height, members },
        &[public(1), public(2), public(3), public(4)],
    )
    .unwrap()
}

fn payment() -> Transaction {
    let mut access_list = vec![
        state::account_key(address(9)),
        state::account_key(address(10)),
    ];
    access_list.sort();

    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id: 7,
        nonce: 0,
        expires_at: 1,
        sender: address(9),
        lane: TransactionLane::Payments,
        access_list,
        resource_limit: Resources::ZERO,
        resource_prices: execution::PAYMENT_PRICES,
        payload: transaction::Payment {
            public_key: public(9),
            recipient: address(10),
            amount: 10,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = crypto::blake2s::ed25519_sign(&[9; 32], &transaction::signing_hash(&tx).0);

    tx
}

#[test]
fn payment_is_committed_only_after_validated_local_votes_and_durable_certificate() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let genesis_hash = genesis.commitment().unwrap();

    let namespace = SigningContext {
        chain_id: 7,
        genesis: genesis_hash,
    };
    let mut storage = FileBackedStorage::open(fixture.archive()).unwrap();
    let anchor = storage
        .initialize_genesis(genesis_hash, genesis.materialize().unwrap())
        .unwrap();
    let mut producer = BlockProducer::from_checkpoint(
        ProducerConfig::default(),
        Some(anchor),
        storage.state().clone(),
    )
    .unwrap();

    producer.submit_transaction(payment()).unwrap();

    let committee = context(&genesis, 1);
    let proposal = producer.produce_block_for_committee(&committee).unwrap();
    let before = producer.state().root();

    producer.validate_proposal(&proposal).unwrap();
    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.pending_count(), 1);

    let mut invalid = proposal.clone();
    invalid.block.header.state_root = Hash256::ZERO;
    assert!(producer.validate_proposal(&invalid).is_err());

    let mut collector = BftFinalityEngine::new(context(&genesis, 1));

    for seed in 1..=4 {
        let signer =
            DurableSigner::create_protected(fixture.journal(seed), namespace, [seed; 32]).unwrap();
        let mut local = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();

        // This in-process fixture supplies the authorized proposal; execution is rechecked.
        let vote = local
            .prevote(Some(&proposal.block.header), None, |header| {
                *header == proposal.block.header && producer.validate_proposal(&proposal).is_ok()
            })
            .unwrap();
        collector.receive_vote(vote).unwrap();
    }

    let proof = collector
        .prevote_certificate(proposal.block.header.compute_hash())
        .unwrap();

    for seed in 1..=3 {
        let signer = DurableSigner::open(fixture.journal(seed), namespace, [seed; 32]).unwrap();
        let mut local = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();
        assert_eq!(local.step(), VotingStep::Prevoted);

        let vote = local
            .precommit(&proposal.block.header, &proof, |_| {
                producer.validate_proposal(&proposal).is_ok()
            })
            .unwrap();
        collector.receive_vote(vote).unwrap();
    }

    let certificate = collector.certificate().unwrap().clone();

    let signer = DurableSigner::open(fixture.journal(4), namespace, [4; 32]).unwrap();
    let mut observer = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();
    observer
        .finalize(&proposal.block.header, &certificate, |_| {
            producer.validate_proposal(&proposal).is_ok()
        })
        .unwrap();

    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert!(
        producer
            .commit_certified_block(&proposal, &certificate, &committee, &mut storage)
            .is_err()
    );
    fs::remove_dir(&pending).unwrap();

    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.pending_count(), 1);

    let checkpoint = producer
        .commit_certified_block(&proposal, &certificate, &committee, &mut storage)
        .unwrap();
    assert_eq!(producer.pending_count(), 0);
    drop(storage);

    let storage = FileBackedStorage::open(fixture.archive()).unwrap();
    let recovered =
        FinalityCertificate::decode(storage.get_certificate(&checkpoint.block).unwrap()).unwrap();
    context(&genesis, 1)
        .verify_certificate(
            &recovered,
            &storage.get_block(&checkpoint.block).unwrap().header,
        )
        .unwrap();

    let state = storage.state().snapshot().unwrap();
    assert_eq!(
        read_account(state.as_ref(), address(9)).unwrap(),
        Some(AccountState {
            nonce: 1,
            balance: 989
        })
    );
    assert_eq!(
        read_account(state.as_ref(), address(10)).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 10
        })
    );
}

fn participant(fixture: &Fixture, seed: u8) -> (RoundRobinValidator, FileBackedStorage) {
    let genesis = genesis();
    let genesis_hash = genesis.commitment().unwrap();

    let namespace = SigningContext {
        chain_id: 7,
        genesis: genesis_hash,
    };
    let mut storage = FileBackedStorage::open(fixture.0.join(format!("node-{seed}.bin"))).unwrap();
    let anchor = match storage.checkpoint().copied() {
        Some(checkpoint) => checkpoint,
        None => storage
            .initialize_genesis(genesis_hash, genesis.materialize().unwrap())
            .unwrap(),
    };
    let producer = BlockProducer::from_checkpoint(
        ProducerConfig::default(),
        Some(anchor),
        storage.state().clone(),
    )
    .unwrap();

    let signer = if fixture.journal(seed).exists() {
        DurableSigner::open(fixture.journal(seed), namespace, [seed; 32]).unwrap()
    } else {
        DurableSigner::create_protected(fixture.journal(seed), namespace, [seed; 32]).unwrap()
    };
    let local = LocalBft::new(context(&genesis, anchor.height + 1), signer, genesis_hash).unwrap();

    (
        RoundRobinValidator::new(producer, local, context(&genesis, anchor.height + 1)).unwrap(),
        storage,
    )
}

fn deliver(nodes: &mut [RoundRobinValidator], votes: &[consensus::Vote]) {
    for node in nodes {
        for vote in votes {
            if node.certificate().is_some() {
                break;
            }

            match node.receive_vote(vote.clone()) {
                Ok(())
                | Err(ValidatorError::Voting(consensus::LocalBftError::Consensus(
                    consensus::ConsensusError::DuplicateVote,
                ))) => (),
                result => panic!("vote delivery failed: {result:?}"),
            }
        }
    }
}

fn proposer_index(nodes: &[RoundRobinValidator]) -> usize {
    (1..=4)
        .position(|seed| ValidatorId(crypto::blake2s_hash(&public(seed)).0) == nodes[0].proposer())
        .unwrap()
}

#[test]
fn four_participants_authenticate_proposals_recover_votes_and_commit_payment_atomically() {
    let fixture = Fixture::new();
    let (mut nodes, mut archives): (Vec<_>, Vec<_>) =
        (1..=4).map(|seed| participant(&fixture, seed)).unzip();

    for node in &mut nodes {
        node.submit_transaction(payment()).unwrap();
    }

    let proposer = proposer_index(&nodes);
    assert!(nodes[(proposer + 1) % 4].propose().is_err());

    let proposal = nodes[proposer].propose().unwrap();
    let before = nodes[0].producer().state().root();

    let stale = nodes[0].timeout_event().unwrap();

    let mut forged = proposal.clone();
    forged.envelope.signature[0] ^= 1;
    for node in &mut nodes {
        assert!(node.accept_proposal(&forged).is_err());
        assert_eq!(node.local().step(), VotingStep::AwaitingProposal);
    }

    let prevotes: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.accept_proposal(&proposal).unwrap())
        .collect();
    assert!(nodes[0].timeout(stale).is_err());

    let (producer, local) = nodes.remove(0).into_parts();
    drop(local);

    let genesis_hash = genesis().commitment().unwrap();
    let namespace = SigningContext {
        chain_id: 7,
        genesis: genesis_hash,
    };
    let signer = DurableSigner::open(fixture.journal(1), namespace, [1; 32]).unwrap();
    let local = LocalBft::new(context(&genesis(), 1), signer, genesis_hash).unwrap();
    nodes.insert(
        0,
        RoundRobinValidator::new(producer, local, context(&genesis(), 1)).unwrap(),
    );

    assert_eq!(nodes[0].accept_proposal(&proposal).unwrap(), prevotes[0]);

    deliver(&mut nodes, &prevotes);

    let precommits: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.precommit().unwrap())
        .collect();
    deliver(&mut nodes, &precommits);

    for node in &nodes {
        assert!(node.timeout_event().is_none());
    }

    for node in &mut nodes {
        assert!(node.precommit().is_err());
        assert!(node.accept_proposal(&proposal).is_err());
        assert!(node.propose().is_err());
    }

    let certificate = nodes[0].certificate().unwrap().clone();

    let pending = fixture.0.join("node-1.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert!(nodes[0].commit(&mut archives[0]).is_err());
    fs::remove_dir(&pending).unwrap();

    assert_eq!(nodes[0].producer().state().root(), before);
    assert_eq!(nodes[0].producer().pending_count(), 1);
    assert!(nodes[0].propose().is_err());

    for (node, archive) in nodes.iter_mut().zip(&mut archives) {
        node.commit(archive).unwrap();
        assert_eq!(node.producer().height(), 2);
        assert_eq!(node.producer().pending_count(), 0);
        assert!(node.commit(archive).is_err());
    }

    drop(nodes);
    drop(archives);

    for seed in 1..=4 {
        let (mut node, mut archive) = participant(&fixture, seed);
        assert_eq!(node.local().round(), 0);
        assert_eq!(node.local().locked(), None);
        assert_eq!(node.local().committee().height(), 2);

        let checkpoint = archive.checkpoint().copied().unwrap();
        context(&genesis(), 1)
            .verify_certificate(
                &certificate,
                &archive.get_block(&checkpoint.block).unwrap().header,
            )
            .unwrap();

        let snapshot = archive.state().snapshot().unwrap();
        assert_eq!(
            read_account(snapshot.as_ref(), address(9))
                .unwrap()
                .unwrap()
                .balance,
            989
        );
        assert_eq!(
            read_account(snapshot.as_ref(), address(10))
                .unwrap()
                .unwrap()
                .balance,
            10
        );

        // Replayed finality from the preceding height cannot alter the new participant.
        assert!(
            node.commit_finalized(&proposal.proposal, &certificate, &mut archive)
                .is_err()
        );
    }
}

#[test]
fn round_change_reproposes_verified_value_and_rejects_delayed_events() {
    let fixture = Fixture::new();
    let (mut nodes, archives): (Vec<_>, Vec<_>) =
        (1..=4).map(|seed| participant(&fixture, seed)).unzip();

    for node in &mut nodes {
        node.submit_transaction(payment()).unwrap();
    }

    let proposer = proposer_index(&nodes);
    let proposal = nodes[proposer].propose().unwrap();

    let prevotes: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.accept_proposal(&proposal).unwrap())
        .collect();
    deliver(&mut nodes, &prevotes);

    let proof = nodes[0].prevote_certificate().unwrap();

    // Withhold precommit delivery so nobody observes a finality quorum.
    for node in &mut nodes {
        node.precommit().unwrap();

        let event = node.timeout_event().unwrap();
        let mut wrong_height = event;
        wrong_height.height += 1;
        assert!(node.timeout(wrong_height).is_err());

        assert!(node.timeout(event).unwrap().is_none());
        assert!(node.timeout(event).is_err());
        assert_eq!(node.local().round(), 1);
        assert_eq!(
            node.local().locked().unwrap().block,
            proposal.envelope.block
        );
        assert!(node.accept_proposal(&proposal).is_err());
        assert!(node.receive_vote(prevotes[0].clone()).is_err());
    }

    let next = proposer_index(&nodes);
    assert_ne!(next, proposer);

    let reproposal = nodes[next].repropose(proposal.proposal, proof).unwrap();
    assert_eq!(reproposal.envelope.valid_round, Some(0));

    let mut missing_proof = reproposal.clone();
    missing_proof.valid_round = None;
    for node in &mut nodes {
        assert!(node.accept_proposal(&missing_proof).is_err());
    }

    let prevotes: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.accept_proposal(&reproposal).unwrap())
        .collect();
    deliver(&mut nodes, &prevotes);

    let precommits: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.precommit().unwrap())
        .collect();
    deliver(&mut nodes, &precommits);

    assert!(
        nodes
            .iter()
            .all(|node| node.certificate().unwrap().round == 1)
    );

    drop(nodes);
    drop(archives);

    // Loss of all volatile messages is recovered by independent certificate verification.
    let certificate = consensus::FinalityCertificate {
        chain_id: 7,
        height: 1,
        round: 1,
        committee_root: context(&genesis(), 1).root(),
        block: reproposal.envelope.block,
        signatures: {
            let mut entries: Vec<_> = precommits
                .iter()
                .map(|vote| consensus::CertificateSignature {
                    voter: vote.voter,
                    signature: vote.signature,
                })
                .collect();
            entries.sort_by_key(|entry| entry.voter);

            entries
        },
    };

    let (mut recovered, mut archive) = participant(&fixture, 1);
    assert_eq!(recovered.local().step(), VotingStep::Precommitted);
    assert_eq!(recovered.local().round(), 1);
    assert!(recovered.certificate().is_none());
    assert!(recovered.precommit().is_err());

    recovered.restore_proposal(&reproposal).unwrap();
    deliver(std::slice::from_mut(&mut recovered), &prevotes);
    assert_eq!(recovered.precommit().unwrap(), precommits[0]);

    recovered
        .commit_finalized(&reproposal.proposal, &certificate, &mut archive)
        .unwrap();
    assert_eq!(archive.checkpoint().unwrap().height, 1);
}

#[test]
fn invalid_execution_and_nil_timeouts_cannot_publish_or_form_finality() {
    let fixture = Fixture::new();
    let (mut nodes, mut archives): (Vec<_>, Vec<_>) =
        (1..=4).map(|seed| participant(&fixture, seed)).unzip();

    for node in &mut nodes {
        node.submit_transaction(payment()).unwrap();
    }

    let proposer = proposer_index(&nodes);
    let mut proposal = nodes[proposer].propose().unwrap();

    // Envelope/header remain authentic, but this body no longer matches its commitments.
    proposal.proposal.block.transactions.clear();

    for (node, archive) in nodes.iter_mut().zip(&mut archives) {
        assert_eq!(node.accept_proposal(&proposal).unwrap().block, None);
        assert!(node.precommit().is_err());
        assert!(node.commit(archive).is_err());
        assert_eq!(
            node.timeout(node.timeout_event().unwrap())
                .unwrap()
                .unwrap()
                .block,
            None
        );

        node.timeout(node.timeout_event().unwrap()).unwrap();
        assert_eq!(node.local().round(), 1);
        assert_eq!(node.producer().pending_count(), 1);
        assert_eq!(archive.checkpoint().unwrap().height, 0);
        assert_eq!(
            node.timeout(node.timeout_event().unwrap())
                .unwrap()
                .unwrap()
                .block,
            None
        );
    }
}