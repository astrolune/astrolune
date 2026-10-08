// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Distributed message delivery, durable recovery, and adversarial reference-network checks.

use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{
    network::{NetworkNode, PreparedExchange, StaticNetwork},
    network_wire::{NetworkMessage, SyncRequest, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use state::StateDatabase;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Address, Hash256, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn double_vote_proofs_are_durable_bounded_and_never_count_forged_accusations() {
    let fixture = Fixture::new(4);
    let mut node = fixture.open(1);
    let context = fixture.network.committee(1).unwrap();
    let mut first = consensus::Vote {
        chain_id: 42,
        committee_root: context.root(),
        height: 1,
        round: 0,
        phase: consensus::VotePhase::Prevote,
        block: None,
        voter: ValidatorId(blake2s(&ed25519_public_key(&[2; 32])).0),
        signature: [0; 64],
    };
    first.signature = ed25519_sign(&[2; 32], &first.signing_hash().0);
    let mut second = first.clone();
    second.block = Some(Hash256([44; 32]));
    second.signature = ed25519_sign(&[2; 32], &second.signing_hash().0);
    let packet = |vote| {
        encode_exchange(
            fixture.network.genesis_hash(),
            &[NetworkMessage::Vote(vote)],
        )
        .unwrap()
    };
    assert_eq!(node.receive(&packet(first.clone())).unwrap(), 0);
    let mut forged = second.clone();
    forged.signature[0] ^= 1;
    assert_eq!(node.receive(&packet(forged)).unwrap(), 1);
    assert_eq!(node.evidence().count(), 0);
    assert!(!fixture.path.join("1/equivocation").exists());
    assert_eq!(node.receive(&packet(second.clone())).unwrap(), 1);
    let proof = node.evidence().next().unwrap().clone();
    proof.verify(&context).unwrap();
    for _ in 0..10 {
        assert_eq!(node.receive(&packet(second.clone())).unwrap(), 1);
    }
    assert_eq!(node.evidence().count(), 1);
    let path = fixture
        .path
        .join("1/equivocation")
        .join(format!("{}.bin", first.voter));
    assert_eq!(std::fs::read(&path).unwrap(), proof.encode());
    drop(node);
    let recovered = fixture.open(1);
    assert_eq!(recovered.evidence().next(), Some(&proof));
    assert_eq!(recovered.storage().checkpoint().unwrap().height, 0);
    drop(recovered);
    let mut bytes = proof.encode();
    bytes[379] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    let signer = DurableSigner::open(
        fixture.path.join("1/signing.journal"),
        SigningContext {
            chain_id: 42,
            genesis: fixture.network.genesis_hash(),
        },
        [1; 32],
    )
    .unwrap();
    assert!(
        NetworkNode::open(
            fixture.network.clone(),
            &fixture.path.join("1"),
            signer,
            Duration::from_millis(100)
        )
        .is_err()
    );
}

#[test]
fn evidence_persistence_failure_is_local_and_never_silently_dropped() {
    let fixture = Fixture::new(4);
    let mut node = fixture.open(1);
    std::fs::write(fixture.path.join("1/equivocation"), b"not a directory").unwrap();
    let context = fixture.network.committee(1).unwrap();
    let mut votes = Vec::new();
    for block in [None, Some(Hash256([7; 32]))] {
        let mut vote = consensus::Vote {
            chain_id: 42,
            committee_root: context.root(),
            height: 1,
            round: 0,
            phase: consensus::VotePhase::Prevote,
            block,
            voter: ValidatorId(blake2s(&ed25519_public_key(&[2; 32])).0),
            signature: [0; 64],
        };
        vote.signature = ed25519_sign(&[2; 32], &vote.signing_hash().0);
        votes.push(NetworkMessage::Vote(vote));
    }
    assert!(matches!(
        node.receive(&encode_exchange(fixture.network.genesis_hash(), &votes).unwrap()),
        Err(node::network::NetworkNodeError::Local(_))
    ));
    assert_eq!(node.evidence().count(), 0);
}
struct Fixture {
    path: PathBuf,
    network: StaticNetwork,
    genesis: Genesis,
}
impl Fixture {
    fn new(count: u8) -> Self {
        Self::with_runtime(count, 1)
    }
    fn with_runtime(count: u8, runtime_version: u32) -> Self {
        Self::with_profile(count, runtime_version, 1, usize::from(count))
    }
    fn with_profile(count: u8, runtime_version: u32, version: u16, committee_size: usize) -> Self {
        Self::with_allocations(
            count,
            runtime_version,
            version,
            committee_size,
            vec![Allocation {
                address: address_from_public_key(&ed25519_public_key(&[99; 32])),
                amount: 1_000_000,
            }],
        )
    }
    fn with_allocations(
        count: u8,
        runtime_version: u32,
        version: u16,
        committee_size: usize,
        allocations: Vec<Allocation>,
    ) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let keys: Vec<_> = (1..=count)
            .map(|index| ed25519_public_key(&[index; 32]))
            .collect();
        let mut validators: Vec<_> = keys
            .iter()
            .map(|key| GenesisValidator {
                id: ValidatorId(blake2s(key).0),
                weight: 1,
            })
            .collect();
        validators.sort_by_key(|validator| validator.id);
        let genesis = Genesis {
            version,
            chain_id: 42,
            committee_size,
            rotation_count: 1,
            runtime_version,
            capacity: Resources {
                compute: 1_000_000,
                memory: 1_000_000,
                io: 1_000_000,
                bandwidth: 1_000_000,
            },
            validators,
            allocations,
        };
        let network = StaticNetwork::new(genesis.clone(), keys).unwrap();
        for index in 1..=count {
            let directory = path.join(index.to_string());
            std::fs::create_dir(&directory).unwrap();
            drop(
                DurableSigner::create_protected(
                    directory.join("signing.journal"),
                    SigningContext {
                        chain_id: 42,
                        genesis: network.genesis_hash(),
                    },
                    [index; 32],
                )
                .unwrap(),
            );
        }
        Self {
            path,
            network,
            genesis,
        }
    }
    fn open(&self, index: u8) -> NetworkNode {
        let directory = self.path.join(index.to_string());
        let signer = DurableSigner::open(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: self.network.genesis_hash(),
            },
            [index; 32],
        )
        .unwrap();
        NetworkNode::open(
            self.network.clone(),
            &directory,
            signer,
            Duration::from_millis(100),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn exchange(nodes: &mut [NetworkNode], now: Instant) {
    for index in 0..nodes.len() {
        let request = nodes[index].request();
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for response in responses {
            nodes[index].receive(&response).unwrap();
        }
        nodes[index].tick(now).unwrap();
    }
}

fn transfer() -> Transaction {
    transfer_from(99)
}

fn transfer_from(seed: u8) -> Transaction {
    let key = ed25519_public_key(&[seed; 32]);
    let sender = address_from_public_key(&key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 42,
        sender,
        nonce: 0,
        expires_at: 100,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
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
    tx.signature = ed25519_sign(&[seed; 32], signing_hash(&tx).as_bytes());
    tx
}

#[test]
#[allow(clippy::too_many_lines)]
fn background_catchup_matches_serial_with_bounded_queued_exchanges() {
    let source_fixture = Fixture::new(1);
    let serial_fixture = Fixture::new(1);
    let background_fixture = Fixture::new(1);
    let mut source = source_fixture.open(1);
    source.submit_transaction(transfer()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while source.request().height < 4 {
        assert!(Instant::now() < deadline);
        source.tick(Instant::now()).unwrap();
    }
    let mut serial = serial_fixture.open(1);
    let mut background = background_fixture.open(1);
    let mut serial_observer = ObserverNode::open(
        serial_fixture.network.clone(),
        &serial_fixture.path.join("observer"),
    )
    .unwrap();
    let mut background_observer = ObserverNode::open(
        background_fixture.network.clone(),
        &background_fixture.path.join("observer"),
    )
    .unwrap();
    background.enable_execution_pipeline().unwrap();
    background_observer.enable_execution_pipeline().unwrap();
    let initial = background.storage().checkpoint().copied();
    let initial_root = background.storage().state().root();
    let request = background.request();
    for height in 1..=3 {
        let bytes = source.respond(SyncRequest { height, ..request }).unwrap();
        assert_eq!(serial.receive(&bytes).unwrap(), 0);
        assert_eq!(serial_observer.receive(&bytes).unwrap(), 0);
        assert_eq!(background.receive(&bytes).unwrap(), 0);
        assert_eq!(background_observer.receive(&bytes).unwrap(), 0);
    }
    let mut pending = transfer();
    pending.nonce = 1;
    pending.signature = ed25519_sign(&[99; 32], signing_hash(&pending).as_bytes());
    let pending =
        encode_exchange(request.genesis, &[NetworkMessage::Transaction(pending)]).unwrap();
    for node in [&mut serial, &mut background] {
        assert_eq!(node.receive(&pending).unwrap(), 0);
    }
    for node in [&mut serial_observer, &mut background_observer] {
        assert_eq!(node.receive(&pending).unwrap(), 0);
    }
    assert!(!background.can_receive());
    assert!(!background_observer.can_receive());
    assert!(background.receive(&pending).is_err());
    assert!(background_observer.receive(&pending).is_err());
    // The first poll starts execution; only a subsequent poll may publish it.
    assert_eq!(background.poll_execution().unwrap(), 0);
    assert_eq!(background_observer.poll_execution().unwrap(), 0);
    assert_eq!(background.storage().checkpoint().copied(), initial);
    assert_eq!(background_observer.storage().checkpoint().copied(), initial);
    assert_eq!(background.storage().state().root(), initial_root);
    assert_eq!(background_observer.storage().state().root(), initial_root);
    assert_eq!(background.request(), request);
    background.respond(request).unwrap();
    background_observer.respond(request).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(Instant::now() < deadline, "queued catchup did not finish");
        assert_eq!(background.poll_execution().unwrap(), 0);
        assert_eq!(background_observer.poll_execution().unwrap(), 0);
        if background.request().height == 4
            && background_observer.request().height == 4
            && background.respond(background.request()).unwrap()
                == serial.respond(serial.request()).unwrap()
            && background_observer
                .respond(background_observer.request())
                .unwrap()
                == pending
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(background.can_receive());
    assert!(background_observer.can_receive());
    for checkpoint in [
        background.storage().checkpoint(),
        serial_observer.storage().checkpoint(),
        background_observer.storage().checkpoint(),
    ] {
        assert_eq!(checkpoint, serial.storage().checkpoint());
    }
    for root in [
        background.storage().state().root(),
        serial_observer.storage().state().root(),
        background_observer.storage().state().root(),
    ] {
        assert_eq!(root, serial.storage().state().root());
    }
    for height in 1..=3 {
        let request = SyncRequest { height, ..request };
        assert_eq!(
            background.respond(request).unwrap(),
            source.respond(request).unwrap()
        );
        assert_eq!(
            background_observer.respond(request).unwrap(),
            source.respond(request).unwrap()
        );
    }
}

#[test]
fn background_production_keeps_captured_candidate_and_recovers_after_three_heights() {
    let serial_fixture = Fixture::new(1);
    let background_fixture = Fixture::new(1);
    let mut serial = serial_fixture.open(1);
    let mut background = background_fixture.open(1);
    background.enable_execution_pipeline().unwrap();
    // Start an empty candidate, then change admission while detached work owns its snapshot.
    background.tick(Instant::now()).unwrap();
    // The serial reference chooses the same empty first candidate before admission.
    serial.tick(Instant::now()).unwrap();
    serial.submit_transaction(transfer()).unwrap();
    background.submit_transaction(transfer()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while serial.request().height < 4 || background.request().height < 4 {
        assert!(
            Instant::now() < deadline,
            "background production did not finish"
        );
        if serial.request().height < 4 {
            serial.tick(Instant::now()).unwrap();
        }
        if background.request().height < 4 {
            assert_eq!(background.poll_execution().unwrap(), 0);
            background.tick(Instant::now()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        background.storage().checkpoint(),
        serial.storage().checkpoint()
    );
    assert_eq!(
        background.storage().state().root(),
        serial.storage().state().root()
    );
    let (first, _) = background.storage().read_finalized(1).unwrap().unwrap();
    assert!(first.transactions.is_empty());
    let (second, _) = background.storage().read_finalized(2).unwrap().unwrap();
    assert_eq!(second.transactions, vec![transfer()]);
    let checkpoint = background.storage().checkpoint().copied();
    drop(background);
    let mut recovered = background_fixture.open(1);
    assert_eq!(recovered.storage().checkpoint().copied(), checkpoint);
    recovered.enable_execution_pipeline().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while recovered.request().height < 5 || serial.request().height < 5 {
        assert!(
            Instant::now() < deadline,
            "recovered background production did not finish"
        );
        if recovered.request().height < 5 {
            assert_eq!(recovered.poll_execution().unwrap(), 0);
            recovered.tick(Instant::now()).unwrap();
        }
        if serial.request().height < 5 {
            serial.tick(Instant::now()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        recovered.storage().checkpoint(),
        serial.storage().checkpoint()
    );
}

#[test]
fn background_production_progresses_during_continuous_admission() {
    let mut allocations: Vec<_> = (100..=179)
        .map(|seed| Allocation {
            address: address_from_public_key(&ed25519_public_key(&[seed; 32])),
            amount: 1_000_000,
        })
        .collect();
    allocations.sort_by_key(|allocation| allocation.address);
    let fixture = Fixture::with_allocations(1, 1, 1, 1, allocations);
    let transactions: Vec<_> = (100..=179).map(transfer_from).collect();
    let mut node = fixture.open(1);
    node.enable_execution_pipeline().unwrap();
    node.tick(Instant::now()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    for tx in transactions {
        assert!(
            Instant::now() < deadline,
            "production exceeded its deadline"
        );
        // Every collection observes a newer admission sequence than its captured job.
        node.submit_transaction(tx).unwrap();
        assert_eq!(node.poll_execution().unwrap(), 0);
        node.tick(Instant::now()).unwrap();
        if node.request().height > 1 {
            let (first, _) = node.storage().read_finalized(1).unwrap().unwrap();
            assert!(first.transactions.is_empty());
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("each later admission postponed the captured candidate");
}

#[test]
fn background_production_gets_a_turn_with_a_nonempty_receive_backlog() {
    let fixture = Fixture::new(1);
    let mut node = fixture.open(1);
    node.enable_execution_pipeline().unwrap();
    let packet = encode_exchange(
        node.request().genesis,
        &vec![NetworkMessage::Transaction(transfer()); 512],
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while node.request().height == 1 {
        assert!(
            Instant::now() < deadline,
            "receive backlog starved production"
        );
        while node.can_receive() {
            node.receive(&packet).unwrap();
        }
        // Refill faster than the bounded message budget can drain the mailbox.
        node.poll_execution().unwrap();
        node.tick(Instant::now()).unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    let (first, _) = node.storage().read_finalized(1).unwrap().unwrap();
    assert_eq!(first.transactions, vec![transfer()]);
}

#[test]
fn prepared_live_responses_own_their_snapshot_across_node_changes() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let request = validator.request();
    let validator_before = validator.respond(request).unwrap();
    let observer_before = observer.respond(request).unwrap();
    let validator_snapshot = validator.prepare_response(request).unwrap();
    let observer_snapshot = observer.prepare_response(request).unwrap();

    let tx = transfer();
    validator.submit_transaction(tx.clone()).unwrap();
    observer.submit_transaction(tx.clone()).unwrap();
    let validator_after = validator.respond(request).unwrap();
    let observer_after = observer.respond(request).unwrap();
    assert_ne!(validator_after, validator_before);
    assert_ne!(observer_after, observer_before);
    assert_eq!(
        observer_after,
        encode_exchange(request.genesis, &[NetworkMessage::Transaction(tx)]).unwrap()
    );
    assert_eq!(
        validator
            .prepare_response(request)
            .unwrap()
            .encode()
            .unwrap(),
        validator_after
    );
    assert_eq!(
        observer
            .prepare_response(request)
            .unwrap()
            .encode()
            .unwrap(),
        observer_after
    );

    // An encoder worker needs neither a node borrow nor a live node instance.
    drop(validator);
    drop(observer);
    let encoded = std::thread::spawn(move || {
        (
            validator_snapshot.encode().unwrap(),
            observer_snapshot.encode().unwrap(),
        )
    })
    .join()
    .unwrap();
    assert_eq!(encoded, (validator_before, observer_before));
}

#[test]
fn prepared_finalized_and_future_responses_match_for_both_roles() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    validator.submit_transaction(transfer()).unwrap();
    let request = validator.request();
    let now = Instant::now();
    for step in 0..20 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height > request.height {
            break;
        }
    }
    assert!(validator.request().height > request.height);
    let finalized = validator.respond(request).unwrap();
    assert!(matches!(
        decode_exchange(request.genesis, &finalized)
            .unwrap()
            .as_slice(),
        [NetworkMessage::Finalized { .. }]
    ));
    observer.receive(&finalized).unwrap();
    assert_eq!(observer.respond(request).unwrap(), finalized);
    assert_eq!(
        validator
            .prepare_response(request)
            .unwrap()
            .encode()
            .unwrap(),
        finalized
    );
    assert_eq!(
        observer
            .prepare_response(request)
            .unwrap()
            .encode()
            .unwrap(),
        finalized
    );

    let future = SyncRequest {
        height: validator.request().height + 1,
        ..request
    };
    let empty = encode_exchange(request.genesis, &[]).unwrap();
    assert_eq!(validator.respond(future).unwrap(), empty);
    assert_eq!(observer.respond(future).unwrap(), empty);
    assert_eq!(
        validator
            .prepare_response(future)
            .unwrap()
            .encode()
            .unwrap(),
        empty
    );
    assert_eq!(
        observer.prepare_response(future).unwrap().encode().unwrap(),
        empty
    );
}

#[test]
fn prepared_live_exchanges_own_bytes_and_use_current_admission_state() {
    for admit_before_apply in [false, true] {
        let raw_fixture = Fixture::new(1);
        let prepared_fixture = Fixture::new(1);
        let mut raw_validator = raw_fixture.open(1);
        let mut prepared_validator = prepared_fixture.open(1);
        let mut raw_observer = ObserverNode::open(
            raw_fixture.network.clone(),
            &raw_fixture.path.join("observer"),
        )
        .unwrap();
        let mut prepared_observer = ObserverNode::open(
            prepared_fixture.network.clone(),
            &prepared_fixture.path.join("observer"),
        )
        .unwrap();
        let request = raw_validator.request();
        let tx = transfer();
        let raw_bytes =
            encode_exchange(request.genesis, &[NetworkMessage::Transaction(tx.clone())]).unwrap();
        let worker_bytes = raw_bytes.clone();
        let (validator_exchange, observer_exchange) = std::thread::spawn(move || {
            let validator = PreparedExchange::decode(request.genesis, &worker_bytes).unwrap();
            let observer = PreparedExchange::decode(request.genesis, &worker_bytes).unwrap();
            drop(worker_bytes);
            (validator, observer)
        })
        .join()
        .unwrap();

        // Preparation does not reserve admission: application sees the current pool.
        if admit_before_apply {
            raw_validator.submit_transaction(tx.clone()).unwrap();
            prepared_validator.submit_transaction(tx.clone()).unwrap();
            raw_observer.submit_transaction(tx.clone()).unwrap();
            prepared_observer.submit_transaction(tx).unwrap();
        }
        let expected_rejected = usize::from(admit_before_apply);
        assert_eq!(
            raw_validator.receive(&raw_bytes).unwrap(),
            expected_rejected
        );
        assert_eq!(
            prepared_validator
                .receive_prepared(validator_exchange)
                .unwrap(),
            expected_rejected
        );
        assert_eq!(raw_observer.receive(&raw_bytes).unwrap(), expected_rejected);
        assert_eq!(
            prepared_observer
                .receive_prepared(observer_exchange)
                .unwrap(),
            expected_rejected
        );
        assert_eq!(
            raw_validator.respond(request).unwrap(),
            prepared_validator.respond(request).unwrap()
        );
        assert_eq!(raw_observer.respond(request).unwrap(), raw_bytes);
        assert_eq!(prepared_observer.respond(request).unwrap(), raw_bytes);
        assert_eq!(
            raw_validator.storage().checkpoint(),
            prepared_validator.storage().checkpoint()
        );
        assert_eq!(
            raw_validator.storage().state().root(),
            prepared_validator.storage().state().root()
        );
        assert_eq!(
            raw_observer.storage().checkpoint(),
            prepared_observer.storage().checkpoint()
        );
        assert_eq!(
            raw_observer.storage().state().root(),
            prepared_observer.storage().state().root()
        );
    }
}

#[test]
fn prepared_finalized_exchanges_match_sequential_catch_up_for_both_roles() {
    let source_fixture = Fixture::new(1);
    let raw_fixture = Fixture::new(1);
    let prepared_fixture = Fixture::new(1);
    let mut source = source_fixture.open(1);
    source.submit_transaction(transfer()).unwrap();
    let now = Instant::now();
    for step in 0..40 {
        source.tick(now + Duration::from_millis(step)).unwrap();
        if source.request().height >= 4 {
            break;
        }
    }
    assert!(source.request().height >= 4);
    let mut raw_validator = raw_fixture.open(1);
    let mut prepared_validator = prepared_fixture.open(1);
    let mut raw_observer = ObserverNode::open(
        raw_fixture.network.clone(),
        &raw_fixture.path.join("observer"),
    )
    .unwrap();
    let mut prepared_observer = ObserverNode::open(
        prepared_fixture.network.clone(),
        &prepared_fixture.path.join("observer"),
    )
    .unwrap();

    while raw_validator.request().height < source.request().height {
        let request = raw_validator.request();
        let bytes = source.respond(request).unwrap();
        let validator_exchange = PreparedExchange::decode(request.genesis, &bytes).unwrap();
        let observer_exchange = PreparedExchange::decode(request.genesis, &bytes).unwrap();
        assert_eq!(raw_validator.receive(&bytes).unwrap(), 0);
        assert_eq!(
            prepared_validator
                .receive_prepared(validator_exchange)
                .unwrap(),
            0
        );
        assert_eq!(raw_observer.receive(&bytes).unwrap(), 0);
        assert_eq!(
            prepared_observer
                .receive_prepared(observer_exchange)
                .unwrap(),
            0
        );
        for checkpoint in [
            prepared_validator.storage().checkpoint(),
            raw_observer.storage().checkpoint(),
            prepared_observer.storage().checkpoint(),
        ] {
            assert_eq!(checkpoint, raw_validator.storage().checkpoint());
        }
        for root in [
            prepared_validator.storage().state().root(),
            raw_observer.storage().state().root(),
            prepared_observer.storage().state().root(),
        ] {
            assert_eq!(root, raw_validator.storage().state().root());
        }
        assert_eq!(prepared_validator.respond(request).unwrap(), bytes);
        assert_eq!(raw_observer.respond(request).unwrap(), bytes);
        assert_eq!(prepared_observer.respond(request).unwrap(), bytes);
        assert_eq!(
            raw_validator.respond(raw_validator.request()).unwrap(),
            prepared_validator
                .respond(prepared_validator.request())
                .unwrap()
        );
    }
    assert_eq!(
        raw_validator.storage().checkpoint(),
        source.storage().checkpoint()
    );
    assert_eq!(
        raw_validator.storage().state().root(),
        source.storage().state().root()
    );
}

#[test]
fn prepared_exchange_requires_complete_decoding_before_application() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let request = validator.request();
    let validator_before = validator.respond(request).unwrap();
    let observer_before = observer.respond(request).unwrap();
    let checkpoint = *validator.storage().checkpoint().unwrap();
    let root = validator.storage().state().root();
    let tx = transfer();
    let bytes = encode_exchange(
        request.genesis,
        &[
            NetworkMessage::Transaction(tx.clone()),
            NetworkMessage::Transaction(tx),
        ],
    )
    .unwrap();
    let incomplete = &bytes[..bytes.len() - 1];
    assert!(matches!(
        PreparedExchange::decode(request.genesis, incomplete),
        Err(node::network::NetworkNodeError::Input(_))
    ));
    assert!(validator.receive(incomplete).is_err());
    assert!(observer.receive(incomplete).is_err());
    assert_eq!(validator.respond(request).unwrap(), validator_before);
    assert_eq!(observer.respond(request).unwrap(), observer_before);
    assert_eq!(validator.storage().checkpoint(), Some(&checkpoint));
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    assert_eq!(validator.storage().state().root(), root);
    assert_eq!(observer.storage().state().root(), root);

    assert_eq!(
        validator
            .receive_prepared(PreparedExchange::decode(request.genesis, &bytes).unwrap())
            .unwrap(),
        1
    );
    assert_eq!(
        observer
            .receive_prepared(PreparedExchange::decode(request.genesis, &bytes).unwrap())
            .unwrap(),
        1
    );
}

#[test]
fn prepared_exchanges_preserve_the_receiving_nodes_genesis_binding() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let request = validator.request();
    let validator_before = validator.respond(request).unwrap();
    let observer_before = observer.respond(request).unwrap();
    let other_genesis = Hash256([200; 32]);
    assert_ne!(other_genesis, request.genesis);
    let bytes = encode_exchange(other_genesis, &[NetworkMessage::Transaction(transfer())]).unwrap();
    assert!(matches!(
        validator.receive_prepared(PreparedExchange::decode(other_genesis, &bytes).unwrap()),
        Err(node::network::NetworkNodeError::Input(_))
    ));
    assert!(matches!(
        observer.receive_prepared(PreparedExchange::decode(other_genesis, &bytes).unwrap()),
        Err(node::network::NetworkNodeError::Input(_))
    ));
    assert_eq!(validator.respond(request).unwrap(), validator_before);
    assert_eq!(observer.respond(request).unwrap(), observer_before);
    assert_eq!(validator.storage().checkpoint().unwrap().height, 0);
    assert_eq!(observer.storage().checkpoint().unwrap().height, 0);
}

#[test]
fn payment_gossip_three_of_four_commit_and_late_node_catches_up_after_restart() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=3).map(|index| fixture.open(index)).collect();
    let tx = transfer();
    nodes[0].submit_transaction(tx.clone()).unwrap();
    let started = Instant::now();
    for step in 0..400 {
        exchange(&mut nodes, started + Duration::from_millis(step * 20));
        if nodes.iter().all(|node| node.request().height >= 5) {
            break;
        }
    }
    assert!(
        nodes.iter().all(|node| node.request().height >= 5),
        "one offline validator must not prevent quorum progress"
    );
    // Stop producing and catch every node up to the same certified head.
    let highest = nodes
        .iter()
        .map(|node| node.request().height)
        .max()
        .unwrap();
    let source = nodes
        .iter()
        .position(|node| node.request().height == highest)
        .unwrap();
    for index in 0..nodes.len() {
        while nodes[index].request().height < highest {
            let bytes = nodes[source].respond(nodes[index].request()).unwrap();
            nodes[index].receive(&bytes).unwrap();
        }
    }
    let checkpoint = *nodes[0].storage().checkpoint().unwrap();
    assert!(
        nodes
            .iter()
            .all(|node| node.storage().checkpoint() == Some(&checkpoint))
    );
    let state = nodes[0].storage().state().snapshot().unwrap();
    assert_eq!(
        state::read_account(state.as_ref(), Address([77; 32])).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 123
        })
    );
    drop(nodes);
    let source = fixture.open(1);
    let mut late = fixture.open(4);
    while late.request().height < source.request().height {
        late.receive(&source.respond(late.request()).unwrap())
            .unwrap();
    }
    assert_eq!(late.storage().checkpoint(), source.storage().checkpoint());
    assert_eq!(
        late.storage().state().root(),
        source.storage().state().root()
    );
    assert!(
        late.submit_transaction(tx).is_err(),
        "finalized nonce must reject replay"
    );
}

#[test]
fn contracts_finalize_recover_and_catch_up_with_authenticated_history() {
    use transaction::{
        ContractAction, ContractPayload, contract_address, contract_code_key, contract_state_key,
    };
    let fixture = Fixture::with_runtime(4, 2);
    let mut nodes: Vec<_> = (1..=3).map(|index| fixture.open(index)).collect();
    let mut deploy = transfer();
    let code = wat::parse_str(r#"(module
        (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1 1) (data (i32.const 0) "kv")
        (func (export "call") (result i32)
          (drop (call $put (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 1))) (i32.const 0)))"#).unwrap();
    let contract = contract_address(42, deploy.sender, 0);
    deploy.lane = types::TransactionLane::Contracts;
    deploy.payload = ContractPayload {
        public_key: ed25519_public_key(&[99; 32]),
        action: ContractAction::Deploy(code.clone()),
    }
    .to_bytes();
    deploy.access_list = vec![
        state::account_key(deploy.sender),
        contract_code_key(contract),
    ];
    deploy.access_list.sort();
    deploy.resource_limit = Resources {
        compute: 10_000,
        memory: 65_568,
        io: 10_000,
        bandwidth: 4096,
    };
    deploy.signature = ed25519_sign(&[99; 32], signing_hash(&deploy).as_bytes());
    nodes[0].submit_transaction(deploy.clone()).unwrap();
    let started = Instant::now();
    let key = contract_state_key(contract, b"k");
    let mut call = deploy.clone();
    call.nonce = 1;
    call.payload = ContractPayload {
        public_key: ed25519_public_key(&[99; 32]),
        action: ContractAction::Call {
            address: contract,
            input: vec![],
            keys: vec![b"k".to_vec()],
        },
    }
    .to_bytes();
    call.access_list.push(key.clone());
    call.access_list.sort();
    call.signature = ed25519_sign(&[99; 32], signing_hash(&call).as_bytes());
    let mut submitted = false;
    for step in 0..500 {
        exchange(&mut nodes, started + Duration::from_millis(step * 20));
        if !submitted
            && nodes.iter().all(|node| {
                node.storage()
                    .state()
                    .get(&contract_code_key(contract))
                    .is_some()
            })
        {
            nodes[0].submit_transaction(call.clone()).unwrap();
            submitted = true;
        }
        if nodes
            .iter()
            .all(|node| node.storage().state().get(&key) == Some(b"v".as_slice()))
        {
            break;
        }
    }
    assert!(submitted);
    assert!(
        nodes
            .iter()
            .all(|node| node.storage().state().get(&key) == Some(b"v".as_slice()))
    );
    drop(nodes);
    let source = fixture.open(1);
    let mut late = fixture.open(4);
    while late.request().height < source.request().height {
        late.receive(&source.respond(late.request()).unwrap())
            .unwrap();
    }
    assert_eq!(
        source.storage().state().root(),
        late.storage().state().root()
    );
    assert_eq!(
        late.storage().state().get(&contract_code_key(contract)),
        Some(code.as_slice())
    );
    assert_eq!(late.storage().state().get(&key), Some(b"v".as_slice()));
    assert!(late.submit_transaction(call).is_err());
    drop(late);
    assert_eq!(
        fixture.open(4).storage().state().root(),
        source.storage().state().root()
    );
}

#[test]
fn two_of_four_never_finalize_and_forged_input_cannot_advance_state() {
    let fixture = Fixture::new(4);
    let mut nodes = vec![fixture.open(1), fixture.open(2)];
    let started = Instant::now();
    for step in 0..100 {
        exchange(&mut nodes, started + Duration::from_millis(step * 30));
    }
    assert!(nodes.iter().all(|node| node.request().height == 1));
    assert!(nodes.iter().all(|node| node.round() > 0));
    let before = *nodes[0].storage().checkpoint().unwrap();
    let messages = vec![NetworkMessage::Vote(consensus::Vote {
        chain_id: 42,
        height: 1,
        round: nodes[0].round(),
        committee_root: fixture.network.committee(1).unwrap().root(),
        voter: fixture.genesis.validators[0].id,
        phase: consensus::VotePhase::Precommit,
        block: Some(Hash256([255; 32])),
        signature: [0; 64],
    })];
    let rejected = nodes[0]
        .receive(&encode_exchange(fixture.network.genesis_hash(), &messages).unwrap())
        .unwrap();
    assert_eq!(
        rejected, 1,
        "forged signature from a registered member must be rejected"
    );
    assert_eq!(nodes[0].storage().checkpoint(), Some(&before));
    assert!(
        nodes[0]
            .respond(SyncRequest {
                genesis: Hash256([1; 32]),
                height: 1
            })
            .is_err()
    );
    assert!(
        nodes[0]
            .receive(&encode_exchange(Hash256([1; 32]), &[]).unwrap())
            .is_err()
    );
}

#[test]
fn all_nodes_restart_after_precommit_and_recover_the_payment_body() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for node in &mut nodes {
        node.submit_transaction(transfer()).unwrap();
    }
    let now = Instant::now();
    // Propose, distribute proposals/prevotes, then lock without delivering precommits.
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    let request = nodes[0].request();
    for _ in 0..2 {
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for node in &mut nodes {
            for bytes in &responses {
                node.receive(bytes).unwrap();
            }
        }
    }
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    assert!(nodes.iter().all(|node| node.request().height == 1));
    drop(nodes);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for step in 0..40 {
        exchange(&mut nodes, now + Duration::from_millis(step * 10));
        if nodes.iter().all(|node| node.request().height > 1) {
            break;
        }
    }
    assert!(nodes.iter().all(|node| node.request().height > 1));
    for node in &nodes {
        let snapshot = node.storage().state().snapshot().unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            123
        );
    }
}

#[test]
fn registry_and_envelopes_fail_closed() {
    let fixture = Fixture::new(1);
    assert!(
        StaticNetwork::new(fixture.genesis.clone(), vec![ed25519_public_key(&[2; 32])]).is_err()
    );
    let bytes = encode_exchange(
        fixture.network.genesis_hash(),
        &[NetworkMessage::Transaction(transfer())],
    )
    .unwrap();
    for length in 0..bytes.len() {
        assert!(decode_exchange(fixture.network.genesis_hash(), &bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_exchange(fixture.network.genesis_hash(), &trailing).is_err());
    let mut oversized = bytes.clone();
    oversized[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_exchange(fixture.network.genesis_hash(), &oversized).is_err());
    let decoded = decode_exchange(fixture.network.genesis_hash(), &bytes).unwrap();
    assert_eq!(
        encode_exchange(fixture.network.genesis_hash(), &decoded).unwrap(),
        bytes
    );
}

#[test]
fn locked_value_survives_round_change_when_precommits_are_lost() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for node in &mut nodes {
        node.submit_transaction(transfer()).unwrap();
    }
    let now = Instant::now();
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    let request = nodes[0].request();
    for _ in 0..2 {
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for node in &mut nodes {
            for bytes in &responses {
                node.receive(bytes).unwrap();
            }
        }
    }
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    // Every node locked the available payment, but no precommit was delivered.
    for node in &mut nodes {
        node.tick(now + Duration::from_millis(101)).unwrap();
    }
    assert!(nodes.iter().all(|node| node.round() == 1));
    for step in 0..40 {
        exchange(&mut nodes, now + Duration::from_millis(102 + step));
        if nodes.iter().all(|node| node.request().height > 1) {
            break;
        }
    }
    assert!(nodes.iter().all(|node| node.request().height > 1));
    for node in &nodes {
        let snapshot = node.storage().state().snapshot().unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            123
        );
    }
}

#[test]
fn demonstration_history_is_rejected_before_network_signing() {
    use node::{FullNodeService, NodeService, ProducerConfig};
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1");
    let mut demo = FullNodeService::open_with_genesis(
        ProducerConfig {
            chain_id: 42,
            block_capacity: fixture.genesis.capacity,
            ..ProducerConfig::default()
        },
        path.join("chain.bin"),
        &fixture.genesis,
    )
    .unwrap();
    for _ in 0..5 {
        demo.advance().unwrap();
    }
    drop(demo);
    let signer = DurableSigner::open(
        path.join("signing.journal"),
        SigningContext {
            chain_id: 42,
            genesis: fixture.network.genesis_hash(),
        },
        [1; 32],
    )
    .unwrap();
    assert!(
        NetworkNode::open(
            fixture.network.clone(),
            &path,
            signer,
            Duration::from_millis(100)
        )
        .is_err()
    );
}

#[test]
fn certified_history_cannot_be_downgraded_to_demonstration_finality() {
    let fixture = Fixture::new(1);
    let mut node = fixture.open(1);
    let now = Instant::now();
    for step in 0..4 {
        node.tick(now + Duration::from_millis(step)).unwrap();
        if node.request().height > 1 {
            break;
        }
    }
    assert_eq!(node.request().height, 2);
    drop(node);
    let archive = fixture.path.join("1/chain.bin");
    let bytes = std::fs::read(&archive).unwrap();
    let config = node::ProducerConfig {
        chain_id: 42,
        block_capacity: fixture.genesis.capacity,
        ..node::ProducerConfig::default()
    };
    assert!(node::FullNodeService::open_with_genesis(config, &archive, &fixture.genesis).is_err());
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}

#[test]
fn every_network_message_has_canonical_mutation_and_truncation_behavior() {
    let fixture = Fixture::new(1);
    let mut node = fixture.open(1);
    node.submit_transaction(transfer()).unwrap();
    let request = node.request();
    let now = Instant::now();
    node.tick(now).unwrap();
    let mut messages = decode_exchange(request.genesis, &node.respond(request).unwrap()).unwrap();
    node.tick(now + Duration::from_millis(1)).unwrap();
    messages.extend(decode_exchange(request.genesis, &node.respond(request).unwrap()).unwrap());
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Proposal { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Vote(_)))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Finalized { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::ValidValue { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Transaction(_)))
    );
    let bytes = encode_exchange(request.genesis, &messages).unwrap();
    for offset in 0..bytes.len() {
        assert!(decode_exchange(request.genesis, &bytes[..offset]).is_err());
        let mut mutated = bytes.clone();
        mutated[offset] ^= 0x80;
        if let Ok(decoded) = decode_exchange(request.genesis, &mutated) {
            assert_eq!(encode_exchange(request.genesis, &decoded).unwrap(), mutated);
        }
    }
    let mut expected_request = b"ALRQ\x01\0\0\0".to_vec();
    expected_request.extend_from_slice(&request.genesis.0);
    expected_request.extend_from_slice(&1u64.to_le_bytes());
    assert_eq!(request.encode(), expected_request);
}

#[test]
fn observer_gossips_payments_syncs_relays_and_recovers_without_signing_authority() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    let mut validator = fixture.open(1);
    let tx = transfer();
    observer.submit_transaction(tx.clone()).unwrap();
    let pending = observer.respond(validator.request()).unwrap();
    assert!(
        decode_exchange(fixture.network.genesis_hash(), &pending)
            .unwrap()
            .iter()
            .all(|message| matches!(message, NetworkMessage::Transaction(_)))
    );
    validator.receive(&pending).unwrap();
    let now = Instant::now();
    for step in 0..20 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height >= 4 {
            break;
        }
    }
    assert_eq!(validator.request().height, 4);
    while observer.request().height < validator.request().height {
        assert_eq!(
            observer
                .receive(&validator.respond(observer.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(
        observer.storage().checkpoint(),
        validator.storage().checkpoint()
    );
    assert_eq!(
        observer.storage().state().root(),
        validator.storage().state().root()
    );
    assert!(observer.submit_transaction(tx.clone()).is_err());
    assert_eq!(
        decode_exchange(
            fixture.network.genesis_hash(),
            &observer.respond(observer.request()).unwrap()
        )
        .unwrap(),
        [] as [node::network_wire::NetworkMessage; 0]
    );
    let checkpoint = *observer.storage().checkpoint().unwrap();
    drop(observer);
    let observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    let mut late =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("late-observer")).unwrap();
    while late.request().height < observer.request().height {
        assert_eq!(
            late.receive(&observer.respond(late.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(
        late.storage().state().root(),
        observer.storage().state().root()
    );
    assert!(late.submit_transaction(tx).is_err());
    for directory in [path, fixture.path.join("late-observer")] {
        assert!(!directory.join("signing.journal").exists());
        assert!(!directory.join("validator.seed").exists());
        assert!(!directory.join("consensus-cache.bin").exists());
        assert_eq!(
            std::fs::read(directory.join(node::observer::OBSERVER_MARKER))
                .unwrap()
                .len(),
            36
        );
    }
}

#[test]
fn observer_rejects_forged_finality_body_mutations_gaps_and_truncated_batches() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    validator.submit_transaction(transfer()).unwrap();
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let initial = *observer.storage().checkpoint().unwrap();
    let now = Instant::now();
    for step in 0..8 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height >= 3 {
            break;
        }
    }
    let original = validator.respond(observer.request()).unwrap();
    let message = decode_exchange(fixture.network.genesis_hash(), &original)
        .unwrap()
        .remove(0);
    for defect in 0..2 {
        let mut mutated = message.clone();
        let NetworkMessage::Finalized { block, certificate } = &mut mutated else {
            panic!("finalized block expected")
        };
        if defect == 0 {
            certificate.signatures[0].signature[0] ^= 1;
        } else {
            block.transactions[0].payload[0] ^= 1;
        }
        let bytes = encode_exchange(fixture.network.genesis_hash(), &[mutated]).unwrap();
        assert_eq!(observer.receive(&bytes).unwrap(), 1);
        assert_eq!(observer.storage().checkpoint(), Some(&initial));
    }
    let gap = validator
        .respond(SyncRequest {
            height: 2,
            ..observer.request()
        })
        .unwrap();
    assert_eq!(observer.receive(&gap).unwrap(), 1);
    let mut truncated = original.clone();
    truncated.pop();
    assert!(observer.receive(&truncated).is_err());
    assert_eq!(observer.storage().checkpoint(), Some(&initial));
    assert!(
        observer
            .respond(SyncRequest {
                genesis: Hash256([0x42; 32]),
                height: 1
            })
            .is_err()
    );
    assert_eq!(observer.receive(&original).unwrap(), 0);
    assert_eq!(observer.receive(&original).unwrap(), 1);
    assert_eq!(observer.request().height, 2);
}

#[test]
fn observer_cannot_replace_missing_quorum_or_relay_live_consensus_messages() {
    let fixture = Fixture::new(4);
    let mut validators = vec![fixture.open(1), fixture.open(2)];
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let now = Instant::now();
    for step in 0..60 {
        exchange(&mut validators, now + Duration::from_millis(step * 20));
        for validator in &mut validators {
            observer
                .receive(&validator.respond(observer.request()).unwrap())
                .unwrap();
            let bytes = observer.respond(validator.request()).unwrap();
            assert_eq!(
                decode_exchange(fixture.network.genesis_hash(), &bytes).unwrap(),
                [] as [node::network_wire::NetworkMessage; 0]
            );
            validator.receive(&bytes).unwrap();
        }
    }
    assert_eq!(observer.request().height, 1);
    assert!(
        validators
            .iter()
            .all(|validator| validator.request().height == 1)
    );
}

#[test]
fn observer_role_validation_preserves_validator_data_and_rejects_corrupt_markers() {
    let fixture = Fixture::new(1);
    let directory = fixture.path.join("1");
    let journal = std::fs::read(directory.join("signing.journal")).unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &directory).is_err());
    assert_eq!(
        std::fs::read(directory.join("signing.journal")).unwrap(),
        journal
    );
    assert!(!directory.join("chain.bin").exists());
    let path = fixture.path.join("observer");
    drop(ObserverNode::open(fixture.network.clone(), &path).unwrap());
    let archive = std::fs::read(path.join("chain.bin")).unwrap();
    std::fs::write(path.join(node::observer::OBSERVER_MARKER), b"ALOB").unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &path).is_err());
    assert_eq!(std::fs::read(path.join("chain.bin")).unwrap(), archive);
}

#[test]
fn observer_recovery_rejects_demonstration_history() {
    use node::{FullNodeService, NodeService, ProducerConfig};
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    std::fs::create_dir(&path).unwrap();
    let mut demo = FullNodeService::open_with_genesis(
        ProducerConfig {
            chain_id: 42,
            block_capacity: fixture.genesis.capacity,
            ..ProducerConfig::default()
        },
        path.join("chain.bin"),
        &fixture.genesis,
    )
    .unwrap();
    for _ in 0..5 {
        demo.advance().unwrap();
    }
    drop(demo);
    let archive = std::fs::read(path.join("chain.bin")).unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &path).is_err());
    assert_eq!(std::fs::read(path.join("chain.bin")).unwrap(), archive);
    assert!(!path.join(node::observer::OBSERVER_MARKER).exists());
}

#[test]
fn observer_storage_failure_is_fatal_and_does_not_publish_or_consume_pending_payment() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    observer.submit_transaction(transfer()).unwrap();
    let mut validator = fixture.open(1);
    validator
        .receive(&observer.respond(validator.request()).unwrap())
        .unwrap();
    let initial = *observer.storage().checkpoint().unwrap();
    let now = Instant::now();
    for step in 0..4 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height > 1 {
            break;
        }
    }
    let bytes = validator.respond(observer.request()).unwrap();
    let blocked = path.join("chain.bin.pending");
    std::fs::create_dir(&blocked).unwrap();
    assert!(matches!(
        observer.receive(&bytes),
        Err(node::network::NetworkNodeError::Local(_))
    ));
    assert_eq!(observer.storage().checkpoint(), Some(&initial));
    assert_eq!(
        decode_exchange(
            fixture.network.genesis_hash(),
            &observer.respond(observer.request()).unwrap()
        )
        .unwrap()
        .len(),
        1
    );
    drop(observer);
    std::fs::remove_dir(&blocked).unwrap();
    let mut recovered = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    assert_eq!(recovered.storage().checkpoint(), Some(&initial));
    assert_eq!(recovered.receive(&bytes).unwrap(), 0);
    assert_eq!(
        recovered.storage().checkpoint(),
        validator.storage().checkpoint()
    );
}

#[test]
fn legacy_validator_and_log_observer_exchange_certified_payments_and_recover() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1/chain.bin");
    let mut archive = storage::FileBackedStorage::open(&path).unwrap();
    archive
        .initialize_genesis(
            fixture.network.genesis_hash(),
            fixture.genesis.materialize().unwrap(),
        )
        .unwrap();
    drop(archive);
    let mut validator = fixture.open(1);
    assert!(validator.storage().is_legacy_archive());
    let directory = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &directory).unwrap();
    assert!(!observer.storage().is_legacy_archive());
    validator.submit_transaction(transfer()).unwrap();
    let now = Instant::now();
    for step in 0..4 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height > 1 {
            break;
        }
    }
    observer
        .receive(&validator.respond(observer.request()).unwrap())
        .unwrap();
    assert_eq!(
        observer.storage().checkpoint(),
        validator.storage().checkpoint()
    );
    drop(observer);
    drop(validator);
    let validator = fixture.open(1);
    let observer = ObserverNode::open(fixture.network.clone(), &directory).unwrap();
    assert_eq!(
        observer.storage().state().root(),
        validator.storage().state().root()
    );
    assert!(validator.storage().is_legacy_archive());
    let id = transaction::compute_tx_id(&transfer());
    let (height, index) = validator.storage().transaction_location(id).unwrap();
    let recovered_receipts = validator.storage().read_receipts(height).unwrap().unwrap();
    assert_eq!(recovered_receipts.effects.receipts[index].transaction, id);
    assert_eq!(
        Some(recovered_receipts),
        observer.storage().read_receipts(height).unwrap()
    );
    assert_eq!(&std::fs::read(path).unwrap()[..8], b"ASTSTORE");
}

#[test]
fn network_crosses_full_signing_journal_recovers_and_finalizes_payments() {
    use consensus::{Vote, VotePhase};
    use types::hash::domain_hash;
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1/signing.journal");
    // Build the documented full v2 prefix: 100,000 reserved nil prevotes during
    // an extended outage. No test-only reduction of the production limit.
    let mut prefix = std::fs::read(&path).unwrap();
    let mut tip = Hash256(prefix[76..108].try_into().unwrap());
    let committee = fixture.network.committee(1).unwrap();
    let voter = ValidatorId(blake2s(&ed25519_public_key(&[1; 32])).0);
    for sequence in 1..=keystore::MAX_JOURNAL_RECORDS {
        let round = u32::try_from(sequence - 1).unwrap();
        let vote = Vote {
            chain_id: 42,
            height: 1,
            committee_root: committee.root(),
            round,
            phase: VotePhase::Prevote,
            block: None,
            voter,
            signature: [0; 64],
        };
        let mut record = sequence.to_le_bytes().to_vec();
        record.extend_from_slice(&1u64.to_le_bytes());
        record.extend_from_slice(&round.to_le_bytes());
        record.push(keystore::PREVOTE_PHASE);
        record.extend_from_slice(vote.signing_hash().as_bytes());
        record.extend_from_slice(committee.root().as_bytes());
        record.extend_from_slice(&[0; 37]); // No BFT lock.
        let mut input = tip.0.to_vec();
        input.extend_from_slice(&record);
        tip = domain_hash(b"astrolune.signing.decision.v1", &input);
        record.extend_from_slice(tip.as_bytes());
        prefix.extend_from_slice(&record);
    }
    std::fs::write(&path, &prefix).unwrap();
    assert_eq!(prefix.len() as u64, keystore::MAX_PROTECTED_JOURNAL_BYTES);
    let mut node = fixture.open(1);
    assert_eq!(node.round(), 99_999);
    let now = Instant::now();
    node.tick(now).unwrap();
    node.tick(now + Duration::from_secs(20_000)).unwrap(); // Nil precommit activates rollover.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        keystore::MAX_ROLLOVER_JOURNAL_BYTES
    );
    drop(node);
    let mut node = fixture.open(1);
    node.submit_transaction(transfer()).unwrap();
    for step in 0..16 {
        node.tick(now + Duration::from_secs(step * 20_000)).unwrap();
        if node.request().height >= 2 {
            break;
        }
    }
    assert_eq!(node.request().height, 2);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    observer
        .receive(&node.respond(observer.request()).unwrap())
        .unwrap();
    assert_eq!(observer.storage().checkpoint(), node.storage().checkpoint());
    let checkpoint = *node.storage().checkpoint().unwrap();
    drop(node);
    assert_eq!(&std::fs::read(&path).unwrap()[..prefix.len()], prefix);
    let mut recovered = fixture.open(1);
    assert_eq!(recovered.storage().checkpoint(), Some(&checkpoint));
    for step in 0..4 {
        recovered.tick(now + Duration::from_millis(step)).unwrap();
    }
    assert!(recovered.request().height > 2);
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        keystore::MAX_ROLLOVER_JOURNAL_BYTES
    );
}

#[test]
fn rotating_roster_pauses_without_a_proof_then_changes_seats_and_recovers() {
    let fixture = Fixture::with_profile(4, 2, 2, 3);
    assert!(fixture.network.committee(2).is_err());
    let mut nodes = paused_rotating_nodes(&fixture);
    let start = Instant::now();
    let mut saw_standby = [false; 4];
    let mut resumed = [false; 4];
    for step in 0..600 {
        exchange(&mut nodes, start + Duration::from_millis(step * 20));
        for (index, node) in nodes.iter().enumerate() {
            resumed[index] |= saw_standby[index] && !node.is_standby();
            saw_standby[index] |= node.is_standby();
        }
        if nodes.iter().all(|node| node.request().height >= 12) {
            break;
        }
    }
    assert!(
        nodes.iter().all(|node| node.request().height >= 12),
        "full roster must resume progress"
    );
    assert!(
        saw_standby.iter().filter(|seen| **seen).count() >= 2,
        "multiple registered identities must leave the committee"
    );
    let source = nodes
        .iter()
        .max_by_key(|node| node.request().height)
        .unwrap();
    let source_height = source.request().height;
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    while observer.request().height < source_height {
        assert_eq!(
            observer
                .receive(&source.respond(observer.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(
        observer.storage().checkpoint(),
        source.storage().checkpoint()
    );
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    let mut trusted = consensus::rotation::HandoffVerifier::new(&fixture.genesis, &keys).unwrap();
    for height in 1..source_height {
        let handoff = node::handoff::read_handoff(source.storage(), height)
            .unwrap()
            .unwrap();
        trusted.apply(&handoff).unwrap();
    }
    assert_eq!(
        trusted.parent(),
        source.storage().checkpoint().unwrap().block
    );
    assert_eq!(
        state::read_account(
            source.storage().state().snapshot().unwrap().as_ref(),
            Address([77; 32])
        )
        .unwrap()
        .unwrap()
        .balance,
        123
    );
    // A stale proof is rejected without displacing any valid current contribution.
    reject_stale_contribution(&mut nodes, &fixture.network, source_height);
    drop(nodes);
    let mut reopened: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for step in 0..200 {
        exchange(
            &mut reopened,
            Instant::now() + Duration::from_millis(step * 20),
        );
        if reopened
            .iter()
            .all(|node| node.request().height > source_height)
        {
            break;
        }
    }
    assert!(
        reopened
            .iter()
            .all(|node| node.request().height > source_height)
    );
    drop(observer);
    let recovered =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    assert_eq!(recovered.request().height, source_height);
}

fn paused_rotating_nodes(fixture: &Fixture) -> Vec<NetworkNode> {
    let mut nodes: Vec<_> = (1..=3).map(|index| fixture.open(index)).collect();
    nodes[0].submit_transaction(transfer()).unwrap();
    let start = Instant::now();
    for step in 0..25 {
        exchange(&mut nodes, start + Duration::from_secs(step));
    }
    assert!(
        nodes
            .iter()
            .all(|node| node.request().height == 1 && node.round() == 0)
    );
    assert!(
        nodes
            .iter()
            .all(|node| node.missing_contributions().len() == 1)
    );
    nodes.push(fixture.open(4));
    nodes
}

fn reject_stale_contribution(
    nodes: &mut [NetworkNode],
    network: &StaticNetwork,
    source_height: u64,
) {
    let old = node::handoff::read_handoff(nodes[0].storage(), 1)
        .unwrap()
        .unwrap();
    let packet = encode_exchange(
        network.genesis_hash(),
        &[NetworkMessage::VrfContribution {
            height: source_height,
            contribution: old.contributions.entries()[0].clone(),
        }],
    )
    .unwrap();
    assert_eq!(nodes[0].receive(&packet).unwrap(), 1);
}

#[test]
fn recovered_evidence_authenticates_different_rotating_committees_in_one_history() {
    let fixture = Fixture::with_profile(4, 1, 2, 3);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    let start = Instant::now();
    for step in 0..300 {
        exchange(&mut nodes, start + Duration::from_millis(step * 20));
        if nodes[0].request().height >= 5 {
            break;
        }
    }
    assert!(nodes[0].request().height >= 5);
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    let mut trusted = consensus::rotation::HandoffVerifier::new(&fixture.genesis, &keys).unwrap();
    let directory = fixture.path.join("1/equivocation");
    std::fs::create_dir(&directory).unwrap();
    let mut proofs = Vec::new();
    for height in 1..=3 {
        if height != 2 {
            let context = trusted.current().context().unwrap();
            let seed = (1..=4)
                .find(|seed| {
                    let id = ValidatorId(blake2s(&ed25519_public_key(&[*seed; 32])).0);
                    context.voting_power(id).is_some()
                        && proofs
                            .iter()
                            .all(|proof: &consensus::DoubleVoteEvidence| proof.voter() != id)
                })
                .unwrap();
            let mut votes = [None, Some(Hash256([9; 32]))].map(|block| consensus::Vote {
                chain_id: 42,
                committee_root: context.root(),
                height,
                round: 0,
                phase: consensus::VotePhase::Prevote,
                block,
                voter: ValidatorId(blake2s(&ed25519_public_key(&[seed; 32])).0),
                signature: [0; 64],
            });
            for vote in &mut votes {
                vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
            }
            let [first, second] = votes;
            let proof = consensus::DoubleVoteEvidence::from_votes(&context, first, second).unwrap();
            std::fs::write(
                directory.join(format!("{}.bin", proof.voter())),
                proof.encode(),
            )
            .unwrap();
            proofs.push(proof);
        }
        trusted
            .apply(
                &node::handoff::read_handoff(nodes[0].storage(), height)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
    }
    drop(nodes);
    let recovered = fixture.open(1);
    assert_eq!(recovered.evidence().count(), 2);
    assert!(
        proofs
            .iter()
            .all(|proof| recovered.evidence().any(|stored| stored == proof))
    );
    drop(recovered);
    let mut corrupt = proofs[0].encode();
    corrupt[379] ^= 1;
    std::fs::write(
        directory.join(format!("{}.bin", proofs[0].voter())),
        corrupt,
    )
    .unwrap();
    let signer = DurableSigner::open(
        fixture.path.join("1/signing.journal"),
        SigningContext {
            chain_id: 42,
            genesis: fixture.network.genesis_hash(),
        },
        [1; 32],
    )
    .unwrap();
    assert!(
        NetworkNode::open(
            fixture.network.clone(),
            &fixture.path.join("1"),
            signer,
            Duration::from_millis(100)
        )
        .is_err()
    );
}
