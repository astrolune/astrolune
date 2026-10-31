// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Native contract publication, restart and exact archive replay.

use genesis::{Allocation, Genesis, GenesisValidator};
use node::{FullNodeService, NodeService, ProducerConfig};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::FileBackedStorage;
use transaction::{
    ContractAction, ContractPayload, address_from_public_key, trocto_contract_address,
    trocto_contract_code_key, trocto_contract_state_key,
};
use types::{Resources, Transaction, TransactionLane, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-native-node-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn archive(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn genesis() -> Genesis {
    Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 1_000_000,
            memory: 1_000_000,
            io: 1_000_000,
            bandwidth: 1_000_000,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 3,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: 1,
        }],
        allocations: vec![Allocation {
            address: address_from_public_key(&crypto::blake2s::ed25519_public_key(&[240; 32])),
            amount: 1_000_000_000,
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

fn contract(nonce: u64, action: ContractAction) -> Transaction {
    let public_key = crypto::blake2s::ed25519_public_key(&[240; 32]);
    let sender = address_from_public_key(&public_key);
    let mut access_list = vec![state::account_key(sender)];
    match &action {
        ContractAction::DeployTrocto(_) => access_list.push(trocto_contract_code_key(
            trocto_contract_address(42, sender, nonce),
        )),
        ContractAction::CallTrocto { address, keys, .. } => {
            access_list.push(trocto_contract_code_key(*address));
            access_list.extend(
                keys.iter()
                    .map(|key| trocto_contract_state_key(*address, key)),
            );
        }
        _ => unreachable!(),
    }
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 42,
        sender,
        nonce,
        expires_at: 100,
        lane: TransactionLane::Contracts,
        access_list,
        resource_prices: execution::PAYMENT_PRICES,
        resource_limit: Resources {
            compute: 100_000,
            memory: 256_000,
            io: 128_000,
            bandwidth: 128_000,
        },
        payload: ContractPayload { public_key, action }.to_bytes(),
        signature: [0; 64],
    };
    tx.signature =
        crypto::blake2s::ed25519_sign(&[240; 32], transaction::signing_hash(&tx).as_bytes());
    tx
}

fn advance(service: &mut FullNodeService<FileBackedStorage>) {
    for _ in 0..5 {
        service.advance().unwrap();
    }
}

#[test]
fn native_infrastructure_failure_is_local_and_does_not_score_the_peer() {
    let error: node::network::NetworkNodeError =
        node::ProducerError::Execution(execution::ExecutionError::NativeUnavailable).into();
    assert!(matches!(error, node::network::NetworkNodeError::Local(_)));
    assert!(error.offence().is_none());
}

#[test]
#[ignore = "requires pinned LLVM 22.1.8 and native OS isolation"]
fn native_contract_state_receipts_survive_restart_and_exact_replay() {
    let fixture = Fixture::new();
    let reference = Fixture::new();
    let genesis = genesis();
    let deploy = contract(0, ContractAction::DeployTrocto(b"fn call(input: u64) -> u64 { let next = state_get(\"counter\") + input; state_set(\"counter\", next); emit(height(), next); return input * 2; }".to_vec()));
    let address = trocto_contract_address(42, deploy.sender, 0);
    let call = |nonce, input: u64| {
        contract(
            nonce,
            ContractAction::CallTrocto {
                address,
                input: input.to_le_bytes().to_vec(),
                keys: vec![b"counter".to_vec()],
            },
        )
    };
    {
        let mut service =
            FullNodeService::open_with_genesis(config(&genesis), fixture.archive(), &genesis)
                .unwrap();
        service.submit_transaction(deploy.clone()).unwrap();
        advance(&mut service);
        service.submit_transaction(call(1, 5)).unwrap();
        advance(&mut service);
        let before = std::fs::read(fixture.archive()).unwrap();
        let root = service.storage().state().root();
        assert!(
            service
                .submit_transaction(call(2, u64::MAX / 2 + 1))
                .is_err()
        );
        assert_eq!(service.storage().state().root(), root);
        assert_eq!(std::fs::read(fixture.archive()).unwrap(), before);
    }
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.archive(), &genesis).unwrap();
    assert_eq!(
        service
            .storage()
            .state()
            .get(&trocto_contract_state_key(address, b"counter")),
        Some(5u64.to_le_bytes().as_slice())
    );
    service.submit_transaction(call(2, 7)).unwrap();
    advance(&mut service);
    assert_eq!(
        service
            .storage()
            .state()
            .get(&trocto_contract_state_key(address, b"counter")),
        Some(12u64.to_le_bytes().as_slice())
    );
    let mut uninterrupted =
        FullNodeService::open_with_genesis(config(&genesis), reference.archive(), &genesis)
            .unwrap();
    for tx in [deploy, call(1, 5), call(2, 7)] {
        uninterrupted.submit_transaction(tx).unwrap();
        advance(&mut uninterrupted);
    }
    assert_eq!(
        service.storage().checkpoint(),
        uninterrupted.storage().checkpoint()
    );
    assert_eq!(
        std::fs::read(fixture.archive()).unwrap(),
        std::fs::read(reference.archive()).unwrap()
    );
}

fn drive_certified(nodes: &mut [node::network::NetworkNode], height: u64) {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_secs(20);
    while nodes.iter().any(|node| node.request().height < height) {
        assert!(
            Instant::now() < end,
            "native certified network did not advance"
        );
        for index in 0..nodes.len() {
            let request = nodes[index].request();
            let responses: Vec<_> = nodes
                .iter()
                .map(|node| node.respond(request).unwrap())
                .collect();
            for response in responses {
                nodes[index].receive(&response).unwrap();
            }
            if nodes[index].request().height < height {
                nodes[index].tick(Instant::now()).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn certified_network(
    fixture: &Fixture,
) -> (
    node::network::StaticNetwork,
    Vec<node::network::NetworkNode>,
) {
    use keystore::{DurableSigner, SigningContext};
    use node::network::{NetworkNode, StaticNetwork};
    use std::time::Duration;
    let keys: Vec<_> = (1..=2)
        .map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]))
        .collect();
    let mut genesis = genesis();
    genesis.committee_size = 2;
    genesis.validators = keys
        .iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(crypto::blake2s::blake2s(key).0),
            weight: 1,
        })
        .collect();
    genesis.validators.sort_by_key(|validator| validator.id);
    let network = StaticNetwork::new(genesis, keys).unwrap();
    let mut nodes = Vec::new();
    for seed in 1..=2 {
        let directory = fixture.0.join(format!("validator-{seed}"));
        std::fs::create_dir(&directory).unwrap();
        let signer = DurableSigner::create_protected(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: network.genesis_hash(),
            },
            [seed; 32],
        )
        .unwrap();
        nodes.push(
            NetworkNode::open(network.clone(), &directory, signer, Duration::from_secs(2)).unwrap(),
        );
    }
    (network, nodes)
}

#[test]
#[ignore = "requires pinned LLVM 22.1.8 and native OS isolation"]
fn certified_nodes_and_restarted_observer_replay_native_state() {
    use node::observer::ObserverNode;
    let fixture = Fixture::new();
    let (network, mut nodes) = certified_network(&fixture);
    let deploy = contract(0, ContractAction::DeployTrocto(b"fn call(input: u64) -> u64 { let next = state_get(\"counter\") + input; state_set(\"counter\", next); emit(height(), next); return next; }".to_vec()));
    let address = trocto_contract_address(42, deploy.sender, 0);
    nodes[0].submit_transaction(deploy).unwrap();
    drive_certified(&mut nodes, 2);
    let call = contract(
        1,
        ContractAction::CallTrocto {
            address,
            input: 11u64.to_le_bytes().to_vec(),
            keys: vec![b"counter".to_vec()],
        },
    );
    let id = transaction::compute_tx_id(&call);
    nodes[0].submit_transaction(call).unwrap();
    drive_certified(&mut nodes, 3);
    let state_key = trocto_contract_state_key(address, b"counter");
    for node in &nodes {
        assert_eq!(
            node.storage().state().get(&state_key),
            Some(11u64.to_le_bytes().as_slice())
        );
    }
    assert_eq!(
        nodes[0].storage().checkpoint(),
        nodes[1].storage().checkpoint()
    );
    let observer_path = fixture.0.join("observer");
    let mut observer = ObserverNode::open(network.clone(), &observer_path).unwrap();
    for _ in 0..3 {
        let packet = nodes[0].respond(observer.request()).unwrap();
        observer.receive(&packet).unwrap();
    }
    assert_eq!(
        observer.storage().checkpoint(),
        nodes[0].storage().checkpoint()
    );
    assert_eq!(
        observer.storage().state().get(&state_key),
        Some(11u64.to_le_bytes().as_slice())
    );
    assert_eq!(
        observer.storage().state().root(),
        nodes[0].storage().state().root()
    );
    // The finalized body commits the signed native call and its receipt.
    let (height, index) = nodes[0].storage().transaction_location(id).unwrap();
    let (body, encoded) = nodes[0].storage().read_finalized(height).unwrap().unwrap();
    let certificate = consensus::FinalityCertificate::decode(&encoded).unwrap();
    network
        .committee(height)
        .unwrap()
        .verify_certificate(&certificate, &body.header)
        .unwrap();
    let receipts = nodes[0].storage().read_receipts(height).unwrap().unwrap();
    assert_eq!(receipts.effects.receipts[index].transaction, id);
    receipts.effects.validate(&body).unwrap();
    assert!(
        body.transactions
            .iter()
            .any(|tx| transaction::compute_tx_id(tx) == id)
    );
    assert!(!body.header.receipts_root.is_zero());
    drop(observer);
    let recovered = ObserverNode::open(network, &observer_path).unwrap();
    assert_eq!(
        recovered.storage().checkpoint(),
        nodes[0].storage().checkpoint()
    );
    assert_eq!(
        recovered.storage().state().get(&state_key),
        Some(11u64.to_le_bytes().as_slice())
    );
}
