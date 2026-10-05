// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use codec::{DecodeError, Decoder, PROTOCOL_VERSION};
use config::{NetworkConfig, NodeConfig, SecretRef};
use consensus::{
    Committee, CommitteeMember, CommitteeSelector, DemonstrationSampler, FinalityEngine,
    PotbWeight, quorum_power,
};
use dns::{InMemoryResolver, Record, Resolver};
use execution::{ExecutorConfig, SimpleExecutor};
use genesis::{Genesis, GenesisValidator};
use keystore::{KeyHandle, KeyPurpose, MockKeystore, Signer};
use mempool::{Mempool, PoolEntry, PoolLimits};
use node::NodeService;
use p2p::{BoundedFrameDecoder, FrameDecoder, FrameEncoder, MAX_FRAME_SIZE, MessageKind};
use rpc::{InMemoryRpcService, RpcRequest, RpcResponse, RpcService};
use state::{InMemoryState, StateDatabase, StateDiff};
use storage::{CommitBatch, InMemoryStorage, NodeStorage};
use sync::{ChainVerifier, SyncVerifier};
use testkit::{hash, resources, transaction, validator};
use transaction::{AccountState, BasicValidator};
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, ValidatorId};

// Original baseline tests

#[test]
fn protocol_baseline_invariants_hold() {
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(quorum_power(100), 67);

    let mut decoder = Decoder::new(&[1]);
    assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    assert_eq!(Decoder::new(&[1]).finish(), Err(DecodeError::TrailingBytes));
}

#[test]
fn configuration_validates_and_redacts_key_reference() {
    let key = SecretRef::new("hardware-slot-7").expect("valid key reference");
    let config = NodeConfig {
        chain_id: 7,
        data_dir: PathBuf::from("node-data"),
        validator_key: Some(key),
        network: NetworkConfig {
            p2p_listen: "127.0.0.1:17330".into(),
            rpc_listen: "127.0.0.1:17331".into(),
            max_peers: 32,
        },
    };

    config.validate().expect("valid node configuration");

    let debug = format!("{config:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("hardware-slot-7"));
}

#[test]
fn genesis_and_mempool_form_a_deterministic_baseline() {
    let genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity: resources(10),
        committee_size: 2,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![
            GenesisValidator {
                id: validator(1),
                weight: 10,
            },
            GenesisValidator {
                id: validator(2),
                weight: 10,
            },
        ],
        allocations: Vec::new(),
    };
    genesis.validate().expect("valid genesis");

    let mut pool = Mempool::new(PoolLimits {
        max_transactions: 2,
        max_bytes: 128,
    })
    .expect("valid limits");

    pool.insert(
        PoolEntry {
            id: hash(1),
            transaction: transaction(1, 0),
            priority: 1,
            sequence: 1,
        },
        32,
    )
    .expect("first transaction");
    pool.insert(
        PoolEntry {
            id: hash(2),
            transaction: transaction(2, 0),
            priority: 2,
            sequence: 2,
        },
        32,
    )
    .expect("second transaction");

    let selected = pool.select(2, resources(2));
    assert_eq!(selected[0].id, hash(2));
    assert_eq!(selected[1].id, hash(1));
}

// Keystore + consensus signing integration

#[test]
fn keystore_signs_consensus_votes() {
    let mut ks = MockKeystore::new();
    ks.insert(
        "validator-1",
        ValidatorId::from_bytes([1; 32]),
        KeyPurpose::Consensus,
    );

    let handle = KeyHandle {
        id: "validator-1".into(),
        purpose: KeyPurpose::Consensus,
    };

    let vid = ks.validator_id(&handle).expect("key exists");
    assert_eq!(vid, ValidatorId::from_bytes([1; 32]));

    let msg = hash(42);
    let pos = keystore::SigningPosition {
        height: 1,
        round: 0,
        phase: 0,
    };

    let sig = ks.sign_consensus(&handle, pos, msg).expect("signs");
    assert_ne!(sig, [0u8; 64]);

    let sig2 = ks
        .sign_consensus(&handle, pos, msg)
        .expect("re-signs same msg");
    assert_eq!(sig, sig2);

    let err = ks.sign_consensus(&handle, pos, hash(99));
    assert_eq!(err, Err(keystore::KeystoreError::ConflictingSign));
}

// Committee rotation + finality integration

#[test]
fn committee_rotation_feeds_finality() {
    let identity = |seed: u8| {
        ValidatorId(crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&[seed; 32])).0)
    };

    let committee = Committee {
        height: 0,
        members: vec![
            CommitteeMember {
                id: identity(1),
                power: PotbWeight(10),
            },
            CommitteeMember {
                id: identity(2),
                power: PotbWeight(10),
            },
            CommitteeMember {
                id: identity(3),
                power: PotbWeight(10),
            },
        ],
    };

    let candidates = vec![
        consensus::Candidate {
            id: identity(4),
            weight: PotbWeight(50),
            vrf: crypto::VrfOutput {
                randomness: Hash256([0xFF; 32]),
                proof: vec![1],
            },
        },
        consensus::Candidate {
            id: identity(5),
            weight: PotbWeight(30),
            vrf: crypto::VrfOutput {
                randomness: Hash256([0xFE; 32]),
                proof: vec![2],
            },
        },
    ];

    let sampler = DemonstrationSampler;
    let next = sampler.rotate(&committee, &candidates, 1);
    assert_eq!(next.height, 1);
    assert_eq!(next.members.len(), 3);
    assert_eq!(next.members[0].id, identity(1));

    assert_eq!(next.members[1].id, identity(2));
    assert_eq!(next.members[2].id, identity(4));

    let seeds = [1u8, 2, 4];
    let keys = seeds.map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]));
    let context = consensus::AuthenticatedCommittee::new(7, &next, &keys).unwrap();
    let root = context.root();

    let mut engine = consensus::BftFinalityEngine::new(context);
    let block = hash(100);

    for member in &next.members {
        let mut vote = consensus::Vote {
            chain_id: 7,
            committee_root: root,
            height: 1,
            round: 0,
            phase: consensus::VotePhase::Precommit,
            block: Some(block),
            voter: member.id,
            signature: [0xFF; 64],
        };

        let seed = seeds
            .iter()
            .find(|seed| identity(**seed) == member.id)
            .unwrap();
        vote.signature = crypto::blake2s::ed25519_sign(&[*seed; 32], &vote.signing_hash().0);

        engine.receive_vote(vote).expect("valid vote");
    }

    assert_eq!(engine.finalized_block(), Some(block));
}

// State + execution + storage integration

#[test]
fn state_execution_storage_roundtrip() {
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let mut diff = StateDiff::new();
    let key = StateKey::new(b"account:alice".to_vec()).expect("valid key");
    diff.put(key.clone(), vec![100, 200, 50]);

    let root1 = state.commit(root0, &[diff]).expect("commit succeeds");
    assert_ne!(root0, root1);

    let snapshot = state.snapshot().expect("snapshot");
    assert_eq!(snapshot.get(&key).expect("get"), Some(vec![100, 200, 50]));

    let mut storage = InMemoryStorage::new();
    let batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                state_root: root1,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: resources(100),
            },
            transactions: Vec::new(),
        },
        finality_certificate: vec![0xAA; 32],
        effects: None,
        state_diffs: vec![{
            let mut d = StateDiff::new();
            d.put(key, vec![100, 200, 50]);
            d
        }],
    };

    let cp = storage.commit(&batch).expect("storage commit");
    assert_eq!(cp.height, 0);
    assert_eq!(cp.state_root, root1);
}

// Transaction validation + execution integration

#[test]
fn transaction_validates_and_executes() {
    let sender = Address([1u8; 32]);
    let mut accounts = BTreeMap::new();
    accounts.insert(
        sender,
        AccountState {
            nonce: 0,
            balance: 1000,
        },
    );

    let validator_inst = BasicValidator::new(accounts);
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let config = ExecutorConfig {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };

    let mut executor = SimpleExecutor::new(&mut state, validator_inst, config);
    let txs = vec![transaction(1, 0)];
    let (outputs, root1) = executor.execute_block(&txs, root0).expect("executes");

    assert_eq!(outputs.len(), 1);
    assert!(outputs[0].receipt.succeeded);
    assert_ne!(root0, root1);
}

// P2P frame encode/decode roundtrip

#[test]
fn p2p_frame_roundtrip() {
    let payload = b"hello astrolune";
    let encoded = FrameEncoder::encode(MessageKind::Hello, payload);
    assert_eq!(encoded[0], MessageKind::Hello as u8);
    assert_eq!(encoded.len(), 5 + payload.len());

    let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
    let frame = decoder.decode(&encoded).expect("decodes");
    assert_eq!(frame.kind, MessageKind::Hello);
    assert_eq!(frame.payload, payload);
}

// Sync verifier header chain validation

#[test]
fn sync_verifies_header_chain() {
    let genesis = BlockHeader {
        height: 0,
        parent: Hash256::ZERO,
        transactions_root: Hash256::ZERO,
        state_root: Hash256([0xAA; 32]),
        receipts_root: Hash256::ZERO,
        committee_root: Hash256::ZERO,
        capacity: resources(100),
    };
    let genesis_hash = genesis.compute_hash();

    let verifier = ChainVerifier::new(genesis_hash, 1, 1);

    let h1 = BlockHeader {
        height: 1,
        parent: genesis_hash,
        transactions_root: Hash256::ZERO,
        state_root: Hash256([0xBB; 32]),
        receipts_root: Hash256::ZERO,
        committee_root: Hash256::ZERO,
        capacity: resources(100),
    };

    verifier.verify_headers(&[h1]).expect("valid chain");
}

// RPC service integration

#[test]
fn rpc_service_full_workflow() {
    let mut rpc = InMemoryRpcService::new(7);

    rpc.set_finalized(10, hash(42));
    let resp = rpc.handle(RpcRequest::ChainStatus).expect("chain status");
    match resp {
        RpcResponse::ChainStatus {
            chain_id,
            finalized_height,
            ..
        } => {
            assert_eq!(chain_id, 7);
            assert_eq!(finalized_height, 10);
        }
        _ => panic!("unexpected response"),
    }

    let resp = rpc
        .handle(RpcRequest::SubmitTransaction(vec![1, 2, 3]))
        .expect("submit tx");
    assert!(matches!(resp, RpcResponse::TransactionAccepted(_)));

    let resp = rpc
        .handle(RpcRequest::Account(Address([99u8; 32])))
        .expect("account");
    assert_eq!(resp, RpcResponse::Account(None));
}

// DNS service resolution

#[test]
fn dns_service_resolution() {
    let mut resolver = InMemoryResolver::new();
    let record = Record::Service(b"application".to_vec());

    resolver
        .register(
            "appastro",
            Address::default(),
            record.clone(),
            0,
            dns::DEFAULT_LEASE_SECS,
        )
        .unwrap();

    assert_eq!(resolver.resolve("appastro").unwrap(), Some(record));
}

// Telemetry + node capacity integration

#[test]
fn telemetry_tracks_node_capacity() {
    use node::CapacityController;
    use node::CapacityObservation;
    use telemetry::{InMemoryTelemetry, Metric, TelemetrySink};

    let tel = InMemoryTelemetry::new(64);
    let controller =
        node::AdaptiveCapacityController::new(node::DEFAULT_CAPACITY, node::LATENCY_WINDOW);

    let observations: Vec<CapacityObservation> = (0..8)
        .map(|i| CapacityObservation {
            used: Resources {
                compute: 500 + i * 50,
                memory: 512,
                io: 128,
                bandwidth: 512,
            },
            within_latency_target: true,
        })
        .collect();

    for obs in &observations {
        tel.record(Metric {
            name: "block_compute",
            value: obs.used.compute,
        });
        controller.next_capacity(node::DEFAULT_CAPACITY, std::slice::from_ref(obs));
    }

    assert_eq!(tel.count("block_compute"), 8);
    assert_eq!(tel.latest("block_compute"), Some(850));
}

// Storage commit + recover

#[test]
fn storage_commit_and_recover() {
    let mut storage = InMemoryStorage::new();
    assert!(storage.recover().expect("recovers").is_none());

    let batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                state_root: storage.state().root(),
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: resources(100),
            },
            transactions: Vec::new(),
        },
        finality_certificate: vec![0xAA; 32],
        effects: None,
        state_diffs: Vec::new(),
    };
    let cp = storage.commit(&batch).expect("commit");
    assert_eq!(cp.height, 0);

    let recovered = storage.recover().expect("recovers");
    assert_eq!(recovered, Some(cp));
}

// End-to-end: genesis -> mempool -> execution -> storage

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_block_production() {
    let genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity: resources(1000),
        committee_size: 3,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![
            GenesisValidator {
                id: validator(1),
                weight: 100,
            },
            GenesisValidator {
                id: validator(2),
                weight: 100,
            },
            GenesisValidator {
                id: validator(3),
                weight: 100,
            },
        ],
        allocations: Vec::new(),
    };
    genesis.validate().expect("genesis valid");

    let mut pool = Mempool::new(PoolLimits {
        max_transactions: 10,
        max_bytes: 10240,
    })
    .expect("valid limits");

    let tx1 = transaction(1, 0);
    let tx2 = transaction(2, 0);

    pool.insert(
        PoolEntry {
            id: hash(1),
            transaction: tx1,
            priority: 10,
            sequence: 1,
        },
        64,
    )
    .expect("insert tx1");
    pool.insert(
        PoolEntry {
            id: hash(2),
            transaction: tx2,
            priority: 20,
            sequence: 2,
        },
        64,
    )
    .expect("insert tx2");

    let selected = pool.select(5, resources(100));
    assert_eq!(selected.len(), 2);

    let sender = Address([1u8; 32]);
    let sender2 = Address([2u8; 32]);
    let mut accounts = BTreeMap::new();
    accounts.insert(
        sender,
        AccountState {
            nonce: 0,
            balance: 100_000,
        },
    );
    accounts.insert(
        sender2,
        AccountState {
            nonce: 0,
            balance: 100_000,
        },
    );

    let validator_inst = BasicValidator::new(accounts);
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let exec_config = ExecutorConfig {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };
    let mut executor = SimpleExecutor::new(&mut state, validator_inst, exec_config);

    let selected_txs: Vec<_> = selected
        .into_iter()
        .map(|e| e.transaction.clone())
        .collect();
    let (outputs, new_root) = executor
        .execute_block(&selected_txs, root0)
        .expect("executes");
    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().all(|o| o.receipt.succeeded));
    assert_ne!(root0, new_root);

    let mut storage = InMemoryStorage::new();
    let parent_hash = Hash256::ZERO;
    let commit_batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 0,
                parent: parent_hash,
                transactions_root: node::compute_transactions_root(&selected_txs),
                state_root: new_root,
                receipts_root: hash(100),
                committee_root: hash(101),
                capacity: resources(1000),
            },
            transactions: selected_txs,
        },
        finality_certificate: vec![0xBB; 64],
        effects: None,
        state_diffs: outputs.into_iter().map(|o| o.diff).collect(),
    };

    let cp = storage.commit(&commit_batch).expect("storage commit");
    assert_eq!(cp.height, 0);
    assert_eq!(cp.state_root, new_root);

    let recovered = storage.recover().expect("recovers");
    assert_eq!(recovered, Some(cp));
}

// Block production pipeline integration tests

#[test]
fn block_producer_produces_empty_block() {
    let mut producer = node::BlockProducer::new(node::ProducerConfig::default());
    let proposal = producer.produce_block().expect("produces block");

    assert_eq!(proposal.block.header.height, 0);
    assert_eq!(proposal.block.transactions, [] as [types::Transaction; 0]);
    assert_eq!(proposal.outputs, [] as [execution::TransactionOutput; 0]);
    assert_eq!(proposal.state_root, state::commitment::empty_root());
}

#[test]
fn block_producer_submit_and_produce() {
    let sender = Address([1u8; 32]);
    let producer =
        node::BlockProducer::with_account(sender, 0, 100_000, node::ProducerConfig::default());
    let mut producer = producer;

    let tx = types::Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender,
        nonce: 0,
        access_list: Vec::new(),
        resource_limit: resources(10),
        payload: vec![1, 2, 3],
        signature: [0xFF; 64],
    };
    producer.submit_transaction(tx).expect("submits");

    let proposal = producer.produce_block().expect("produces");
    assert_eq!(proposal.block.transactions.len(), 1);
    assert!(proposal.outputs[0].receipt.succeeded);
}

#[test]
fn block_producer_commits_to_storage() {
    let producer = node::BlockProducer::new(node::ProducerConfig::default());
    let mut producer = producer;
    let mut storage = InMemoryStorage::new();

    let proposal = producer.produce_block().expect("produces");
    let cp = producer
        .commit_block(&proposal, vec![0xAA; 32], &mut storage)
        .expect("commits");

    assert_eq!(cp.height, 0);
    assert_eq!(producer.height(), 1);
    assert_eq!(producer.parent_hash(), proposal.block.header.compute_hash());
}

#[test]
fn block_producer_multiple_blocks() {
    let sender = Address([1u8; 32]);
    let producer =
        node::BlockProducer::with_account(sender, 0, 100_000, node::ProducerConfig::default());
    let mut producer = producer;
    let mut storage = InMemoryStorage::new();

    for h in 0u64..5 {
        #[allow(clippy::cast_possible_truncation)]
        let tx = types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender,
            nonce: h,
            access_list: Vec::new(),
            resource_limit: resources(10),
            payload: vec![h as u8],
            signature: [0xFF; 64],
        };
        producer.submit_transaction(tx).expect("submits");

        let proposal = producer.produce_block().expect("produces");
        assert_eq!(proposal.block.header.height, h);

        producer
            .commit_block(&proposal, vec![0xAA; 32], &mut storage)
            .expect("commits");
    }

    assert_eq!(producer.height(), 5);

    let cp = storage
        .recover()
        .expect("recovers")
        .expect("has checkpoint");
    assert_eq!(cp.height, 4);
}

#[test]
fn full_node_service_full_cycle() {
    let mut service = node::FullNodeService::new(node::ProducerConfig::default());

    // Run one complete pipeline cycle: Idle -> Proposing -> Voting -> Executing -> Committing -> Idle
    for _ in 0..5 {
        service.advance().expect("advances");
    }

    assert_eq!(*service.current_state(), node::FullNodeState::Idle);
    assert_eq!(service.height(), 1);
    assert!(service.storage().checkpoint().is_some());
}

#[test]
fn full_node_service_with_transactions() {
    let mut service = node::FullNodeService::new(node::ProducerConfig::default());

    let sender = Address([1u8; 32]);
    let tx = types::Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender,
        nonce: 0,
        access_list: Vec::new(),
        resource_limit: resources(10),
        payload: vec![1, 2, 3],
        signature: [0xFF; 64],
    };
    service.submit_transaction(tx).expect("submits");
    assert_eq!(service.pending_transactions(), 1);

    // Run one cycle
    for _ in 0..5 {
        service.advance().expect("advances");
    }

    assert_eq!(service.height(), 1);
    assert_eq!(service.pending_transactions(), 0);
}

#[test]
fn full_node_service_committee_setup() {
    let mut service = node::FullNodeService::new(node::ProducerConfig::default());

    let members = vec![
        CommitteeMember {
            id: ValidatorId::from_bytes([1; 32]),
            power: PotbWeight(100),
        },
        CommitteeMember {
            id: ValidatorId::from_bytes([2; 32]),
            power: PotbWeight(200),
        },
    ];
    service.setup_committee(members);

    let committee = service.committee().expect("has committee");
    assert_eq!(committee.members.len(), 2);
    assert_eq!(committee.height, 0);
}

#[test]
fn full_node_service_multiple_cycles() {
    let mut service = node::FullNodeService::new(node::ProducerConfig::default());

    for _ in 0..3 {
        for _ in 0..5 {
            service.advance().expect("advances");
        }
    }

    assert_eq!(service.height(), 3);
}

#[test]
fn transactions_root_deterministic() {
    let txs = vec![testkit::transaction(0, 0), testkit::transaction(1, 0)];
    let root1 = node::compute_transactions_root(&txs);
    let root2 = node::compute_transactions_root(&txs);
    assert_eq!(root1, root2);
    assert_ne!(root1, Hash256::ZERO);
}

#[test]
fn hash_transaction_deterministic() {
    let tx = testkit::transaction(0, 0);
    let h1 = node::hash_transaction(&tx);
    let h2 = node::hash_transaction(&tx);
    assert_eq!(h1, h2);
    assert_ne!(h1, Hash256::ZERO);
}

#[test]
fn producer_config_default_values() {
    let config = node::ProducerConfig::default();
    assert_eq!(config.chain_id, 7);
    assert_eq!(config.max_block_transactions, 256);
    assert_eq!(config.max_transaction_bytes, 1024 * 1024);
}
