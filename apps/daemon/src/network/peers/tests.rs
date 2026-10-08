// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real packet checks for opt-in compact requests and legacy session fallback.

use super::*;
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{
    compact_wire::{TransactionDictionary, decode_response, encode_response},
    network::{NetworkNode, StaticNetwork},
    network_wire::{NetworkMessage, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use std::{net::TcpListener, path::PathBuf, sync::atomic::AtomicU64};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{Address, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn speculative_cursor_stays_within_four_heights_of_committed_state() {
    assert_eq!(poll_height(7, None), 7);
    assert_eq!(poll_height(7, Some(6)), 7);
    for height in 7..=11 {
        assert_eq!(poll_height(7, Some(height)), height);
    }
    assert_eq!(poll_height(7, Some(12)), 7);
    assert_eq!(poll_height(10, Some(8)), 10);
    assert_eq!(poll_height(u64::MAX - 1, Some(u64::MAX)), u64::MAX);
}

struct Fixture {
    path: PathBuf,
    network: StaticNetwork,
    transport: PeerTransport,
}

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-compact-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let key = ed25519_public_key(&[1; 32]);
        let mut allocations: Vec<_> = [98, 99]
            .map(|seed| Allocation {
                address: address_from_public_key(&ed25519_public_key(&[seed; 32])),
                amount: 1_000_000,
            })
            .into_iter()
            .collect();
        allocations.sort_by_key(|allocation| allocation.address);
        let network = StaticNetwork::new(
            Genesis {
                version: 1,
                chain_id: 42,
                committee_size: 1,
                rotation_count: 1,
                runtime_version: 1,
                capacity: Resources {
                    compute: 1_000_000,
                    memory: 1_000_000,
                    io: 1_000_000,
                    bandwidth: 1_000_000,
                },
                validators: vec![GenesisValidator {
                    id: ValidatorId(blake2s(&key).0),
                    weight: 1,
                }],
                allocations,
            },
            vec![key],
        )
        .unwrap();
        let identity = p2p::provisioning::TransportAuthority::generate()
            .unwrap()
            .issue("compact-test")
            .unwrap();
        let transport = PeerTransport(Some(
            p2p::tls::PeerTlsConfig::from_der(
                identity.ca_der,
                identity.certificate_der,
                identity.private_key_der.to_vec(),
            )
            .unwrap(),
        ));
        Self {
            path,
            network,
            transport,
        }
    }

    fn observer(&self, name: &str) -> PeerNode {
        PeerNode::Observer(Box::new(
            ObserverNode::open(self.network.clone(), &self.path.join(name)).unwrap(),
        ))
    }

    fn finalized(&self) -> Vec<u8> {
        let directory = self.path.join("validator");
        std::fs::create_dir(&directory).unwrap();
        let signer = DurableSigner::create_protected(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: self.network.genesis_hash(),
            },
            [1; 32],
        )
        .unwrap();
        let mut validator = NetworkNode::open(
            self.network.clone(),
            &directory,
            signer,
            Duration::from_millis(100),
        )
        .unwrap();
        for tx in transactions() {
            validator.submit_transaction(tx).unwrap();
        }
        let request = validator.request();
        let now = Instant::now();
        for step in 0..20 {
            validator.tick(now + Duration::from_millis(step)).unwrap();
            if validator.request().height > request.height {
                break;
            }
        }
        assert_eq!(validator.request().height, 2);
        let response = validator.respond(request).unwrap();
        let messages = decode_exchange(request.genesis, &response).unwrap();
        assert!(
            matches!(messages.as_slice(), [NetworkMessage::Finalized { block, .. }] if block.transactions.len() == 2)
        );
        response
    }

    fn runtime(&self, node: PeerNode, local: SocketAddr, discovery: bool) -> PeerRuntime {
        PeerRuntime {
            directory: Arc::new(Mutex::new(
                PeerDirectory::new(
                    discovery.then(|| "127.0.0.0/8".parse().unwrap()),
                    local,
                    &[],
                )
                .unwrap(),
            )),
            stop: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            transport: self.transport.clone(),
            node: Arc::new(Mutex::new(node)),
            genesis: self.network.genesis_hash(),
            discovery,
            compact_blocks: true,
            metrics: Arc::new(NodeMetrics::new(0, true)),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn transactions() -> [Transaction; 2] {
    [98, 99].map(|seed| {
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
    })
}

#[test]
fn server_accepts_raw_and_discovery_compact_requests_alongside_legacy() {
    let fixture = Fixture::new();
    let full = fixture.finalized();
    let genesis = fixture.network.genesis_hash();
    let expected = decode_exchange(genesis, &full).unwrap();
    for discovery in [false, true] {
        let mut node = fixture.observer(if discovery {
            "server-discovery"
        } else {
            "server-raw"
        });
        node.receive_prepared(PreparedExchange::decode(genesis, &full).unwrap())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = fixture.runtime(node, address, discovery);
        let server = runtime.clone();
        let handle = std::thread::spawn(move || {
            let storage_failed = AtomicBool::new(false);
            let _ = server.serve(listener.accept().unwrap().0, &storage_failed);
            assert!(!storage_failed.load(Ordering::Acquire));
        });
        let mut stream = fixture
            .transport
            .connect(TcpStream::connect(address).unwrap())
            .unwrap();
        for wrapped in [false, true] {
            if wrapped && !discovery {
                continue;
            }
            for known_count in [None, Some(0), Some(1), Some(2)] {
                let dictionary = TransactionDictionary::new(
                    transactions().into_iter().take(known_count.unwrap_or(0)),
                );
                let request = SyncRequest { genesis, height: 1 };
                let request = known_count.map_or_else(
                    || request.encode().to_vec(),
                    |_| CompactRequest::new(request, &dictionary).encode(),
                );
                let request = if wrapped {
                    discovery::encode(genesis, &[], &request, MAX_COMPACT_REQUEST_BYTES).unwrap()
                } else {
                    request
                };
                write_packet(
                    &mut stream,
                    &request,
                    runtime.limit(MAX_COMPACT_REQUEST_BYTES),
                    IO_TIMEOUT,
                )
                .unwrap();
                let bytes = read_packet(&mut stream, runtime.limit(MAX_EXCHANGE_BYTES), IO_TIMEOUT)
                    .unwrap();
                let payload = if wrapped {
                    discovery::decode(&bytes, genesis, MAX_EXCHANGE_BYTES)
                        .unwrap()
                        .1
                } else {
                    &bytes
                };
                if known_count.unwrap_or(0) == 0 {
                    assert_eq!(payload, full);
                } else {
                    assert!(payload.starts_with(b"ALCX\x01\0\0\0"));
                    assert!(payload.len() < full.len());
                }
                assert_eq!(
                    decode_response(genesis, payload, &dictionary).unwrap(),
                    expected
                );
            }
        }
        runtime.stop();
        drop(stream);
        handle.join().unwrap();
    }
}

#[test]
fn outgoing_packets_advertise_owned_dictionary_and_reconstruct_after_pool_changes() {
    let fixture = Fixture::new();
    let full = fixture.finalized();
    let genesis = fixture.network.genesis_hash();
    for discovery in [false, true] {
        for known_count in 0..=2 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mut node = fixture.observer(&format!("client-{discovery}-{known_count}"));
            for tx in transactions().into_iter().take(known_count) {
                node.submit_transaction(tx).unwrap();
            }
            let runtime = fixture.runtime(node, "127.0.0.1:1".parse().unwrap(), discovery);
            let server = runtime.clone();
            let full = full.clone();
            let handle = std::thread::spawn(move || {
                let mut stream = server
                    .transport
                    .accept(listener.accept().unwrap().0)
                    .unwrap();
                let bytes = read_packet(
                    &mut stream,
                    server.limit(MAX_COMPACT_REQUEST_BYTES),
                    IO_TIMEOUT,
                )
                .unwrap();
                let (_, payload) = server.unpack(&bytes, MAX_COMPACT_REQUEST_BYTES).unwrap();
                let request = CompactRequest::decode(payload).unwrap();
                assert_eq!(request.known().len(), known_count);
                let messages = decode_exchange(genesis, &full).unwrap();
                let response = encode_response(genesis, &messages, request.known()).unwrap();
                // Finalizing the same block clears the live pool before response decoding.
                server
                    .node
                    .lock()
                    .unwrap()
                    .receive_prepared(PreparedExchange::decode(genesis, &full).unwrap())
                    .unwrap();
                assert!(
                    CompactRequest::new(
                        request.sync(),
                        &server.node.lock().unwrap().compact_dictionary()
                    )
                    .known()
                    .is_empty()
                );
                let response = server.frame(&response, MAX_EXCHANGE_BYTES).unwrap();
                write_packet(
                    &mut stream,
                    &response,
                    server.limit(MAX_EXCHANGE_BYTES),
                    IO_TIMEOUT,
                )
                .unwrap();
            });
            let mut session = None;
            let mut compact = true;
            let prepared = runtime
                .exchange_with_fallback(address, &mut session, &mut compact, None)
                .unwrap();
            assert!(compact);
            let mut receiver = fixture.observer(&format!("receiver-{discovery}-{known_count}"));
            assert_eq!(receiver.receive_prepared(prepared).unwrap(), 0);
            assert_eq!(receiver.request().height, 2);
            assert_eq!(runtime.metrics.get(NodeMetric::ConnectionsOpened), 1);
            assert_eq!(runtime.metrics.get(NodeMetric::ExchangeFailures), 0);
            drop(session);
            handle.join().unwrap();
        }
    }
}

#[test]
fn connected_compact_failure_retries_legacy_and_keeps_preference_across_reconnects() {
    let fixture = Fixture::new();
    let genesis = fixture.network.genesis_hash();
    for discovery in [false, true] {
        for malformed_response in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let node = fixture.observer(&format!("fallback-{discovery}-{malformed_response}"));
            let runtime = fixture.runtime(node, "127.0.0.1:1".parse().unwrap(), discovery);
            let server = runtime.clone();
            let handle = std::thread::spawn(move || {
                let mut stream = server
                    .transport
                    .accept(listener.accept().unwrap().0)
                    .unwrap();
                let bytes = read_packet(
                    &mut stream,
                    server.limit(MAX_COMPACT_REQUEST_BYTES),
                    IO_TIMEOUT,
                )
                .unwrap();
                let (_, payload) = server.unpack(&bytes, MAX_COMPACT_REQUEST_BYTES).unwrap();
                CompactRequest::decode(payload).unwrap();
                if malformed_response {
                    let bytes = if discovery {
                        discovery::encode(
                            genesis,
                            &["127.0.0.2:1".parse().unwrap()],
                            b"ALCX\x01\0\0\0",
                            MAX_EXCHANGE_BYTES,
                        )
                        .unwrap()
                    } else {
                        b"ALCX\x01\0\0\0".to_vec()
                    };
                    write_packet(
                        &mut stream,
                        &bytes,
                        server.limit(MAX_EXCHANGE_BYTES),
                        IO_TIMEOUT,
                    )
                    .unwrap();
                }
                drop(stream);
                for count in [2, 1] {
                    let mut stream = server
                        .transport
                        .accept(listener.accept().unwrap().0)
                        .unwrap();
                    for _ in 0..count {
                        let bytes = read_packet(&mut stream, server.limit(48), IO_TIMEOUT).unwrap();
                        let (_, payload) = server.unpack(&bytes, 48).unwrap();
                        let request = SyncRequest::decode(payload).unwrap();
                        assert_eq!(request.genesis, genesis);
                        let response = server
                            .frame(&encode_exchange(genesis, &[]).unwrap(), MAX_EXCHANGE_BYTES)
                            .unwrap();
                        write_packet(
                            &mut stream,
                            &response,
                            server.limit(MAX_EXCHANGE_BYTES),
                            IO_TIMEOUT,
                        )
                        .unwrap();
                    }
                }
            });
            let mut session = None;
            let mut compact = true;
            runtime
                .exchange_with_fallback(address, &mut session, &mut compact, None)
                .unwrap();
            assert!(!compact);
            runtime
                .exchange_with_fallback(address, &mut session, &mut compact, None)
                .unwrap();
            session = None;
            runtime
                .exchange_with_fallback(address, &mut session, &mut compact, None)
                .unwrap();
            assert!(!compact);
            assert_eq!(runtime.metrics.get(NodeMetric::ConnectionsOpened), 3);
            assert_eq!(runtime.metrics.get(NodeMetric::ExchangeFailures), 1);
            assert!(
                !runtime
                    .directory()
                    .unwrap()
                    .addresses()
                    .contains(&"127.0.0.2:1".parse().unwrap())
            );
            drop(session);
            assert_eq!(runtime.metrics.get(NodeMetric::OutgoingSessions), 0);
            handle.join().unwrap();
        }
    }
}
