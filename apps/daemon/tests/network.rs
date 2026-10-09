// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real processes exchange signatures, gossip payments, restart, and synchronize over mutual TLS.

use codec::CanonicalEncode;
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use rpc::json::{JsonValue, parse_json};
use std::{
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Address, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[path = "../../../crates/consensus/tests/support/potb.rs"]
mod potb_support;
struct Fixture {
    path: PathBuf,
    genesis: Genesis,
    keys: Vec<[u8; 32]>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_profile(1, 4)
    }
    fn with_profile(version: u16, committee_size: usize) -> Self {
        Self::with_activation(version, committee_size, false)
    }
    fn with_activation(version: u16, committee_size: usize, potb: bool) -> Self {
        Self::with_governance(version, committee_size, potb, false)
    }
    fn with_governance(version: u16, committee_size: usize, potb: bool, governed: bool) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-network-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let keys: Vec<_> = (1..=4)
            .map(|index| ed25519_public_key(&[index; 32]))
            .collect();
        let mut validators: Vec<_> = keys
            .iter()
            .map(|key| GenesisValidator {
                id: ValidatorId(blake2s(key).0),
                weight: 1,
            })
            .collect();
        validators.sort_by_key(|member| member.id);
        let genesis = Genesis {
            version,
            chain_id: 42,
            committee_size,
            rotation_count: 1,
            runtime_version: 1,
            capacity: Resources {
                compute: 1_000_000,
                memory: 1_000_000,
                io: 1_000_000,
                bandwidth: 1_000_000,
            },
            validators,
            allocations: vec![Allocation {
                address: address_from_public_key(&ed25519_public_key(&[99; 32])),
                amount: 1_000_000,
            }],
        };
        let profile = potb.then(|| {
            let base = potb_profile(&genesis);
            if governed {
                potb_support::governed(base)
            } else {
                base
            }
        });
        let namespace = profile.as_ref().map_or_else(
            || genesis.commitment().unwrap(),
            consensus::potb_transition::PotbConfiguration::commitment,
        );
        std::fs::write(
            path.join("genesis.bin"),
            profile.as_ref().map_or_else(
                || genesis.to_bytes(),
                consensus::potb_transition::PotbConfiguration::to_bytes,
            ),
        )
        .unwrap();
        std::fs::write(path.join("validators.bin"), keys.concat()).unwrap();
        let authority = p2p::provisioning::TransportAuthority::generate().unwrap();
        for index in 1..=5 {
            let data = path.join(index.to_string());
            std::fs::create_dir(&data).unwrap();
            let tls = data.join("tls");
            std::fs::create_dir(&tls).unwrap();
            let identity = authority.issue(&format!("node-{index}")).unwrap();
            std::fs::write(tls.join("ca.der"), &identity.ca_der).unwrap();
            std::fs::write(tls.join("cert.der"), &identity.certificate_der).unwrap();
            std::fs::write(tls.join("key.der"), &identity.private_key_der).unwrap();
            if index == 5 {
                continue;
            }
            std::fs::write(data.join("validator.seed"), [index; 32]).unwrap();
            drop(
                DurableSigner::create_protected(
                    data.join("signing.journal"),
                    SigningContext {
                        chain_id: 42,
                        genesis: namespace,
                    },
                    [index; 32],
                )
                .unwrap(),
            );
        }
        Self {
            path,
            genesis,
            keys,
        }
    }
    fn start(&self, index: usize, peers: &[String]) -> Process {
        let seeds: Vec<_> = peers
            .iter()
            .enumerate()
            .filter(|(seat, _)| *seat != index - 1)
            .map(|(_, value)| value.clone())
            .collect();
        self.start_with(index, peers, &seeds, &[])
    }
    fn start_with(
        &self,
        index: usize,
        peers: &[String],
        seeds: &[String],
        extra: &[&str],
    ) -> Process {
        let data = self.path.join(index.to_string());
        let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
        if index == 5 {
            command.arg("--observer");
        } else {
            command
                .arg("--validator-key")
                .arg(data.join("validator.seed"))
                .args(["--round-timeout-ms", "500"]);
        }
        command.args(extra);
        if !seeds.is_empty() {
            command.args(["--peers", &seeds.join(",")]);
        }
        let mut child = Process(
            command
                .arg("--genesis")
                .arg(self.path.join("genesis.bin"))
                .arg("--validators")
                .arg(self.path.join("validators.bin"))
                .arg("--tls-dir")
                .arg(data.join("tls"))
                .arg("--data-dir")
                .arg(data)
                .args([
                    "--run",
                    "--p2p-listen",
                    &peers[index - 1],
                    "--rpc-listen",
                    "127.0.0.1:0",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
            String::new(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(address) = line.strip_prefix("rpc       : ") {
                    let _ = sender.send(address.to_owned());
                }
            }
        });
        child.1 = receiver
            .recv_timeout(Duration::from_secs(20))
            .expect("certified daemon starts its RPC listener");
        child
    }
}

#[test]
fn observer_rpc_payment_gossip_and_restart_use_tls_without_any_consensus_seed() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    drop(reservations[4].take());
    let observer = fixture.start(5, &peers);
    let tx = payment();
    let submitted = call(
        &observer.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(submitted.get("error").is_none(), "{submitted:?}");
    let mut validators = Vec::new();
    for index in 1..=3 {
        drop(reservations[index - 1].take());
        validators.push(fixture.start(index, &peers));
    }
    drop(reservations[3].take());
    await_payment(&[&observer, &validators[0], &validators[1], &validators[2]]);
    verify_account_proof(&fixture, &observer);
    drop(observer);
    let restarted = fixture.start(5, &peers);
    await_payment(&[&restarted]);
    verify_account_proof(&fixture, &restarted);
    let replay = call(
        &restarted.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(replay.get("error").is_some());
    drop(restarted);
    drop(validators);
    for name in ["validator.seed", "signing.journal", "consensus-cache.bin"] {
        assert!(!fixture.path.join("5").join(name).exists());
    }
    let restored = node::observer::ObserverNode::open(
        node::network::StaticNetwork::new(fixture.genesis.clone(), fixture.keys.clone()).unwrap(),
        &fixture.path.join("5"),
    )
    .unwrap();
    assert!(restored.storage().checkpoint().unwrap().height >= 1);
}

#[test]
fn observer_directory_cannot_downgrade_to_demonstration_or_reuse_validator_journal() {
    let fixture = Fixture::new();
    let initialize = |index: &str| {
        Command::new(env!("CARGO_BIN_EXE_daemon"))
            .args(["--observer", "--blocks", "0"])
            .arg("--genesis")
            .arg(fixture.path.join("genesis.bin"))
            .arg("--validators")
            .arg(fixture.path.join("validators.bin"))
            .arg("--tls-dir")
            .arg(fixture.path.join(index).join("tls"))
            .arg("--data-dir")
            .arg(fixture.path.join(index))
            .output()
            .unwrap()
    };
    assert!(!initialize("1").status.success());
    assert!(!fixture.path.join("1/chain.bin").exists());
    assert!(initialize("5").status.success());
    let archive = std::fs::read(fixture.path.join("5/chain.bin")).unwrap();
    let downgrade = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .args(["--blocks", "1"])
        .arg("--genesis")
        .arg(fixture.path.join("genesis.bin"))
        .arg("--data-dir")
        .arg(fixture.path.join("5"))
        .output()
        .unwrap();
    assert!(!downgrade.status.success());
    assert_eq!(
        std::fs::read(fixture.path.join("5/chain.bin")).unwrap(),
        archive
    );
    assert!(!fixture.path.join("5/signing.journal").exists());
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
struct Process(Child, String);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn call(address: &str, method: &str, params: &str) -> JsonValue {
    let mut stream = TcpStream::connect(address).unwrap();
    let json = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    p2p::exchange::write_packet(&mut stream, json.as_bytes(), 65536, Duration::from_secs(5))
        .unwrap();
    let bytes = p2p::exchange::read_packet(&mut stream, 65536, Duration::from_secs(5)).unwrap();
    parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}
fn payment() -> Transaction {
    let key = ed25519_public_key(&[99; 32]);
    let sender = address_from_public_key(&key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 42,
        sender,
        nonce: 0,
        expires_at: 1000,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        resource_limit: Resources::ZERO,
        access_list,
        payload: Payment {
            public_key: key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[99; 32], signing_hash(&tx).as_bytes());
    tx
}
fn await_payment(processes: &[&Process]) {
    let deadline = Instant::now() + Duration::from_secs(40);
    let expected = JsonValue::String(hex(&AccountState {
        nonce: 0,
        balance: 123,
    }
    .to_bytes()));
    loop {
        if processes.iter().all(|process| {
            call(
                &process.1,
                "account",
                &format!(r#"{{"address":"{}"}}"#, Address([77; 32])),
            )
            .get("result")
                == Some(&expected)
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "payment did not finalize across the network"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits for this node's own finalized head, the precondition for a historical query.
/// A finalized payment only proves current account state: the payment lands in block
/// one, so a restarted late joiner can serve it while still below height two.
fn await_finalized_height(client: &rpc::TcpRpcClient, height: u64) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let head = client.chain_status().unwrap().finalized_height;
        if head >= height {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "node stalled at height {head} below {height}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn tls_quorum_payment_restart_and_late_join() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..4)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut processes = Vec::new();
    for index in 1..=3 {
        drop(reservations[index - 1].take());
        processes.push(fixture.start(index, &peers));
    }
    drop(reservations[3].take());
    let tx = payment();
    let submitted = call(
        &processes[0].1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(submitted.get("error").is_none(), "{submitted:?}");
    await_payment(&processes.iter().collect::<Vec<_>>());
    // Cold startup at genesis and independent history verification on process restart.
    let late = fixture.start(4, &peers);
    drop(processes.remove(1));
    let restarted = fixture.start(2, &peers);
    await_payment(&[&processes[0], &processes[1], &late, &restarted]);
    let replay = call(
        &late.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(replay.get("error").is_some());
    drop(processes);
    drop(late);
    drop(restarted);
    let network =
        node::network::StaticNetwork::new(fixture.genesis.clone(), fixture.keys.clone()).unwrap();
    let mut heads = Vec::new();
    for index in 1..=4 {
        let data = fixture.path.join(index.to_string());
        let signer = DurableSigner::open(
            data.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: network.genesis_hash(),
            },
            [index; 32],
        )
        .unwrap();
        let node = node::network::NetworkNode::open(
            network.clone(),
            &data,
            signer,
            Duration::from_millis(500),
        )
        .unwrap();
        let request = node::network_wire::SyncRequest {
            genesis: network.genesis_hash(),
            height: 1,
        };
        let messages = node::network_wire::decode_exchange(
            network.genesis_hash(),
            &node.respond(request).unwrap(),
        )
        .unwrap();
        let node::network_wire::NetworkMessage::Finalized { block, .. } = &messages[0] else {
            panic!("certified block required")
        };
        heads.push(block.header.compute_hash());
    }
    assert!(heads.iter().all(|head| *head == heads[0]));
}

#[test]
fn dry_run_checks_tls_before_touching_chain_or_signing_state() {
    let fixture = Fixture::new();
    let data = fixture.path.join("1");
    let journal = std::fs::read(data.join("signing.journal")).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_daemon"))
            .arg("--genesis")
            .arg(fixture.path.join("genesis.bin"))
            .arg("--validators")
            .arg(fixture.path.join("validators.bin"))
            .arg("--validator-key")
            .arg(data.join("validator.seed"))
            .arg("--data-dir")
            .arg(&data)
            .arg("--tls-dir")
            .arg(data.join("tls"))
            .arg("--dry-run")
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    // A valid key from a different identity must fail matching, not silently downgrade.
    let wrong_key = std::fs::read(fixture.path.join("2/tls/key.der")).unwrap();
    std::fs::write(data.join("tls/key.der"), wrong_key).unwrap();
    assert!(!run().status.success());
    std::fs::remove_file(data.join("tls/key.der")).unwrap();
    assert!(!run().status.success());
    assert_eq!(
        std::fs::read(data.join("signing.journal")).unwrap(),
        journal
    );
    assert!(!data.join("chain.bin").exists());
    assert!(!data.join("consensus-cache.bin").exists());
}

#[test]
fn missing_journal_and_incomplete_network_arguments_fail_without_provisioning() {
    let fixture = Fixture::new();
    let downgrade = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--genesis")
        .arg(fixture.path.join("genesis.bin"))
        .arg("--data-dir")
        .arg(fixture.path.join("1"))
        .args(["--blocks", "1"])
        .output()
        .unwrap();
    assert!(!downgrade.status.success());
    assert!(!fixture.path.join("1/chain.bin").exists());
    let directory = fixture.path.join("missing");
    std::fs::create_dir(&directory).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--genesis")
        .arg(fixture.path.join("genesis.bin"))
        .arg("--validators")
        .arg(fixture.path.join("validators.bin"))
        .arg("--validator-key")
        .arg(fixture.path.join("1/validator.seed"))
        .arg("--tls-dir")
        .arg(fixture.path.join("1/tls"))
        .arg("--data-dir")
        .arg(&directory)
        .args(["--blocks", "0"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!directory.join("signing.journal").exists());
    assert!(!directory.join("chain.bin").exists());
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_daemon"))
            .args(["--validators", "keys", "--blocks", "0"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

fn corrupt_first_finalized(path: &std::path::Path) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    // Corrupt block 1, after the genesis anchor, without changing file length.
    file.seek(SeekFrom::Start(40)).unwrap();
    let mut length = [0; 8];
    file.read_exact(&mut length).unwrap();
    let at = 40 + 40 + u64::from_le_bytes(length) + 12;
    file.seek(SeekFrom::Start(at)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn corrupted_history_read_stops_observer_process() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|r| r.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    drop(reservations[4].take());
    let mut observer = fixture.start(5, &peers);
    let tx = payment();
    let result = call(
        &observer.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(result.get("error").is_none());
    let mut validators = Vec::new();
    for index in 1..=3 {
        drop(reservations[index - 1].take());
        validators.push(fixture.start(index, &peers));
    }
    await_payment(&[&observer]);
    drop(validators);
    corrupt_first_finalized(&fixture.path.join("5/chain.bin"));
    let tls = p2p::tls::PeerTlsConfig::from_directory(&fixture.path.join("1/tls")).unwrap();
    let socket = TcpStream::connect(&peers[4]).unwrap();
    let mut stream = tls.connect(socket, Duration::from_secs(2)).unwrap();
    let request = node::network_wire::SyncRequest {
        genesis: fixture.genesis.commitment().unwrap(),
        height: 1,
    };
    p2p::exchange::write_packet(&mut stream, &request.encode(), 48, Duration::from_secs(2))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = observer.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "local history corruption must stop the daemon"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn corrupted_history_read_over_rpc_stops_observer_process() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|r| r.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    drop(reservations[4].take());
    let mut observer = fixture.start(5, &peers);
    let tx = payment();
    let result = call(
        &observer.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(result.get("error").is_none());
    let mut validators = Vec::new();
    for index in 1..=3 {
        drop(reservations[index - 1].take());
        validators.push(fixture.start(index, &peers));
    }
    await_payment(&[&observer]);
    drop(validators);
    corrupt_first_finalized(&fixture.path.join("5/chain.bin"));
    let result = call(&observer.1, "block", r#"{"height":1}"#);
    assert!(result.get("error").is_some());
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = observer.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "RPC corruption must stop the daemon"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn verify_account_proof(fixture: &Fixture, process: &Process) {
    let client =
        rpc::TcpRpcClient::new(process.1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let id = transaction::compute_tx_id(&payment());
    let receipt = client.receipt(id, None).unwrap().unwrap();
    assert!(
        receipt
            .verify(&fixture.genesis, &fixture.keys, id, 1)
            .unwrap()
            .succeeded
    );
    let saved = rpc::CertifiedReceiptProof::from_bytes(&receipt.to_bytes().unwrap()).unwrap();
    assert_eq!(saved, receipt);
    assert_eq!(
        client.receipt(id, Some(receipt.0.header.height)).unwrap(),
        Some(receipt)
    );
    assert!(
        client
            .receipt(types::Hash256([0xff; 32]), None)
            .unwrap()
            .is_none()
    );
    let key = state::account_key(Address([77; 32]));
    let proof = client.state_proof(&key).unwrap();
    let historical = client
        .state_proof_at(&key, proof.header.unwrap().height)
        .unwrap()
        .unwrap();
    assert_eq!(historical, proof);
    let genesis_proof = client.state_proof_at(&key, 0).unwrap().unwrap();
    assert_eq!(
        genesis_proof
            .verify(&fixture.genesis, &fixture.keys, &key, 0)
            .unwrap(),
        None
    );
    // A height beyond the served head is catch-up, never absent retained history.
    assert!(matches!(
        client.state_proof_at(&key, u64::MAX),
        Err(rpc::ClientError::Remote { code: -32000, .. })
    ));
    assert_eq!(
        proof
            .verify(&fixture.genesis, &fixture.keys, &key, 1)
            .unwrap(),
        Some(
            AccountState {
                nonce: 0,
                balance: 123
            }
            .to_bytes()
            .as_slice()
        )
    );
    let absent = types::StateKey(b"absent-from-chain".to_vec());
    let proof = client.state_proof(&absent).unwrap();
    assert_eq!(
        proof
            .verify(&fixture.genesis, &fixture.keys, &absent, 1)
            .unwrap(),
        None
    );
}

fn metric(address: &str, name: &str) -> u64 {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut text = String::new();
    stream.take(8192).read_to_string(&mut text).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("astrolune_{name} ")))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn scoped_tls_discovery_builds_a_mesh_reuses_sessions_and_survives_bootstrap_loss() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|value| value.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut metric_ports: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let metrics: Vec<_> = metric_ports
        .iter()
        .map(|value| value.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let extra = |index: usize| {
        [
            "--discover-in",
            "127.0.0.0/8",
            "--metrics-listen",
            metrics[index - 1].as_str(),
        ]
    };
    drop(reservations[4].take());
    drop(metric_ports[4].take());
    let bootstrap = fixture.start_with(5, &peers, &[], &extra(5));
    let mut validators = Vec::new();
    for index in 1..=4 {
        drop(reservations[index - 1].take());
        drop(metric_ports[index - 1].take());
        validators.push(fixture.start_with(index, &peers, &[peers[4].clone()], &extra(index)));
    }
    let tx = payment();
    assert!(
        call(
            &bootstrap.1,
            "submit_transaction",
            &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes()))
        )
        .get("error")
        .is_none()
    );
    await_payment(&[
        &validators[0],
        &validators[1],
        &validators[2],
        &validators[3],
        &bootstrap,
    ]);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if metrics[..4].iter().all(|address| {
            metric(address, "p2p_known_peers") == 4
                && metric(address, "p2p_exchanges_total")
                    > metric(address, "p2p_connections_opened_total") * 3
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "discovery must find validators and reuse authenticated sessions"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(metric(&metrics[4], "observer"), 1);
    let height = metrics[..4]
        .iter()
        .map(|address| metric(address, "finalized_height"))
        .max()
        .unwrap();
    drop(bootstrap);
    let deadline = Instant::now() + Duration::from_secs(20);
    while metrics[..4]
        .iter()
        .any(|address| metric(address, "finalized_height") <= height + 1)
    {
        assert!(
            Instant::now() < deadline,
            "direct discovered routes must keep finalizing without bootstrap"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(validators.remove(0));
    let restarted = fixture.start_with(1, &peers, &[peers[1].clone()], &extra(1));
    await_payment(&[&restarted]);
    verify_account_proof(&fixture, &restarted);
}

#[test]
fn tls_rotating_profile_serves_verifiable_handoffs_and_recovers_all_roles() {
    let fixture = Fixture::with_profile(2, 3);
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut processes = Vec::new();
    for index in 1..=4 {
        drop(reservations[index - 1].take());
        processes.push(fixture.start(index, &peers));
    }
    let tx = payment();
    let submitted = call(
        &processes[0].1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(submitted.get("error").is_none(), "{submitted:?}");
    await_payment(&processes.iter().collect::<Vec<_>>());
    let client =
        rpc::TcpRpcClient::new(processes[0].1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    while client.chain_status().unwrap().finalized_height < 4 {
        assert!(Instant::now() < deadline, "rotating quorum did not advance");
        std::thread::sleep(Duration::from_millis(100));
    }
    let key = state::account_key(Address([77; 32]));
    let proof = client.state_proof(&key).unwrap();
    let mut trusted =
        consensus::rotation::HandoffVerifier::new(&fixture.genesis, &fixture.keys).unwrap();
    client
        .advance_handoffs(
            &mut trusted,
            proof.header.unwrap().height,
            100,
            Duration::from_secs(20),
        )
        .unwrap();
    let value = proof
        .verify_with_handoffs(&trusted, &key, 4)
        .unwrap()
        .unwrap();
    assert_eq!(
        value,
        AccountState {
            nonce: 0,
            balance: 123
        }
        .to_bytes()
    );
    assert!(
        proof
            .verify(&fixture.genesis, &fixture.keys, &key, 0)
            .is_err()
    );
    drop(reservations[4].take());
    let observer = fixture.start(5, &peers);
    await_payment(&[&observer]);
    drop(observer);
    drop(processes);
    let mut restarted = Vec::new();
    for index in 1..=5 {
        restarted.push(fixture.start(index, &peers));
    }
    await_payment(&restarted.iter().collect::<Vec<_>>());
    let client =
        rpc::TcpRpcClient::new(restarted[4].1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    // The finalized payment lands in block one, so it does not imply this observer
    // has caught back up to the height queried below.
    await_finalized_height(&client, 2);
    let first = client.committee_handoff(1).unwrap().unwrap();
    let mut fresh =
        consensus::rotation::HandoffVerifier::new(&fixture.genesis, &fixture.keys).unwrap();
    fresh.apply(&first).unwrap();
    assert_eq!(fresh.current().context().unwrap().members().count(), 3);
    let historical = client
        .state_proof_at(&genesis::genesis_key(), 2)
        .unwrap()
        .unwrap_or_else(|| {
            // A restarted late-joining observer must retain height 2: the window is 64
            // blocks and log replay rebuilds the index. Report its head so an
            // intermittent absence shows whether catch-up had progressed.
            panic!(
                "restarted observer retained no state at height 2; status: {:?}",
                call(&restarted[4].1, "chain_status", "{}").get("result")
            )
        });
    historical
        .verify_with_handoffs(&fresh, &genesis::genesis_key(), 2)
        .unwrap();
}

#[test]
fn tls_potb_profile_serves_verifiable_handoffs_and_recovers_all_roles() {
    let fixture = Fixture::with_activation(2, 3, true);
    let profile = potb_profile(&fixture.genesis);
    let mut reservations: Vec<_> = (0..5)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut processes = Vec::new();
    for index in 1..=4 {
        drop(reservations[index - 1].take());
        processes.push(fixture.start(index, &peers));
    }
    let tx = payment();
    let submitted = call(
        &processes[0].1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(submitted.get("error").is_none(), "{submitted:?}");
    await_payment(&processes.iter().collect::<Vec<_>>());
    let client =
        rpc::TcpRpcClient::new(processes[0].1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    while client.chain_status().unwrap().finalized_height < 4 {
        assert!(Instant::now() < deadline, "rotating quorum did not advance");
        std::thread::sleep(Duration::from_millis(100));
    }
    let key = state::account_key(Address([77; 32]));
    let proof = client.state_proof(&key).unwrap();
    let mut trusted =
        consensus::potb_transition::PotbVerifier::new(&profile, &fixture.keys).unwrap();
    client
        .advance_potb_handoffs(
            &mut trusted,
            proof.header.unwrap().height,
            100,
            Duration::from_secs(20),
        )
        .unwrap();
    let value = proof.verify_with_potb(&trusted, &key, 4).unwrap().unwrap();
    assert_eq!(
        value,
        AccountState {
            nonce: 0,
            balance: 123
        }
        .to_bytes()
    );
    assert!(
        proof
            .verify(&fixture.genesis, &fixture.keys, &key, 0)
            .is_err()
    );
    drop(reservations[4].take());
    let observer = fixture.start(5, &peers);
    await_payment(&[&observer]);
    drop(observer);
    drop(processes);
    let mut restarted = Vec::new();
    for index in 1..=5 {
        restarted.push(fixture.start(index, &peers));
    }
    await_payment(&restarted.iter().collect::<Vec<_>>());
    let client =
        rpc::TcpRpcClient::new(restarted[4].1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    // The finalized payment lands in block one, so it does not imply this observer
    // has caught back up to the height queried below.
    await_finalized_height(&client, 2);
    let first = client.potb_handoff(1).unwrap().unwrap();
    let mut fresh = consensus::potb_transition::PotbVerifier::new(&profile, &fixture.keys).unwrap();
    fresh.apply(&first).unwrap();
    let historical = client
        .state_proof_at(&genesis::genesis_key(), 2)
        .unwrap()
        .unwrap();
    historical
        .verify_with_potb(&fresh, &genesis::genesis_key(), 2)
        .unwrap();
    assert_eq!(
        fresh
            .current()
            .committee()
            .context()
            .unwrap()
            .members()
            .count(),
        3
    );
}

/// A height the answering node never finalized is catch-up, not absent history.
/// Collapsing both into a null result let a restarted late joiner that still sat
/// below the queried height look exactly like one whose index had evicted it.
#[test]
fn unreached_heights_are_unavailable_rather_than_absent_retained_history() {
    let fixture = Fixture::new();
    let reservations: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().to_string())
        .collect();
    drop(reservations);
    // Without configured peers this observer cannot leave its genesis anchor.
    let observer = fixture.start_with(5, &peers, &[], &[]);
    let client =
        rpc::TcpRpcClient::new(observer.1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    assert_eq!(client.chain_status().unwrap().finalized_height, 0);
    assert!(
        client
            .state_proof_at(&genesis::genesis_key(), 0)
            .unwrap()
            .is_some()
    );
    for height in [1, 2, u64::MAX] {
        assert!(
            matches!(
                client.state_proof_at(&genesis::genesis_key(), height),
                Err(rpc::ClientError::Remote { code: -32000, .. })
            ),
            "height {height} answered as retained history"
        );
    }
}

fn potb_profile(genesis: &Genesis) -> consensus::potb_transition::PotbConfiguration {
    consensus::potb_transition::PotbConfiguration::new(
        genesis.clone(),
        consensus::potb::PotbPolicy {
            epoch_blocks: 2,
            initial_weight: 1,
            age_increment: 1,
            maximum_weight: 10,
        },
    )
    .unwrap()
}

#[test]
fn potb_rpc_authenticates_and_persists_pending_admission_without_claiming_finality() {
    let fixture = Fixture::with_activation(2, 3, true);
    let profile = potb_profile(&fixture.genesis);
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let peers = vec![reserved.local_addr().unwrap().to_string()];
    drop(reserved);
    let process = fixture.start(1, &peers);
    let client =
        rpc::TcpRpcClient::new(process.1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let trusted = consensus::potb_transition::PotbVerifier::new(&profile, &fixture.keys).unwrap();
    let admission = potb_support::admission(trusted.current(), trusted.parent(), 99);
    assert_eq!(
        client.submit_potb_admission(&admission).unwrap(),
        admission.request().id()
    );
    assert_eq!(
        client.submit_potb_admission(&admission).unwrap(),
        admission.request().id()
    );
    assert_eq!(client.chain_status().unwrap().finalized_height, 0);
    let bytes = std::fs::read(fixture.path.join("1/consensus-cache.bin")).unwrap();
    assert!(node::network_wire::decode_exchange(profile.commitment(), &bytes).unwrap().iter().any(|message| matches!(message, node::network_wire::NetworkMessage::PotbAdmission(value) if value == &admission)));
    let mut corrupt = admission.to_bytes().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    let params = format!(r#"{{"data":"{}"}}"#, hex(&corrupt));
    assert!(
        call(&process.1, "submit_potb_admission", &params)
            .get("error")
            .is_some()
    );
    assert!(
        call(
            &process.1,
            "submit_potb_evidence",
            &format!(r#"{{"data":"{}"}}"#, hex(&admission.to_bytes().unwrap()))
        )
        .get("error")
        .is_some()
    );
    let key = genesis::genesis_key();
    client
        .state_proof(&key)
        .unwrap()
        .verify_potb_genesis(&profile, &fixture.keys, &key)
        .unwrap();
}

#[test]
fn governance_rpc_persists_only_valid_current_quorum_and_survives_restart() {
    let fixture = Fixture::with_governance(2, 3, true, true);
    let profile = potb_support::governed(potb_profile(&fixture.genesis));
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let peers = vec![reserved.local_addr().unwrap().to_string()];
    drop(reserved);
    let process = fixture.start(1, &peers);
    let client =
        rpc::TcpRpcClient::new(process.1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let trusted = consensus::potb_transition::PotbVerifier::new(&profile, &fixture.keys).unwrap();
    let certificate = potb_support::parameters(trusted.current(), trusted.parent());
    assert_eq!(
        client.submit_governance(&certificate).unwrap(),
        certificate.request().id()
    );
    assert_eq!(client.chain_status().unwrap().finalized_height, 0);
    let mut invalid = certificate.to_bytes().unwrap();
    *invalid.last_mut().unwrap() ^= 1;
    assert!(
        call(
            &process.1,
            "submit_governance",
            &format!(r#"{{"data":"{}"}}"#, hex(&invalid))
        )
        .get("error")
        .is_some()
    );
    let saved = std::fs::read(fixture.path.join("1/consensus-cache.bin")).unwrap();
    assert!(node::network_wire::decode_exchange(profile.commitment(), &saved).unwrap().iter().any(|message| matches!(message, node::network_wire::NetworkMessage::Governance(value) if value == &certificate)));
    drop(process);
    let restarted = fixture.start(1, &peers);
    let client =
        rpc::TcpRpcClient::new(restarted.1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    assert_eq!(
        client.submit_governance(&certificate).unwrap(),
        certificate.request().id()
    );
    client
        .state_proof(&genesis::genesis_key())
        .unwrap()
        .verify_potb_genesis(&profile, &fixture.keys, &genesis::genesis_key())
        .unwrap();
}

#[test]
fn daemon_retained_recovery_requires_both_descriptor_and_independent_pin() {
    let fixture = Fixture::with_governance(2, 3, true, true);
    let profile = potb_support::governed(potb_profile(&fixture.genesis));
    let mut reservations: Vec<_> = (0..4)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut processes = Vec::new();
    for index in 1..=4 {
        drop(reservations[index - 1].take());
        processes.push(fixture.start(index, &peers));
    }
    let client =
        rpc::TcpRpcClient::new(processes[0].1.parse().unwrap(), Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.chain_status().unwrap().finalized_height < 3 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(processes);
    let network = node::network::StaticNetwork::with_potb(profile, fixture.keys.clone()).unwrap();
    let source = storage::ChainStorage::open(fixture.path.join("1/chain.bin")).unwrap();
    let destination = fixture.path.join("retained");
    let point = network.export_retained(&source, 1, &destination).unwrap();
    std::fs::write(destination.join("checkpoint.bin"), point.to_bytes()).unwrap();
    let run = |pin: Option<String>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
        command
            .args(["--blocks", "0", "--observer"])
            .arg("--genesis")
            .arg(fixture.path.join("genesis.bin"))
            .arg("--validators")
            .arg(fixture.path.join("validators.bin"))
            .arg("--tls-dir")
            .arg(fixture.path.join("5/tls"))
            .arg("--data-dir")
            .arg(&destination)
            .arg("--checkpoint")
            .arg(destination.join("checkpoint.bin"));
        if let Some(pin) = pin {
            command.args(["--checkpoint-id", &pin]);
        }
        command.output().unwrap()
    };
    assert!(!run(None).status.success());
    assert!(
        !run(Some(types::Hash256([9; 32]).to_string()))
            .status
            .success()
    );
    let recovered = run(Some(point.id().to_string()));
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(
        String::from_utf8_lossy(&recovered.stdout)
            .contains("Certified history and node-role recovery complete.")
    );
    assert!(run(Some(point.id().to_string())).status.success());
    let mut altered = point.to_bytes();
    altered[40] ^= 1;
    std::fs::write(destination.join("checkpoint.bin"), altered).unwrap();
    assert!(!run(Some(point.id().to_string())).status.success());
}
