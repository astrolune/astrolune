// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real TCP submission, durable account queries, and restart replay protection.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use rpc::json::{JsonValue, parse_json};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Address, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-rpc-payment-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(fixture: &Fixture, with_genesis: bool) -> (Process, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
    command
        .arg("--data-dir")
        .arg(fixture.0.join("data"))
        .args([
            "--run",
            "--p2p-listen",
            "127.0.0.1:0",
            "--rpc-listen",
            "127.0.0.2:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if with_genesis {
        command.arg("--genesis").arg(fixture.0.join("genesis.bin"));
    }
    let mut process = Process(command.spawn().unwrap());
    let stdout = process.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(address) = line.strip_prefix("rpc       : ") {
                let _ = sender.send(address.to_owned());
            }
        }
    });
    let address = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("daemon RPC listener");
    (process, address)
}

fn call(address: &str, method: &str, params: &str) -> JsonValue {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let json = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    stream
        .write_all(&u32::try_from(json.len()).unwrap().to_le_bytes())
        .unwrap();
    stream.write_all(json.as_bytes()).unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!(length < 65536);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}
fn account(address: &str, wallet: Address) -> JsonValue {
    call(address, "account", &format!(r#"{{"address":"{wallet}"}}"#))
}
fn submit(address: &str, tx: &Transaction) -> JsonValue {
    call(
        address,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    )
}
fn transfer(recipient: Address, nonce: u64) -> Transaction {
    let public_key = ed25519_public_key(&[1; 32]);
    let sender = address_from_public_key(&public_key);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 42,
        sender,
        nonce,
        access_list,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key,
            recipient,
            amount: 100,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[1; 32], signing_hash(&tx).as_bytes());
    tx
}
fn await_account(address: &str, wallet: Address, expected: &AccountState) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let expected = JsonValue::String(hex(&expected.to_bytes()));
    loop {
        let response = account(address, wallet);
        if response.get("result") == Some(&expected) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "unexpected account response: {response:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn reject_invalid_envelopes(address: &str, tx: &Transaction) {
    for field in 0..3 {
        let mut invalid = tx.clone();
        match field {
            0 => invalid.expires_at = 0,
            1 => invalid.resource_prices = Resources::ZERO,
            _ => invalid.lane = types::TransactionLane::Contracts,
        }
        invalid.signature = ed25519_sign(&[1; 32], signing_hash(&invalid).as_bytes());
        assert!(submit(address, &invalid).get("error").is_some());
    }
}

#[test]
fn rpc_payments_commit_recover_and_reject_replay() {
    let fixture = Fixture::new();
    let recipient = Address([2; 32]);
    let tx = transfer(recipient, 0);
    let genesis = Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 100,
            memory: 1024,
            io: 100,
            bandwidth: 10000,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: 1,
        }],
        allocations: vec![Allocation {
            address: tx.sender,
            amount: 1000,
        }],
    };
    fs::write(fixture.0.join("genesis.bin"), genesis.to_bytes()).unwrap();
    let (process, address) = start(&fixture, true);
    let status = call(&address, "chain_status", "{}");
    assert_eq!(
        status.get("result").unwrap().get("chain_id"),
        Some(&JsonValue::Number(42))
    );
    assert_eq!(
        account(&address, recipient).get("result"),
        Some(&JsonValue::Null)
    );
    let mut forged = tx.clone();
    forged.signature[0] ^= 1;
    assert!(submit(&address, &forged).get("error").is_some());
    assert!(
        call(&address, "submit_transaction", r#"{"data":"00"}"#)
            .get("error")
            .is_some()
    );
    reject_invalid_envelopes(&address, &tx);
    let accepted = submit(&address, &tx);
    assert_eq!(
        accepted.get("result"),
        Some(&JsonValue::String(
            transaction::compute_tx_id(&tx).to_string()
        ))
    );
    await_account(
        &address,
        tx.sender,
        &AccountState {
            nonce: 1,
            balance: 899,
        },
    );
    await_account(
        &address,
        recipient,
        &AccountState {
            nonce: 0,
            balance: 100,
        },
    );
    assert!(submit(&address, &tx).get("error").is_some());
    drop(process);
    let (_process, address) = start(&fixture, true);
    await_account(
        &address,
        tx.sender,
        &AccountState {
            nonce: 1,
            balance: 899,
        },
    );
    assert!(submit(&address, &tx).get("error").is_some());
    assert!(
        submit(&address, &transfer(recipient, 1))
            .get("result")
            .is_some()
    );
    await_account(
        &address,
        tx.sender,
        &AccountState {
            nonce: 2,
            balance: 798,
        },
    );
    await_account(
        &address,
        recipient,
        &AccountState {
            nonce: 0,
            balance: 200,
        },
    );
}

#[test]
fn legacy_daemon_exposes_status_but_rejects_account_operations() {
    let fixture = Fixture::new();
    let (_process, address) = start(&fixture, false);
    assert!(call(&address, "chain_status", "{}").get("result").is_some());
    assert_eq!(
        account(&address, Address([1; 32]))
            .get("error")
            .unwrap()
            .get("code"),
        Some(&JsonValue::Number(-32000))
    );
    assert_eq!(
        call(&address, "submit_transaction", r#"{"data":"00"}"#)
            .get("error")
            .unwrap()
            .get("code"),
        Some(&JsonValue::Number(-32000))
    );
}
