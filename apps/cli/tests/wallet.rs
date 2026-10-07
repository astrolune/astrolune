// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Actual CLI subprocesses, signature validation, execution, and submission failures.

use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::ed25519_public_key;
use state::{StateDatabase, read_account};
use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};
use transaction::{ValidationContext, address_from_public_key, compute_tx_id};
use types::{AccountState, Address, Resources, Transaction};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-wallet-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("wallet.seed"), [240; 32]).unwrap();
        Self(path)
    }
    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .env_remove("ASTROLUNE_RPC_ADDR")
            .args(args)
            .output()
            .unwrap()
    }
    fn with_password(&self, args: &[&str], password: &[u8]) -> Output {
        use std::process::Stdio;
        let mut process = Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        process.stdin.take().unwrap().write_all(password).unwrap();
        process.wait_with_output().unwrap()
    }
    fn sign(&self, recipient: Address) -> Output {
        self.command(&[
            "sign-payment",
            "42",
            "wallet.seed",
            &recipient.to_string(),
            "123",
            "0",
            "1000",
            "payment.bin",
        ])
    }
    fn payment(&self) -> Transaction {
        Transaction::decode(&std::fs::read(self.0.join("payment.bin")).unwrap()).unwrap()
    }
}

#[test]
fn vault_passwords_stay_off_argv_and_unlocked_keys_sign_normal_transactions() {
    let fixture = Fixture::new();
    let password = b"correct horse battery staple\n";
    let encrypted = success(
        &fixture.with_password(&["wallet-encrypt", "wallet.seed", "wallet.vault"], password),
    );
    assert!(!encrypted.contains("correct horse"));
    assert!(!encrypted.contains(&"f0".repeat(32)));
    assert_eq!(
        std::fs::metadata(fixture.0.join("wallet.vault"))
            .unwrap()
            .len(),
        keystore::vault::WALLET_VAULT_BYTES as u64
    );
    let recipient = Address([77; 32]);
    let signed = fixture.with_password(
        &[
            "sign-payment",
            "42",
            "wallet.vault",
            &recipient.to_string(),
            "123",
            "0",
            "1000",
            "vault-payment.bin",
        ],
        password,
    );
    success(&signed);
    success(&fixture.sign(recipient));
    assert_eq!(
        std::fs::read(fixture.0.join("vault-payment.bin")).unwrap(),
        std::fs::read(fixture.0.join("payment.bin")).unwrap()
    );
    assert!(
        !fixture
            .with_password(
                &["wallet-address", "wallet.vault"],
                b"wrong long password\n"
            )
            .status
            .success()
    );
    assert!(
        !fixture
            .with_password(&["wallet-encrypt", "wallet.seed", "wallet.vault"], password)
            .status
            .success()
    );
    let created = success(&fixture.with_password(&["wallet-create", "fresh.vault"], password));
    assert_ne!(created.lines().next(), encrypted.lines().next());
    let raw = std::fs::read(fixture.0.join("wallet.vault")).unwrap();
    std::fs::write(fixture.0.join("truncated.vault"), &raw[..32]).unwrap();
    assert!(
        !fixture
            .with_password(&["wallet-address", "truncated.vault"], password)
            .status
            .success()
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn contract_commands_activate_explicitly_sign_inspect_and_execute() {
    use transaction::{contract_address, contract_code_key};
    let fixture = Fixture::new();
    success(&fixture.command(&["devnet", "network", "1", "--contracts"]));
    let genesis =
        genesis::Genesis::decode(&std::fs::read(fixture.0.join("network/genesis.bin")).unwrap())
            .unwrap();
    assert_eq!(genesis.runtime_version, 2);
    let code = wat::parse_str(r#"(module (memory (export "memory") 1 1) (func (export "call") (result i32) i32.const 0))"#).unwrap();
    std::fs::write(fixture.0.join("contract.wasm"), &code).unwrap();
    let arguments = [
        "sign-deploy",
        "network/genesis.bin",
        "wallet.seed",
        "contract.wasm",
        "0",
        "1000",
        "deploy.bin",
    ];
    let output = success(&fixture.command(&arguments));
    let deploy =
        Transaction::decode(&std::fs::read(fixture.0.join("deploy.bin")).unwrap()).unwrap();
    let address = contract_address(genesis.chain_id, deploy.sender, deploy.nonce);
    assert!(output.contains(&address.to_string()));
    assert!(
        !fixture.command(&arguments).status.success(),
        "must not overwrite"
    );
    success(&fixture.command(&["inspect-transaction", "deploy.bin"]));
    let mut state = genesis.materialize().unwrap();
    let root = state.root();
    let context = ValidationContext {
        chain_id: genesis.chain_id,
        next_height: 1,
        max_transaction_bytes: 65_536,
    };
    execution::execute_signed(&mut state, &[deploy], root, context, genesis.capacity).unwrap();
    assert_eq!(
        state.get(&contract_code_key(address)),
        Some(code.as_slice())
    );
    std::fs::write(fixture.0.join("input.bin"), []).unwrap();
    std::fs::write(fixture.0.join("keys.txt"), []).unwrap();
    success(&fixture.command(&[
        "sign-call",
        "network/genesis.bin",
        "wallet.seed",
        &address.to_string(),
        "input.bin",
        "keys.txt",
        "1",
        "1000",
        "1000",
        "call.bin",
    ]));
    let call = Transaction::decode(&std::fs::read(fixture.0.join("call.bin")).unwrap()).unwrap();
    success(&fixture.command(&["inspect-transaction", "call.bin"]));
    let root = state.root();
    execution::execute_signed(&mut state, &[call], root, context, genesis.capacity).unwrap();
    success(&fixture.command(&["devnet", "legacy", "1"]));
    assert!(
        !fixture
            .command(&[
                "sign-deploy",
                "legacy/genesis.bin",
                "wallet.seed",
                "contract.wasm",
                "0",
                "1000",
                "denied.bin"
            ])
            .status
            .success()
    );
    assert!(!fixture.0.join("denied.bin").exists());
}

#[test]
fn signed_file_executes_and_replay_fails_without_changing_balances() {
    let fixture = Fixture::new();
    let recipient = Address([77; 32]);
    let sender = address_from_public_key(&ed25519_public_key(&[240; 32]));
    let identity = success(&fixture.command(&["keys", "wallet.seed"]));
    assert!(identity.contains(&sender.to_string()));
    assert!(!identity.contains(&"f0".repeat(32)));
    let signed = success(&fixture.sign(recipient));
    let tx = fixture.payment();
    assert!(signed.contains(&compute_tx_id(&tx).to_string()));
    assert!(signed.contains("submission: not sent"));
    let inspected = success(&fixture.command(&["inspect-payment", "payment.bin"]));
    assert!(inspected.contains("amount: 123"));
    assert!(inspected.contains("fee: 1"));

    success(&fixture.command(&["devnet", "network", "1"]));
    assert_eq!(
        std::fs::read(fixture.0.join("network/wallet.seed")).unwrap(),
        [240; 32]
    );
    let genesis =
        genesis::Genesis::decode(&std::fs::read(fixture.0.join("network/genesis.bin")).unwrap())
            .unwrap();
    let mut state = genesis.materialize().unwrap();
    let context = ValidationContext {
        chain_id: 42,
        next_height: 1,
        max_transaction_bytes: 65536,
    };
    let capacity = Resources {
        compute: 1000,
        memory: 1000,
        io: 1000,
        bandwidth: 65536,
    };
    let root = state.root();
    execution::execute_payments(
        &mut state,
        std::slice::from_ref(&tx),
        root,
        context,
        capacity,
    )
    .unwrap();
    let snapshot = state.snapshot().unwrap();
    assert_eq!(
        read_account(snapshot.as_ref(), sender).unwrap(),
        Some(AccountState {
            nonce: 1,
            balance: 999_999_876
        })
    );
    assert_eq!(
        read_account(snapshot.as_ref(), recipient).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 123
        })
    );
    let root = state.root();
    assert!(execution::execute_payments(&mut state, &[tx], root, context, capacity).is_err());
    assert_eq!(state.root(), root);
}

#[test]
fn self_payment_has_one_access_key_and_existing_output_is_never_overwritten() {
    let fixture = Fixture::new();
    success(&fixture.sign(address_from_public_key(&ed25519_public_key(&[240; 32]))));
    let tx = fixture.payment();
    assert_eq!(tx.access_list.len(), 1);
    assert!(!fixture.sign(Address([77; 32])).status.success());
    assert_eq!(fixture.payment(), tx);
    let old_seed = std::fs::read(fixture.0.join("wallet.seed")).unwrap();
    let output = fixture.command(&[
        "sign-payment",
        "42",
        "wallet.seed",
        &Address([77; 32]).to_string(),
        "1",
        "0",
        "1000",
        "wallet.seed",
    ]);
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(fixture.0.join("wallet.seed")).unwrap(),
        old_seed
    );
}

#[test]
fn rejects_bad_seeds_parameters_and_corrupted_payment_files() {
    let fixture = Fixture::new();
    for length in [0, 31, 33, 1024] {
        std::fs::write(fixture.0.join("bad.seed"), vec![1; length]).unwrap();
        assert!(
            !fixture
                .command(&["wallet-address", "bad.seed"])
                .status
                .success()
        );
    }
    assert!(!fixture.command(&["keys"]).status.success());
    assert!(
        !fixture
            .command(&["status", "localhost:17331"])
            .status
            .success()
    );
    assert!(
        !fixture
            .command(&["status", "127.0.0.1:0", "ignored"])
            .status
            .success()
    );
    let recipient = Address([77; 32]).to_string();
    for (position, invalid) in [
        (1, "0"),
        (1, "4294967296"),
        (3, "0x00"),
        (4, "0"),
        (4, "-1"),
        (4, "+1"),
        (4, "1.5"),
        (4, "18446744073709551615"),
        (5, "18446744073709551615"),
        (6, "0"),
    ] {
        let mut args = vec![
            "sign-payment",
            "42",
            "wallet.seed",
            &recipient,
            "1",
            "0",
            "1000",
            "bad.bin",
        ];
        args[position] = invalid;
        assert!(!fixture.command(&args).status.success(), "{args:?}");
        assert!(!fixture.0.join("bad.bin").exists());
    }
    success(&fixture.sign(Address([77; 32])));
    let mut tx = fixture.payment();
    tx.signature[0] ^= 1;
    std::fs::write(fixture.0.join("payment.bin"), tx.to_bytes()).unwrap();
    assert!(
        !fixture
            .command(&["inspect-payment", "payment.bin"])
            .status
            .success()
    );
    assert!(
        !fixture
            .command(&["submit", "payment.bin", "127.0.0.1:0"])
            .status
            .success()
    );
    std::fs::write(fixture.0.join("payment.bin"), vec![0; 65537]).unwrap();
    assert!(
        !fixture
            .command(&["inspect-payment", "payment.bin"])
            .status
            .success()
    );
}

fn request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let size = u32::from_le_bytes(prefix) as usize;
    assert!(size < 131_500);
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}
fn reply(stream: &mut TcpStream, result: &str) {
    let json = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
    stream
        .write_all(&u32::try_from(json.len()).unwrap().to_le_bytes())
        .unwrap();
    stream.write_all(json.as_bytes()).unwrap();
}
fn status(stream: &mut TcpStream, chain: u32, height: u64) {
    assert!(request(stream).contains("chain_status"));
    reply(
        stream,
        &format!(
            r#"{{"chain_id":{chain},"finalized_height":{height},"finalized_block":"{}"}}"#,
            "00".repeat(32)
        ),
    );
}

#[test]
fn submission_checks_chain_and_expiry_before_sending_any_payment() {
    let fixture = Fixture::new();
    success(&fixture.sign(Address([77; 32])));
    for (chain, height) in [(43, 0), (42, 1000)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            status(&mut stream, chain, height);
            // Keep the listener open until CLI exit; any second connection would
            // hang until its client deadline and fail this test's stderr assertion.
            listener
        });
        let output = fixture.command(&["submit", "payment.bin", &address.to_string()]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("nothing sent"));
        let listener = peer.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn accepted_lost_response_and_wrong_id_preserve_exact_signed_file() {
    let fixture = Fixture::new();
    success(&fixture.sign(Address([77; 32])));
    let tx = fixture.payment();
    let bytes = std::fs::read(fixture.0.join("payment.bin")).unwrap();
    for mode in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let hash = compute_tx_id(&tx);
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            status(&mut stream, 42, 1);
            drop(stream);
            let (mut stream, _) = listener.accept().unwrap();
            let request = request(&mut stream);
            assert!(request.contains("submit_transaction"));
            if mode == 0 {
                reply(&mut stream, &format!(r#""{hash}""#));
            }
            if mode == 2 {
                reply(&mut stream, &format!(r#""{}""#, "00".repeat(32)));
            }
            request
        });
        let output = fixture.command(&["submit", "payment.bin", &address.to_string()]);
        if mode == 0 {
            assert!(success(&output).contains("accepted (not finalized)"));
        } else {
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("outcome unknown"));
        }
        let request = rpc::json::parse_rpc_request(&peer.join().unwrap()).unwrap();
        let sent = request.params.get("data").unwrap().as_str().unwrap();
        let mut expected = String::new();
        for byte in &bytes {
            write!(expected, "{byte:02x}").unwrap();
        }
        assert_eq!(sent, expected);
        assert_eq!(std::fs::read(fixture.0.join("payment.bin")).unwrap(), bytes);
    }
}

#[test]
fn status_and_account_report_node_state_without_fabricated_defaults() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        status(&mut stream, 91, 77);
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        assert!(request(&mut stream).contains("account"));
        reply(&mut stream, r#""0300000000000000f401000000000000""#);
    });
    let status = success(&fixture.command(&["status", &address.to_string()]));
    assert!(status.contains("chain_id: 91"));
    assert!(status.contains("finalized_height: 77"));
    let account = success(&fixture.command(&[
        "account",
        &Address([1; 32]).to_string(),
        &address.to_string(),
    ]));
    assert!(account.contains("balance: 500"));
    assert!(account.contains("next_nonce: 3"));
    peer.join().unwrap();
}
