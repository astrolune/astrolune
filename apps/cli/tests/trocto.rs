// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Native profile provisioning and offline canonical contract signatures.

use codec::{CanonicalDecode, CanonicalEncode};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
use transaction::{ContractAction, ContractPayload};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-cli-trocto-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn command(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn provisions_native_profile_and_signs_source_and_packages_identically() {
    let fixture = Fixture::new();
    let provisioned = fixture.command(&["devnet", "network", "1", "--trocto"]);
    assert!(
        provisioned.status.success(),
        "{}",
        String::from_utf8_lossy(&provisioned.stderr)
    );
    let genesis_path = fixture.0.join("network/genesis.bin");
    let mut genesis = genesis::Genesis::decode(&std::fs::read(&genesis_path).unwrap()).unwrap();
    assert_eq!(genesis.runtime_version, 3);
    let source = "fn call(input: u64) -> u64 { let next = state_get(\"counter\") + input; state_set(\"counter\", next); emit(1, next); return next; }";
    std::fs::write(fixture.0.join("main.tc"), source).unwrap();
    std::fs::write(
        fixture.0.join("main.tcp"),
        trocto_compiler::SourcePackage::new(source)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    for (source, output) in [
        ("main.tc", "deploy.bin"),
        ("main.tcp", "package-deploy.bin"),
    ] {
        let signed = fixture.command(&[
            "sign-trocto-deploy",
            "network/genesis.bin",
            "network/wallet.seed",
            source,
            "0",
            "20",
            output,
        ]);
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    let bytes = std::fs::read(fixture.0.join("deploy.bin")).unwrap();
    assert_eq!(
        bytes,
        std::fs::read(fixture.0.join("package-deploy.bin")).unwrap()
    );
    let tx = types::Transaction::decode(&bytes).unwrap();
    let payload = ContractPayload::decode(&tx.payload).unwrap();
    assert_eq!(
        payload.action,
        ContractAction::DeployTrocto(source.as_bytes().to_vec())
    );
    assert!(
        fixture
            .command(&["inspect-transaction", "deploy.bin"])
            .status
            .success()
    );
    let address =
        transaction::trocto_contract_address(tx.chain_id, tx.sender, tx.nonce).to_string();
    std::fs::write(fixture.0.join("keys.txt"), "636f756e746572\n").unwrap();
    let called = fixture.command(&[
        "sign-trocto-call",
        "network/genesis.bin",
        "network/wallet.seed",
        &address,
        "42",
        "keys.txt",
        "1",
        "20",
        "10000",
        "call.bin",
    ]);
    assert!(
        called.status.success(),
        "{}",
        String::from_utf8_lossy(&called.stderr)
    );
    let call =
        types::Transaction::decode(&std::fs::read(fixture.0.join("call.bin")).unwrap()).unwrap();
    match ContractPayload::decode(&call.payload).unwrap().action {
        ContractAction::CallTrocto { input, keys, .. } => {
            assert_eq!(input, 42u64.to_le_bytes());
            assert_eq!(keys, vec![b"counter".to_vec()]);
        }
        other => panic!("unexpected payload {other:?}"),
    }
    genesis.runtime_version = 2;
    std::fs::write(&genesis_path, genesis.to_bytes()).unwrap();
    let rejected = fixture.command(&[
        "sign-trocto-deploy",
        "network/genesis.bin",
        "network/wallet.seed",
        "main.tc",
        "0",
        "20",
        "rejected.bin",
    ]);
    assert!(!rejected.status.success());
    assert!(!fixture.0.join("rejected.bin").exists());
}
