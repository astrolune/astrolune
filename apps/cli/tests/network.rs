// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Provisioning refuses to overwrite namespaces and produces usable protected journals.

use codec::CanonicalDecode;
use keystore::{DurableSigner, SigningContext};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-cli-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generated_network_has_matching_keys_and_non_overwritable_journals() {
    let fixture = Fixture::new();
    let directory = fixture.0.join("network");
    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("devnet")
        .arg(&directory)
        .arg("4")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(directory.join("genesis.bin")).unwrap();
    let genesis = genesis::Genesis::decode(&bytes).unwrap();
    assert_eq!(genesis.validators.len(), 4);
    let wallet =
        transaction::address_from_public_key(&crypto::blake2s::ed25519_public_key(&[240; 32]));
    assert_eq!(
        genesis.allocations,
        vec![genesis::Allocation {
            address: wallet,
            amount: 1_000_000_000,
        }]
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&wallet.to_string()));
    assert_eq!(
        std::fs::read(directory.join("validators.bin"))
            .unwrap()
            .len(),
        128
    );
    for index in 1..=4 {
        let data = directory.join(format!("node-{index}"));
        p2p::tls::PeerTlsConfig::from_directory(&data.join("tls")).unwrap();
        let signer = DurableSigner::open(
            data.join("signing.journal"),
            SigningContext {
                chain_id: genesis.chain_id,
                genesis: genesis.commitment().unwrap(),
            },
            [index; 32],
        )
        .unwrap();
        assert!(signer.is_protected());
        assert!(signer.last_position().is_none());
    }
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("devnet")
            .arg(&directory)
            .arg("4")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(directory.join("genesis.bin")).unwrap(), bytes);
    let instructions = std::fs::read_to_string(directory.join("START.txt")).unwrap();
    assert_eq!(instructions.matches(" --run --genesis ").count(), 4);
    assert!(instructions.contains("PUBLIC TEST FIXTURES"));
    assert_eq!(instructions.matches(" --tls-dir ").count(), 4);
}

#[test]
fn standalone_tls_bundle_has_unique_secrets_and_refuses_overwrite() {
    let fixture = Fixture::new();
    let directory = fixture.0.join("tls");
    let provision = || {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("init-network-tls")
            .arg(&directory)
            .arg("3")
            .output()
            .unwrap()
    };
    assert!(provision().status.success());
    let mut keys = std::collections::BTreeSet::new();
    let mut root = None;
    for index in 1..=3 {
        let data = directory.join(format!("peer-{index}"));
        p2p::tls::PeerTlsConfig::from_directory(&data).unwrap();
        assert!(keys.insert(std::fs::read(data.join("key.der")).unwrap()));
        let ca = std::fs::read(data.join("ca.der")).unwrap();
        if let Some(root) = &root {
            assert_eq!(&ca, root);
        } else {
            root = Some(ca);
        }
        assert!(!data.join("signing.journal").exists());
    }
    assert!(!provision().status.success());
    assert!(keys.contains(&std::fs::read(directory.join("peer-1/key.der")).unwrap()));
}

#[test]
fn devnet_observer_has_transport_identity_but_no_consensus_seed_or_journal() {
    let fixture = Fixture::new();
    let directory = fixture.0.join("network");
    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("devnet")
        .arg(&directory)
        .arg("--observer")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observer = directory.join("observer");
    p2p::tls::PeerTlsConfig::from_directory(&observer.join("tls")).unwrap();
    assert!(!observer.join("validator.seed").exists());
    assert!(!observer.join("signing.journal").exists());
    let instructions = std::fs::read_to_string(directory.join("START.txt")).unwrap();
    let commands: Vec<_> = instructions
        .lines()
        .filter(|line| line.contains(" --run "))
        .collect();
    assert_eq!(commands.len(), 5);
    let observer_command = commands
        .iter()
        .find(|line| line.contains(" --observer "))
        .unwrap();
    assert!(!observer_command.contains("--validator-key"));
    assert_eq!(
        commands
            .iter()
            .filter(|line| line.contains("--peers 127.0.0.1:18000,"))
            .count(),
        4
    );
}

#[test]
fn supplied_key_provisioning_refuses_existing_chain_or_journal() {
    let fixture = Fixture::new();
    let network = fixture.0.join("network");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("devnet")
            .arg(&network)
            .arg("1")
            .output()
            .unwrap()
            .status
            .success()
    );
    let data = fixture.0.join("validator");
    let provision = || {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("init-validator")
            .arg(network.join("genesis.bin"))
            .arg(network.join("node-1/validator.seed"))
            .arg(&data)
            .output()
            .unwrap()
    };
    assert!(provision().status.success());
    let journal = std::fs::read(data.join("signing.journal")).unwrap();
    assert!(!provision().status.success());
    assert_eq!(
        std::fs::read(data.join("signing.journal")).unwrap(),
        journal
    );
    // Loss of the original journal must not silently authorize new signing state.
    std::fs::remove_file(data.join("signing.journal")).unwrap();
    std::fs::write(data.join("chain.bin"), []).unwrap();
    assert!(!provision().status.success());
    assert!(!data.join("signing.journal").exists());
}
