// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Real CLI provisioning and offline verification of a `PoTB` authority stream.

#[path = "../../../crates/consensus/tests/support/potb.rs"]
mod support;

use consensus::potb_transition::{PotbConfiguration, PotbHandoff, PotbVerifier};
use rpc::{CertifiedReceiptProof, CertifiedStateProof};
use state::{StateDatabase, StateValueProof};
use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::Command,
    time::Duration,
};
use storage::{BlockEffects, StoredReceipts};
use types::{BlockHeader, ExecutionReceipt, Hash256, Resources};

struct Fixture(PathBuf);
impl Fixture {
    fn verify_candidate_journal(&self, profile: &PotbConfiguration) {
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_cli"))
                .current_dir(&self.0)
                .args(["init-validator", "profile", "candidate", "new-node"])
                .output()
                .unwrap()
        };
        let output = run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let journal = self.0.join("new-node/signing.journal");
        let saved = std::fs::read(&journal).unwrap();
        drop(
            keystore::DurableSigner::open(
                &journal,
                keystore::SigningContext {
                    chain_id: profile.genesis().chain_id,
                    genesis: profile.commitment(),
                },
                [99; 32],
            )
            .unwrap(),
        );
        assert!(!run().status.success());
        assert_eq!(std::fs::read(journal).unwrap(), saved);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
fn serve(replies: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let worker = std::thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let length = u32::from_le_bytes(prefix) as usize;
            assert!(length < 1024);
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#, hex(&reply));
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (address, worker)
}
fn fixtures() -> (
    PotbConfiguration,
    Vec<[u8; 32]>,
    Vec<PotbHandoff>,
    CertifiedStateProof,
    CertifiedReceiptProof,
) {
    let (genesis, keys) = support::fixture();
    let mut trusted = PotbVerifier::new(&genesis, &keys).unwrap();
    let mut handoffs = vec![];
    for _ in 0..2 {
        let handoff = support::handoff(&trusted, support::batch(trusted.current()));
        trusted.apply(&handoff).unwrap();
        handoffs.push(handoff);
    }
    let db = genesis.materialize(&keys).unwrap();
    let snapshot = db.snapshot().unwrap();
    let receipt = ExecutionReceipt {
        transaction: Hash256([22; 32]),
        succeeded: true,
        resources: Resources::ZERO,
        output_root: Hash256([23; 32]),
    };
    let header = BlockHeader {
        height: trusted.current().committee().height(),
        parent: trusted.parent(),
        committee_root: trusted.current().committee().context().unwrap().root(),
        capacity: genesis.genesis().capacity,
        transactions_root: Hash256([24; 32]),
        state_root: db.root(),
        receipts_root: receipt.commitment(),
    };
    let certificate = support::certificate(trusted.current().committee(), &header)
        .encode()
        .unwrap();
    let proof = CertifiedStateProof::create(
        snapshot.as_ref(),
        &genesis::genesis_key(),
        Some((header, certificate.clone())),
    )
    .unwrap();
    let receipt = CertifiedReceiptProof(StoredReceipts {
        header,
        certificate,
        effects: BlockEffects {
            receipts: vec![receipt],
            genesis: StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap(),
            committee: None,
            potb: None,
        },
    });
    (genesis, keys, handoffs, proof, receipt)
}

#[test]
fn potb_proof_sidecars_work_offline_and_reject_truncation_or_foreign_anchors() {
    let directory = Fixture(
        std::env::temp_dir().join(format!("astrolune-cli-potb-handoff-{}", std::process::id())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let (genesis, keys, handoffs, proof, receipt) = fixtures();
    std::fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(directory.0.join("keys"), keys.concat()).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&directory.0)
            .args(args)
            .output()
            .unwrap()
    };
    for (command, verify, query, bytes, file) in [
        (
            "state-proof",
            "verify-state-proof",
            hex(genesis::genesis_key().as_bytes()),
            proof.to_bytes().unwrap(),
            "state",
        ),
        (
            "receipt",
            "verify-receipt",
            Hash256([22; 32]).to_string(),
            receipt.to_bytes().unwrap(),
            "receipt",
        ),
    ] {
        let mut replies = vec![bytes];
        replies.extend(handoffs.iter().map(|handoff| handoff.to_bytes().unwrap()));
        let (address, worker) = serve(replies);
        let output = run(&[command, "genesis", "keys", &query, "3", file, &address]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        worker.join().unwrap();
        let output = run(&[verify, "genesis", "keys", &query, "3", file]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let sidecar = directory.0.join(format!("{file}.handoffs"));
        let saved = std::fs::read(&sidecar).unwrap();
        std::fs::write(&sidecar, &saved[..saved.len() - 1]).unwrap();
        assert!(
            !run(&[verify, "genesis", "keys", &query, "3", file])
                .status
                .success()
        );
        let mut foreign = saved;
        foreign[16] ^= 1;
        std::fs::write(sidecar, foreign).unwrap();
        assert!(
            !run(&[verify, "genesis", "keys", &query, "3", file])
                .status
                .success()
        );
    }
    assert!(std::fs::read_dir(&directory.0).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("pending")
    }));
    let output = run(&["devnet", "vrf-devnet", "4", "--potb", "--observer"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let provisioned = PotbConfiguration::from_bytes(
        &std::fs::read(directory.0.join("vrf-devnet/genesis.bin")).unwrap(),
    )
    .unwrap();
    assert_eq!(provisioned.genesis().version, 2);
    assert_eq!(provisioned.genesis().committee_size, 3);
}

#[test]
fn configuration_candidate_provisioning_and_historical_evidence_match_authenticated_state() {
    let directory = Fixture(
        std::env::temp_dir().join(format!("astrolune-cli-potb-tools-{}", std::process::id())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let (profile, keys, handoffs, _, _) = fixtures();
    std::fs::write(
        directory.0.join("base"),
        codec::CanonicalEncode::to_bytes(profile.genesis()),
    )
    .unwrap();
    std::fs::write(directory.0.join("keys"), keys.concat()).unwrap();
    std::fs::write(directory.0.join("candidate"), [99; 32]).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&directory.0)
            .args(args)
            .output()
            .unwrap()
    };
    let output = run(&["potb-config", "base", "2", "10", "3", "20", "profile"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(directory.0.join("profile")).unwrap(),
        profile.to_bytes()
    );
    assert!(
        !run(&["potb-config", "base", "0", "10", "3", "20", "invalid"])
            .status
            .success()
    );
    assert!(!directory.0.join("invalid").exists());
    directory.verify_candidate_journal(&profile);
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let initial = trusted.current().committee().clone();
    let roots: Vec<_> = handoffs
        .iter()
        .map(|handoff| handoff.header.committee_root)
        .collect();
    for handoff in &handoffs {
        trusted.apply(handoff).unwrap();
    }
    let expected = support::evidence(trusted.current(), &initial, &roots, 1);
    std::fs::write(directory.0.join("offence"), expected.evidence().encode()).unwrap();
    let (address, worker) = serve(
        handoffs
            .iter()
            .map(|handoff| handoff.to_bytes().unwrap())
            .collect(),
    );
    let output = run(&[
        "potb-evidence",
        "profile",
        "keys",
        "offence",
        "3",
        "bundle",
        &address,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().unwrap();
    assert_eq!(
        std::fs::read(directory.0.join("bundle")).unwrap(),
        expected.to_bytes().unwrap()
    );
    assert!(
        !run(&[
            "potb-evidence",
            "profile",
            "keys",
            "offence",
            "10002",
            "oversize",
            &address
        ])
        .status
        .success()
    );
    assert!(!directory.0.join("oversize").exists());
}
