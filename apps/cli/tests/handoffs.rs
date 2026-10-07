// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI fetch plus offline verification of a rotating authority stream.

#[path = "../../../crates/consensus/tests/support/rotation.rs"]
mod support;

use codec::{CanonicalDecode, CanonicalEncode};
use consensus::rotation::{CommitteeHandoff, HandoffVerifier};
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
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    genesis::Genesis,
    Vec<[u8; 32]>,
    Vec<CommitteeHandoff>,
    CertifiedStateProof,
    CertifiedReceiptProof,
) {
    let (mut genesis, keys) = support::fixture();
    genesis.version = 2;
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut handoffs = vec![];
    for _ in 0..2 {
        let handoff = support::handoff(&genesis, &trusted);
        trusted.apply(&handoff).unwrap();
        handoffs.push(handoff);
    }
    let db = genesis.materialize().unwrap();
    let snapshot = db.snapshot().unwrap();
    let receipt = ExecutionReceipt {
        transaction: Hash256([22; 32]),
        succeeded: true,
        resources: Resources::ZERO,
        output_root: Hash256([23; 32]),
    };
    let header = BlockHeader {
        height: trusted.current().height(),
        parent: trusted.parent(),
        committee_root: trusted.current().context().unwrap().root(),
        capacity: genesis.capacity,
        transactions_root: Hash256([24; 32]),
        state_root: db.root(),
        receipts_root: receipt.commitment(),
    };
    let certificate = support::sign(trusted.current(), &header).encode().unwrap();
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
fn rotating_proof_sidecars_work_offline_and_reject_truncation_or_foreign_anchors() {
    let directory =
        Fixture(std::env::temp_dir().join(format!("astrolune-cli-handoff-{}", std::process::id())));
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
    let output = run(&["devnet", "vrf-devnet", "4", "--vrf", "--observer"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let provisioned = genesis::Genesis::decode(
        &std::fs::read(directory.0.join("vrf-devnet/genesis.bin")).unwrap(),
    )
    .unwrap();
    assert_eq!(provisioned.version, 2);
    assert_eq!(provisioned.committee_size, 3);
}

#[test]
fn evidence_cli_uses_historical_rotating_membership_and_preserves_offline_authority() {
    use consensus::{DoubleVoteEvidence, Vote, VotePhase};
    use crypto::blake2s::{ed25519_public_key, ed25519_sign};
    let directory = Fixture(std::env::temp_dir().join(format!(
        "astrolune-cli-evidence-handoff-{}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let (genesis, keys, handoffs, _, _) = fixtures();
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    for handoff in &handoffs {
        trusted.apply(handoff).unwrap();
    }
    let context = trusted.current().context().unwrap();
    std::fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(directory.0.join("keys"), keys.concat()).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&directory.0)
            .args(args)
            .output()
            .unwrap()
    };
    for active in [true, false] {
        let seed = (1..=4)
            .find(|seed| {
                let id =
                    types::ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[*seed; 32])).0);
                context.voting_power(id).is_some() == active
            })
            .unwrap();
        for (file, block) in [("a", None), ("b", Some(Hash256([8; 32])))] {
            let mut vote = Vote {
                chain_id: genesis.chain_id,
                committee_root: context.root(),
                height: 3,
                round: 0,
                phase: VotePhase::Prevote,
                block,
                voter: types::ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0),
                signature: [0; 64],
            };
            vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
            std::fs::write(directory.0.join(file), vote.encode()).unwrap();
        }
        let (address, worker) = serve(
            handoffs
                .iter()
                .map(|handoff| handoff.to_bytes().unwrap())
                .collect(),
        );
        let destination = if active { "evidence" } else { "forged" };
        let output = run(&[
            "evidence-create",
            "genesis",
            "keys",
            "a",
            "b",
            destination,
            &address,
        ]);
        assert_eq!(
            output.status.success(),
            active,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        worker.join().unwrap();
        if !active {
            assert!(!directory.0.join(destination).exists());
            assert!(!directory.0.join("forged.handoffs").exists());
            continue;
        }
        let bytes = std::fs::read(directory.0.join(destination)).unwrap();
        DoubleVoteEvidence::decode(&bytes)
            .unwrap()
            .verify(&context)
            .unwrap();
        assert!(
            run(&["evidence-verify", "genesis", "keys", destination])
                .status
                .success()
        );
        std::fs::remove_file(directory.0.join("evidence.handoffs")).unwrap();
        assert!(
            !run(&["evidence-verify", "genesis", "keys", destination])
                .status
                .success()
        );
    }
}
