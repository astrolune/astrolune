// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI finality waiting, independent receipt checks and ambiguous timeout reporting.

use codec::CanonicalEncode;
use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, FinalityCertificate,
    PotbWeight, Vote, VotePhase,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use state::StateDatabase;
use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::Command,
    time::Duration,
};
use types::{BlockHeader, ExecutionReceipt, Hash256, Resources, ValidatorId};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (Fixture, Hash256, rpc::CertifiedReceiptProof) {
    let directory =
        Fixture(std::env::temp_dir().join(format!("astrolune-cli-receipt-{}", std::process::id())));
    std::fs::create_dir(&directory.0).unwrap();
    let public = ed25519_public_key(&[1; 32]);
    let validator = ValidatorId(crypto::blake2s_hash(&public).0);
    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 42,
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        capacity: Resources {
            compute: 1000,
            memory: 1000,
            io: 1000,
            bandwidth: 1000,
        },
        validators: vec![genesis::GenesisValidator {
            id: validator,
            weight: 1,
        }],
        allocations: vec![],
    };
    std::fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(directory.0.join("validators"), public).unwrap();
    let db = genesis.materialize().unwrap();
    let context = AuthenticatedCommittee::new(
        42,
        &Committee {
            height: 1,
            members: vec![CommitteeMember {
                id: validator,
                power: PotbWeight(1),
            }],
        },
        &[public],
    )
    .unwrap();
    let id = Hash256([44; 32]);
    let receipt = ExecutionReceipt {
        transaction: id,
        succeeded: true,
        resources: Resources::ZERO,
        output_root: Hash256([7; 32]),
    };
    let header = BlockHeader {
        height: 1,
        parent: genesis.commitment().unwrap(),
        state_root: db.root(),
        transactions_root: id,
        receipts_root: receipt.commitment(),
        committee_root: context.root(),
        capacity: genesis.capacity,
    };
    let vote = Vote {
        chain_id: 42,
        committee_root: context.root(),
        height: 1,
        round: 0,
        phase: VotePhase::Precommit,
        block: Some(header.compute_hash()),
        voter: validator,
        signature: [0; 64],
    };
    let certificate = FinalityCertificate {
        chain_id: 42,
        height: 1,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures: vec![CertificateSignature {
            voter: validator,
            signature: ed25519_sign(&[1; 32], &vote.signing_hash().0),
        }],
    }
    .encode()
    .unwrap();
    let proof = rpc::CertifiedReceiptProof(storage::StoredReceipts {
        header,
        certificate,
        effects: storage::BlockEffects {
            committee: None,
            potb: None,
            receipts: vec![receipt],
            genesis: state::StateValueProof::create(
                db.snapshot().unwrap().as_ref(),
                &genesis::genesis_key(),
            )
            .unwrap(),
        },
    });
    (directory, id, proof)
}

fn server(
    responses: Vec<Option<Vec<u8>>>,
    delay: Duration,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let thread = std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let size = u32::from_le_bytes(size) as usize;
            assert!(size < 4096);
            let mut request = vec![0; size];
            stream.read_exact(&mut request).unwrap();
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .contains("\"method\":\"receipt\"")
            );
            let result = response.map_or("null".into(), |bytes| {
                let mut text = String::from("\"");
                for byte in bytes {
                    write!(text, "{byte:02x}").unwrap();
                }
                text.push('"');
                text
            });
            std::thread::sleep(delay);
            let response = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{result}}}");
            let _ = stream.write_all(&u32::try_from(response.len()).unwrap().to_le_bytes());
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (address, thread)
}

#[test]
fn wait_saves_only_authenticated_finality_and_timeout_never_resubmits() {
    let (fixture, id, proof) = fixture();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&fixture.0)
            .args(args)
            .output()
            .unwrap()
    };
    let id = id.to_string();
    let (address, worker) = server(
        vec![None, None, Some(proof.to_bytes().unwrap())],
        Duration::ZERO,
    );
    let output = run(&[
        "wait-finality",
        "genesis",
        "validators",
        &id,
        "5",
        "receipt",
        &address,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("finalized_height: 1"));
    let saved = std::fs::read(fixture.0.join("receipt")).unwrap();
    assert_eq!(
        rpc::CertifiedReceiptProof::from_bytes(&saved).unwrap(),
        proof
    );
    assert!(
        run(&[
            "verify-receipt",
            "genesis",
            "validators",
            &id,
            "1",
            "receipt"
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "verify-receipt",
            "genesis",
            "validators",
            &id,
            "2",
            "receipt"
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "wait-finality",
            "genesis",
            "validators",
            &id,
            "5",
            "receipt",
            &address
        ])
        .status
        .success()
    );
    assert_eq!(std::fs::read(fixture.0.join("receipt")).unwrap(), saved);
    let (address, worker) = server(vec![None], Duration::from_millis(1250));
    let output = run(&[
        "wait-finality",
        "genesis",
        "validators",
        &id,
        "1",
        "timed-out",
        &address,
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("timed out"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.0.join("timed-out").exists());
    worker.join().unwrap();
}
