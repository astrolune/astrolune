// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independently signed DNS proofs, stale/foreign record rejection and binary tooling.
//!
//! The two tests that spawn the `dns` binary take `testkit::fork_lock`
//! exclusively. This binary holds no operating-system file lock of its own, so
//! the guard corrects no failure observed here; it keeps the spawning side of
//! that module's contract uniform across the workspace, so a later
//! file-backed test added to this binary is not silently exposed to the
//! fork-window race described there.

use codec::CanonicalEncode;
use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, FinalityCertificate,
    PotbWeight, Vote, VotePhase,
};
use contract_sdk::registry::{self, RegistryAction, RegistryCall, RegistryRecord};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use dns::certified::RegistryTrust;
use rpc::CertifiedStateProof;
use state::{StateDatabase, StateDiff};
use types::{Address, BlockHeader, Hash256, Resources, ValidatorId};

fn fixture() -> (RegistryTrust, CertifiedStateProof, CertifiedStateProof) {
    let key = ed25519_public_key(&[1; 32]);
    let id = ValidatorId(crypto::blake2s_hash(&key).0);

    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 42,
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 2,
        capacity: Resources {
            compute: 1_000_000,
            memory: 1_000_000,
            io: 1_000_000,
            bandwidth: 1_000_000,
        },
        validators: vec![genesis::GenesisValidator { id, weight: 1 }],
        allocations: vec![],
    };

    let code = wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"call\") (result i32) i32.const 0))").unwrap();
    let trust = RegistryTrust {
        genesis,
        validators: vec![key],
        address: Address([42; 32]),
        code_hash: runtime::wasm_code_hash(&code),
    };

    let mut db = trust.genesis.materialize().unwrap();
    let code_key = transaction::contract_code_key(trust.address);
    let name_key = trust.state_key("alice").unwrap();

    let mut diff = StateDiff::new();
    diff.put(code_key.clone(), code);

    let mut record = [0; registry::MAX_LEASE];
    let call = RegistryCall {
        name: b"alice",
        action: RegistryAction::Register(
            10,
            RegistryRecord {
                kind: 0,
                value: &[9; 32],
            },
        ),
    };
    let size = registry::transition(call, None, [2; 32], 1, &mut record)
        .unwrap()
        .unwrap();
    diff.put(name_key.clone(), record[..size].to_vec());

    db.commit(db.root(), &[diff]).unwrap();
    let snapshot = db.snapshot().unwrap();

    let context = AuthenticatedCommittee::new(
        42,
        &Committee {
            height: 2,
            members: vec![CommitteeMember {
                id,
                power: PotbWeight(1),
            }],
        },
        &[key],
    )
    .unwrap();

    let header = BlockHeader {
        height: 2,
        parent: Hash256::ZERO,
        transactions_root: Hash256::ZERO,
        receipts_root: Hash256::ZERO,
        state_root: db.root(),
        committee_root: context.root(),
        capacity: trust.genesis.capacity,
    };

    let vote = Vote {
        chain_id: 42,
        committee_root: context.root(),
        height: 2,
        round: 0,
        phase: VotePhase::Precommit,
        block: Some(header.compute_hash()),
        voter: id,
        signature: [0; 64],
    };

    let certificate = FinalityCertificate {
        chain_id: 42,
        height: 2,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures: vec![CertificateSignature {
            voter: id,
            signature: ed25519_sign(&[1; 32], &vote.signing_hash().0),
        }],
    }
    .encode()
    .unwrap();

    let code = CertifiedStateProof::create(
        snapshot.as_ref(),
        &code_key,
        Some((header, certificate.clone())),
    )
    .unwrap();
    let value =
        CertifiedStateProof::create(snapshot.as_ref(), &name_key, Some((header, certificate)))
            .unwrap();

    (trust, code, value)
}

#[test]
fn resolver_authenticates_code_ownership_exact_name_and_freshness() {
    let (mut trust, code, value) = fixture();

    let resolved = trust.verify(" Alice ", 2, &code, &value).unwrap();
    assert_eq!(resolved.name, "alice");
    assert_eq!(resolved.lease.unwrap().owner, Address([2; 32]));

    assert_eq!(trust.verify("a1ice", 2, &code, &value).unwrap().lease, None);
    assert!(trust.verify("alice", 3, &code, &value).is_err());
    assert!(trust.verify("bob", 2, &code, &value).is_err());
    assert!(trust.verify("alice", 2, &value, &code).is_err());

    let mut altered = value.clone();
    altered.root = Hash256::ZERO;
    assert!(trust.verify("alice", 2, &code, &altered).is_err());

    trust.code_hash.0[0] ^= 1;
    assert!(trust.verify("alice", 2, &code, &value).is_err());
}

#[test]
fn command_prepares_canonical_calls_and_refuses_overwrite() {
    let _fork_lock = testkit::fork_lock::spawning_child();
    let path = std::env::temp_dir().join(format!("astrolune-dns-prepare-{}", std::process::id()));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dns"))
        .args([
            "prepare",
            "register",
            "Alice",
            "100",
            "service",
            "https://internal",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let input = std::fs::read(path.join("input.bin")).unwrap();
    let call = RegistryCall::decode(&input).unwrap();
    assert_eq!(call.name, b"alice");
    assert_eq!(
        std::fs::read_to_string(path.join("keys.txt")).unwrap(),
        "646e732f76312f616c696365\n"
    );

    let failure = std::process::Command::new(env!("CARGO_BIN_EXE_dns"))
        .args(["prepare", "release", "alice"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!failure.status.success());
    assert_eq!(std::fs::read(path.join("input.bin")).unwrap(), input);

    std::fs::remove_dir_all(path).unwrap();
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn resolver_process_serves_verified_results_and_rejects_mismatched_peer_proofs() {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    let _fork_lock = testkit::fork_lock::spawning_child();

    let (trust, code, value) = fixture();
    let path = std::env::temp_dir().join(format!("astrolune-dns-server-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("genesis"), trust.genesis.to_bytes()).unwrap();
    std::fs::write(path.join("validators"), trust.validators.concat()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc_address = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();

    let mock = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);

        for proof in [code.clone(), value.clone(), code, value] {
            let mut stream = loop {
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }

                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            };

            // Windows accepts inherit the nonblocking listener's mode, which the
            // timeout below does not clear. Reads and writes here are blocking.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let length = u32::from_le_bytes(length) as usize;
            assert!(length < 4096);
            stream.read_exact(&mut vec![0; length]).unwrap();

            let mut hex = String::new();
            for byte in proof.to_bytes().unwrap() {
                use std::fmt::Write as _;
                write!(hex, "{byte:02x}").unwrap();
            }
            let response = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{hex}\"}}");
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });

    let mut server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_dns"))
            .arg("serve")
            .arg(path.join("genesis"))
            .arg(path.join("validators"))
            .args([
                trust.address.to_string(),
                trust.code_hash.to_string(),
                "127.0.0.1:0".into(),
                "2".into(),
                rpc_address,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let stdout = server.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let _ = send.send(line);
    });

    let line = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    let address = line.trim().strip_prefix("listening: ").unwrap();

    for (name, expected) in [("ALICE\n", "\"owner\""), ("bob\n", "\"error\"")] {
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(name.as_bytes()).unwrap();

        let mut answer = String::new();
        BufReader::new(client).read_line(&mut answer).unwrap();
        assert!(answer.contains(expected), "{answer}");
    }

    drop(server);
    mock.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

fn sign_rotating_header(
    current: &consensus::rotation::CommitteeState,
    header: &BlockHeader,
) -> FinalityCertificate {
    let context = current.context().unwrap();
    let voter = ValidatorId(crypto::blake2s_hash(&current.roster()[0].public_key).0);

    let vote = Vote {
        chain_id: current.chain_id(),
        committee_root: context.root(),
        height: header.height,
        round: 0,
        phase: VotePhase::Precommit,
        block: Some(header.compute_hash()),
        voter,
        signature: [0; 64],
    };

    FinalityCertificate {
        chain_id: current.chain_id(),
        height: header.height,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures: vec![CertificateSignature {
            voter,
            signature: ed25519_sign(&[1; 32], &vote.signing_hash().0),
        }],
    }
}

fn rotating_fixture() -> (
    RegistryTrust,
    CertifiedStateProof,
    CertifiedStateProof,
    consensus::rotation::CommitteeHandoff,
) {
    use consensus::rotation::{
        CommitteeHandoff, HandoffVerifier, VrfBatch, VrfContribution, committee_state_key,
    };

    let (mut trust, code, value) = fixture();
    let code_key = transaction::contract_code_key(trust.address);
    let name_key = trust.state_key("alice").unwrap();

    let mut diff = StateDiff::new();
    diff.put(
        code_key.clone(),
        code.verify(&trust.genesis, &trust.validators, &code_key, 0)
            .unwrap()
            .unwrap()
            .to_vec(),
    );
    diff.put(
        name_key.clone(),
        value
            .verify(&trust.genesis, &trust.validators, &name_key, 0)
            .unwrap()
            .unwrap()
            .to_vec(),
    );

    trust.genesis.version = 2;
    let mut trusted = HandoffVerifier::new(&trust.genesis, &trust.validators).unwrap();

    let contribution = VrfContribution {
        validator: trust.genesis.validators[0].id,
        committee: crypto::prove_vrf(
            &[1; 32],
            trusted.current().input(crypto::VrfRole::Committee).unwrap(),
        )
        .unwrap(),
        producer: crypto::prove_vrf(
            &[1; 32],
            trusted.current().input(crypto::VrfRole::Producer).unwrap(),
        )
        .unwrap(),
    };
    let contributions = VrfBatch::new(vec![contribution]).unwrap();
    let next = trusted.current().transition(&contributions).unwrap();
    diff.put(committee_state_key(), next.to_bytes().unwrap());

    let mut db = trust.genesis.materialize().unwrap();
    db.commit(db.root(), &[diff]).unwrap();
    let snapshot = db.snapshot().unwrap();

    let mut header = BlockHeader {
        height: 1,
        parent: trusted.parent(),
        transactions_root: Hash256::ZERO,
        receipts_root: Hash256::ZERO,
        state_root: db.root(),
        committee_root: trusted.current().context().unwrap().root(),
        capacity: trust.genesis.capacity,
    };

    let handoff = CommitteeHandoff {
        header,
        certificate: sign_rotating_header(trusted.current(), &header),
        contributions,
        next_state: state::StateValueProof::create(snapshot.as_ref(), &committee_state_key())
            .unwrap(),
    };

    trusted.apply(&handoff).unwrap();

    header.height = 2;
    header.parent = trusted.parent();
    header.committee_root = trusted.current().context().unwrap().root();
    let certificate = sign_rotating_header(trusted.current(), &header)
        .encode()
        .unwrap();

    let code = CertifiedStateProof::create(
        snapshot.as_ref(),
        &code_key,
        Some((header, certificate.clone())),
    )
    .unwrap();
    let value =
        CertifiedStateProof::create(snapshot.as_ref(), &name_key, Some((header, certificate)))
            .unwrap();

    (trust, code, value, handoff)
}

#[test]
fn network_resolver_streams_rotation_then_reuses_authority_and_rejects_rollback() {
    use std::{
        fmt::Write as _,
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    let (trust, code, value, handoff) = rotating_fixture();
    assert!(trust.verify("alice", 0, &code, &value).is_err());

    let mut stale = code.clone();
    stale.header.as_mut().unwrap().height = 1;

    let replies = vec![
        code.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
        handoff.to_bytes().unwrap(),
        code.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
        stale.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
    ];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        rpc::TcpRpcClient::new(listener.local_addr().unwrap(), Duration::from_secs(3)).unwrap();

    let task = std::thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let size = u32::from_le_bytes(prefix) as usize;
            assert!(size < 1024);
            stream.read_exact(&mut vec![0; size]).unwrap();

            let mut hex = String::new();
            for byte in reply {
                write!(hex, "{byte:02x}").unwrap();
            }
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hex}"}}"#);
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });

    let mut resolver = dns::certified::CertifiedResolver::new(trust, client, 2);

    let first = resolver.resolve("alice").unwrap();
    assert_eq!(first.lease.as_ref().unwrap().owner, Address([2; 32]));
    assert_eq!(resolver.resolve("alice").unwrap(), first);
    assert!(resolver.resolve("alice").is_err());

    task.join().unwrap();
}

fn potb_fixture() -> (
    RegistryTrust,
    CertifiedStateProof,
    CertifiedStateProof,
    consensus::potb_transition::PotbHandoff,
    consensus::potb_transition::PotbConfiguration,
) {
    use consensus::{
        potb_transition::{
            PotbBatch, PotbConfiguration, PotbHandoff, PotbVerifier, potb_state_key,
        },
        rotation::{VrfBatch, VrfContribution},
    };

    let (mut trust, code, value) = fixture();
    let code_key = transaction::contract_code_key(trust.address);
    let name_key = trust.state_key("alice").unwrap();

    let mut diff = StateDiff::new();
    diff.put(
        code_key.clone(),
        code.verify(&trust.genesis, &trust.validators, &code_key, 0)
            .unwrap()
            .unwrap()
            .to_vec(),
    );
    diff.put(
        name_key.clone(),
        value
            .verify(&trust.genesis, &trust.validators, &name_key, 0)
            .unwrap()
            .unwrap()
            .to_vec(),
    );

    trust.genesis.version = 2;
    let profile = PotbConfiguration::new(
        trust.genesis.clone(),
        consensus::potb::PotbPolicy {
            epoch_blocks: 1,
            initial_weight: 1,
            age_increment: 1,
            maximum_weight: 10,
        },
    )
    .unwrap();

    let mut trusted = PotbVerifier::new(&profile, &trust.validators).unwrap();

    let contribution = VrfContribution {
        validator: trust.genesis.validators[0].id,
        committee: crypto::prove_vrf(
            &[1; 32],
            trusted
                .current()
                .committee()
                .input(crypto::VrfRole::Committee)
                .unwrap(),
        )
        .unwrap(),
        producer: crypto::prove_vrf(
            &[1; 32],
            trusted
                .current()
                .committee()
                .input(crypto::VrfRole::Producer)
                .unwrap(),
        )
        .unwrap(),
    };
    let contributions = VrfBatch::new(vec![contribution]).unwrap();
    let batch = PotbBatch::new(contributions, vec![], vec![]).unwrap();
    let next = trusted.current().stage(trusted.parent(), &batch).unwrap();
    diff.put(potb_state_key(), next.to_bytes().unwrap());

    let mut db = profile.materialize(&trust.validators).unwrap();
    db.commit(db.root(), &[diff]).unwrap();
    let snapshot = db.snapshot().unwrap();

    let mut header = BlockHeader {
        height: 1,
        parent: trusted.parent(),
        transactions_root: Hash256::ZERO,
        receipts_root: Hash256::ZERO,
        state_root: db.root(),
        committee_root: trusted.current().committee().context().unwrap().root(),
        capacity: trust.genesis.capacity,
    };

    let handoff = PotbHandoff {
        header,
        certificate: sign_rotating_header(trusted.current().committee(), &header),
        batch,
        next_state: state::StateValueProof::create(snapshot.as_ref(), &potb_state_key()).unwrap(),
    };

    trusted.apply(&handoff).unwrap();

    header.height = 2;
    header.parent = trusted.parent();
    header.committee_root = trusted.current().committee().context().unwrap().root();
    let certificate = sign_rotating_header(trusted.current().committee(), &header)
        .encode()
        .unwrap();

    let code = CertifiedStateProof::create(
        snapshot.as_ref(),
        &code_key,
        Some((header, certificate.clone())),
    )
    .unwrap();
    let value =
        CertifiedStateProof::create(snapshot.as_ref(), &name_key, Some((header, certificate)))
            .unwrap();

    (trust, code, value, handoff, profile)
}

#[test]
fn network_resolver_streams_potb_then_reuses_authority_and_rejects_rollback() {
    use std::{
        fmt::Write as _,
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    let (trust, code, value, handoff, profile) = potb_fixture();
    assert!(trust.verify("alice", 0, &code, &value).is_err());

    let mut stale = code.clone();
    stale.header.as_mut().unwrap().height = 1;

    let replies = vec![
        code.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
        handoff.to_bytes().unwrap(),
        code.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
        stale.to_bytes().unwrap(),
        value.to_bytes().unwrap(),
    ];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        rpc::TcpRpcClient::new(listener.local_addr().unwrap(), Duration::from_secs(3)).unwrap();

    let task = std::thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let size = u32::from_le_bytes(prefix) as usize;
            assert!(size < 1024);
            stream.read_exact(&mut vec![0; size]).unwrap();

            let mut hex = String::new();
            for byte in reply {
                write!(hex, "{byte:02x}").unwrap();
            }
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hex}"}}"#);
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });

    let mut resolver =
        dns::certified::CertifiedResolver::with_potb(trust, client, 2, &profile).unwrap();

    let first = resolver.resolve("alice").unwrap();
    assert_eq!(first.lease.as_ref().unwrap().owner, Address([2; 32]));
    assert_eq!(resolver.resolve("alice").unwrap(), first);
    assert!(resolver.resolve("alice").is_err());

    task.join().unwrap();
}
