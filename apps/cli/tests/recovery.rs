// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Operator recovery authenticates history, excludes authority and never overwrites destinations.

use codec::CanonicalEncode;
use consensus::{CertificateSignature, FinalityCertificate, Vote, VotePhase};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use node::network::StaticNetwork;
use state::StateDatabase;
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
use storage::{ChainStorage, CommitBatch, NodeStorage};
use types::{Block, BlockHeader, Hash256, Resources, ValidatorId};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (Fixture, genesis::Genesis, Vec<[u8; 32]>) {
    let directory = Fixture(
        std::env::temp_dir().join(format!("astrolune-cli-recovery-{}", std::process::id())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let key = ed25519_public_key(&[1; 32]);
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
            id: ValidatorId(crypto::blake2s_hash(&key).0),
            weight: 1,
        }],
        allocations: vec![],
    };
    std::fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(directory.0.join("validators"), key).unwrap();
    (directory, genesis, vec![key])
}
fn install(
    path: &Path,
    genesis: &genesis::Genesis,
    keys: &[[u8; 32]],
    archive: bool,
    forged: bool,
) -> ChainStorage {
    std::fs::create_dir(path).unwrap();
    if archive {
        storage::FileBackedStorage::open(path.join("chain.bin"))
            .unwrap()
            .initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap(),
            )
            .unwrap();
    }
    let mut storage = ChainStorage::open(path.join("chain.bin")).unwrap();
    if storage.checkpoint().is_none() {
        storage
            .initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap(),
            )
            .unwrap();
    }
    let context = StaticNetwork::new(genesis.clone(), keys.to_vec())
        .unwrap()
        .committee(1)
        .unwrap();
    let block = Block {
        header: BlockHeader {
            height: 1,
            parent: genesis.commitment().unwrap(),
            state_root: storage.state().root(),
            transactions_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: context.root(),
            capacity: genesis.capacity,
        },
        transactions: vec![],
    };
    let vote = Vote {
        chain_id: 42,
        committee_root: context.root(),
        height: 1,
        round: 0,
        phase: VotePhase::Precommit,
        block: Some(block.header.compute_hash()),
        voter: genesis.validators[0].id,
        signature: [0; 64],
    };
    let signature = if forged {
        [0; 64]
    } else {
        ed25519_sign(&[1; 32], &vote.signing_hash().0)
    };
    let certificate = FinalityCertificate {
        chain_id: 42,
        height: 1,
        round: 0,
        committee_root: context.root(),
        block: block.header.compute_hash(),
        signatures: vec![CertificateSignature {
            voter: vote.voter,
            signature,
        }],
    }
    .encode()
    .unwrap();
    let effects = storage::BlockEffects {
        committee: None,
        potb: None,
        receipts: vec![],
        genesis: state::StateValueProof::create(
            storage.state().snapshot().unwrap().as_ref(),
            &genesis::genesis_key(),
        )
        .unwrap(),
    };
    storage
        .commit(&CommitBatch {
            block,
            finality_certificate: certificate,
            state_diffs: vec![],
            effects: Some(effects),
        })
        .unwrap();
    storage
}
fn run(fixture: &Fixture, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cli"))
        .current_dir(&fixture.0)
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn recovery_exports_both_backends_as_observers_and_rejects_forgery_lock_rollback_or_overwrite() {
    let (fixture, genesis, keys) = fixture();
    for (source, target, archive) in [
        ("log", "log-copy", false),
        ("archive", "archive-copy", true),
    ] {
        check_export(&fixture, &genesis, &keys, source, target, archive);
    }
    drop(install(
        &fixture.0.join("forged"),
        &genesis,
        &keys,
        false,
        true,
    ));
    assert!(
        !run(
            &fixture,
            &[
                "export-history",
                "genesis",
                "validators",
                "forged",
                "1",
                "forged-copy"
            ]
        )
        .status
        .success()
    );
    assert!(!fixture.0.join("forged-copy").exists());
    assert!(
        !run(
            &fixture,
            &["verify-history", "genesis", "validators", "missing", "0"]
        )
        .status
        .success()
    );
    assert!(!fixture.0.join("missing").exists());
    check_retained(&fixture);
}

fn check_retained(fixture: &Fixture) {
    for source in ["log", "archive"] {
        let output = format!("{source}-retained");
        let exported = run(
            fixture,
            &[
                "export-retained",
                "genesis",
                "validators",
                source,
                "1",
                "0",
                &output,
            ],
        );
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        let stdout = String::from_utf8(exported.stdout).unwrap();
        let pin = stdout
            .lines()
            .find_map(|line| line.strip_prefix("checkpoint_id: "))
            .unwrap();
        let descriptor = format!("{output}/checkpoint.bin");
        assert!(
            run(
                fixture,
                &[
                    "verify-retained",
                    "genesis",
                    "validators",
                    &output,
                    "1",
                    &descriptor,
                    pin
                ]
            )
            .status
            .success()
        );
        assert!(
            !run(
                fixture,
                &[
                    "verify-retained",
                    "genesis",
                    "validators",
                    &output,
                    "2",
                    &descriptor,
                    pin
                ]
            )
            .status
            .success()
        );
        assert!(
            !run(
                fixture,
                &[
                    "verify-retained",
                    "genesis",
                    "validators",
                    &output,
                    "1",
                    &descriptor,
                    &Hash256([9; 32]).to_string()
                ]
            )
            .status
            .success()
        );
        assert!(
            !run(
                fixture,
                &["verify-history", "genesis", "validators", &output, "1"]
            )
            .status
            .success()
        );
        assert_eq!(
            ChainStorage::open(fixture.0.join(&output).join("chain.bin"))
                .unwrap()
                .block_count(),
            0
        );
        assert!(fixture.0.join(&output).join("observer.mode").is_file());
        assert!(!fixture.0.join(&output).join("signing.journal").exists());
    }
}

fn check_export(
    fixture: &Fixture,
    genesis: &genesis::Genesis,
    keys: &[[u8; 32]],
    source: &str,
    target: &str,
    archive: bool,
) {
    let store = install(&fixture.0.join(source), genesis, keys, archive, false);
    let expected = *store.checkpoint().unwrap();
    let held = run(
        fixture,
        &[
            "export-history",
            "genesis",
            "validators",
            source,
            "1",
            target,
        ],
    );
    assert!(!held.status.success());
    assert!(!fixture.0.join(target).exists());
    drop(store);
    for name in [
        "validator.seed",
        "signing.journal",
        "consensus-cache.bin",
        "tls.key",
    ] {
        std::fs::write(fixture.0.join(source).join(name), b"private fixture").unwrap();
    }
    assert!(
        run(
            fixture,
            &["verify-history", "genesis", "validators", source, "1"]
        )
        .status
        .success()
    );
    assert!(
        !run(
            fixture,
            &["verify-history", "genesis", "validators", source, "2"]
        )
        .status
        .success()
    );
    let exported = run(
        fixture,
        &[
            "export-history",
            "genesis",
            "validators",
            source,
            "1",
            target,
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(
        !run(
            fixture,
            &[
                "export-history",
                "genesis",
                "validators",
                source,
                "1",
                target
            ]
        )
        .status
        .success()
    );
    let copy = node::observer::ObserverNode::open(
        StaticNetwork::new(genesis.clone(), keys.to_vec()).unwrap(),
        &fixture.0.join(target),
    )
    .unwrap();
    assert_eq!(copy.storage().checkpoint(), Some(&expected));
    assert_eq!(
        copy.storage()
            .read_receipts(1)
            .unwrap()
            .unwrap()
            .header
            .state_root,
        expected.state_root
    );
    for name in [
        "validator.seed",
        "signing.journal",
        "consensus-cache.bin",
        "tls.key",
    ] {
        assert!(!fixture.0.join(target).join(name).exists());
    }
    assert_eq!(
        std::fs::read(fixture.0.join(target).join("genesis.bin")).unwrap(),
        genesis.to_bytes()
    );
}
