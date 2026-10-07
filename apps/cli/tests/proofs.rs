// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Saved proof verification through the real CLI, including untrusted input rejection.

use codec::CanonicalEncode;
use crypto::blake2s::ed25519_public_key;
use state::StateDatabase;
use std::{fmt::Write as _, process::Command};
use types::{Resources, ValidatorId};

#[test]
fn offline_proof_verification_binds_trusted_genesis_key_and_height() {
    let path =
        std::env::temp_dir().join(format!("astrolune-cli-state-proof-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let public = ed25519_public_key(&[1; 32]);
    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 42,
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        capacity: Resources {
            compute: 100,
            memory: 100,
            io: 100,
            bandwidth: 1000,
        },
        validators: vec![genesis::GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&public).0),
            weight: 1,
        }],
        allocations: vec![],
    };
    std::fs::write(path.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(path.join("validators"), public).unwrap();
    let db = genesis.materialize().unwrap();
    let proof = rpc::CertifiedStateProof::create(
        db.snapshot().unwrap().as_ref(),
        &genesis::genesis_key(),
        None,
    )
    .unwrap();
    let bytes = proof.to_bytes().unwrap();
    std::fs::write(path.join("proof"), &bytes).unwrap();

    let mut key = String::new();
    for byte in genesis::genesis_key().0 {
        write!(key, "{byte:02x}").unwrap();
    }
    let run = |key: &str, height: &str| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&path)
            .args([
                "verify-state-proof",
                "genesis",
                "validators",
                key,
                height,
                "proof",
            ])
            .output()
            .unwrap()
    };
    let verified = run(&key, "0");
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("verified_height: 0"));
    assert!(!run(&key, "1").status.success());
    assert!(!run("deadbeef", "0").status.success());
    assert!(!run(&"a".repeat(513), "0").status.success());
    let mut corrupted = bytes;
    corrupted[9] ^= 1;
    std::fs::write(path.join("proof"), corrupted).unwrap();
    assert!(!run(&key, "0").status.success());
    std::fs::remove_dir_all(path).unwrap();
}
