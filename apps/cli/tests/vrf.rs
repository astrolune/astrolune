// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI proof creation, independent verification, and rejection paths.

use codec::CanonicalEncode;
use crypto::blake2s::ed25519_public_key;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
use types::{Hash256, Resources, ValidatorId};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn offline_proofs_are_registered_context_bound_and_never_overwritten() {
    let fixture =
        Fixture(std::env::temp_dir().join(format!("astrolune-vrf-cli-{}", std::process::id())));
    std::fs::create_dir(&fixture.0).unwrap();
    let public = ed25519_public_key(&[1; 32]);
    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 100,
            memory: 100,
            io: 100,
            bandwidth: 1000,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![genesis::GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&public).0),
            weight: 1,
        }],
        allocations: vec![],
    };
    std::fs::write(fixture.0.join("genesis.bin"), genesis.to_bytes()).unwrap();
    std::fs::write(fixture.0.join("validator.seed"), [1; 32]).unwrap();
    let parent = Hash256([3; 32]).to_string();
    let public = Hash256(public).to_string();
    let mut args = [
        "vrf-prove",
        "genesis.bin",
        "validator.seed",
        "1",
        "5",
        &parent,
        "committee",
        "0",
        "proof.bin",
    ];
    let output = fixture.command(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(fixture.0.join("proof.bin")).unwrap();
    assert_eq!(bytes.len(), 120);
    assert!(!fixture.command(&args).status.success());
    assert_eq!(std::fs::read(fixture.0.join("proof.bin")).unwrap(), bytes);
    args[0] = "vrf-verify";
    args[2] = &public;
    assert!(fixture.command(&args).status.success());
    for (index, value) in [(3, "2"), (4, "6"), (6, "producer"), (7, "1")] {
        let mut changed = args;
        changed[index] = value;
        assert!(!fixture.command(&changed).status.success());
    }
    let wrong_key = Hash256(ed25519_public_key(&[2; 32])).to_string();
    args[2] = &wrong_key;
    assert!(!fixture.command(&args).status.success());
    args[2] = &public;
    let mut forged = bytes;
    forged[8] ^= 1;
    std::fs::write(fixture.0.join("proof.bin"), forged).unwrap();
    assert!(!fixture.command(&args).status.success());
}
