// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline proof tooling is authenticated and never overwrites an existing file.

use codec::CanonicalDecode;
use consensus::{AuthenticatedCommittee, Committee, CommitteeMember, PotbWeight, Vote, VotePhase};
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use std::process::Command;
use types::{Hash256, ValidatorId};

#[test]
fn cli_creates_verifies_and_rejects_tampered_evidence() {
    let directory =
        std::env::temp_dir().join(format!("astrolune-cli-evidence-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let command = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&directory)
            .args(args)
            .output()
            .unwrap()
    };
    let result = command(&["devnet", "network", "4"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let genesis =
        genesis::Genesis::decode(&std::fs::read(directory.join("network/genesis.bin")).unwrap())
            .unwrap();
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    let context = AuthenticatedCommittee::new(
        42,
        &Committee {
            height: 1,
            members: genesis
                .validators
                .iter()
                .map(|member| CommitteeMember {
                    id: member.id,
                    power: PotbWeight(member.weight),
                })
                .collect(),
        },
        &keys,
    )
    .unwrap();
    for (file, block) in [("a.bin", None), ("b.bin", Some(Hash256([1; 32])))] {
        let mut vote = Vote {
            chain_id: 42,
            committee_root: context.root(),
            height: 1,
            round: 0,
            phase: VotePhase::Prevote,
            block,
            voter: ValidatorId(blake2s(&keys[0]).0),
            signature: [0; 64],
        };
        vote.signature = ed25519_sign(&[1; 32], &vote.signing_hash().0);
        std::fs::write(directory.join(file), vote.encode()).unwrap();
    }
    let create = [
        "evidence-create",
        "network/genesis.bin",
        "network/validators.bin",
        "a.bin",
        "b.bin",
        "proof.bin",
    ];
    let verified = [
        "evidence-verify",
        "network/genesis.bin",
        "network/validators.bin",
        "proof.bin",
    ];
    assert!(command(&create).status.success());
    assert!(command(&verified).status.success());
    assert!(!command(&create).status.success());
    let mut bytes = std::fs::read(directory.join("proof.bin")).unwrap();
    assert_eq!(bytes.len(), 380);
    bytes[379] ^= 1;
    std::fs::write(directory.join("proof.bin"), bytes).unwrap();
    assert!(!command(&verified).status.success());
    std::fs::remove_dir_all(directory).unwrap();
}
