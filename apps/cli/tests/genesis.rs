// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Operator verification rejects malformed input and reports reproducible roots.

use std::process::Command;

use codec::CanonicalEncode;
use genesis::{Allocation, Genesis, GenesisValidator};
use types::{Address, Resources, ValidatorId};

#[test]
fn verify_genesis_file_and_reject_invalid_arguments_and_bytes() {
    let genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity: Resources {
            compute: 11,
            memory: 22,
            io: 33,
            bandwidth: 44,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: (1 << 80) + 3,
        }],
        allocations: vec![Allocation {
            address: Address([2; 32]),
            amount: 500,
        }],
    };
    let directory =
        std::env::temp_dir().join(format!("astrolune-cli-genesis-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("genesis.bin");
    std::fs::write(&path, genesis.to_bytes()).unwrap();
    let run = || Command::new(env!("CARGO_BIN_EXE_cli"));
    let output = run().arg("genesis").arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("98ddf60aafa73a4717c1b94fbc4df02f1c2ff9ba909f236ee3924c70895c0bf6"));
    assert!(stdout.contains("0b818b0904e6b79282d518498a87120b61e622fd672fc9e78853d8190c4770ef"));
    assert_eq!(std::fs::read(&path).unwrap(), genesis.to_bytes());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    assert!(!run().arg("genesis").output().unwrap().status.success());
    assert!(
        !run()
            .arg("genesis")
            .arg(&path)
            .arg("extra")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !run()
            .arg("genesis")
            .arg(directory.join("missing.bin"))
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut bytes = genesis.to_bytes();
    bytes[58..66].copy_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&path, bytes).unwrap();
    let malformed = run().arg("genesis").arg(&path).output().unwrap();
    assert!(!malformed.status.success());
    assert_eq!(malformed.stdout, [] as [u8; 0]);
    // Only the unique directory created by this test is removed.
    std::fs::remove_dir_all(directory).unwrap();
}
