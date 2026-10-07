// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Daemon process recovery, startup failure, and command-line conformance.

use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use storage::FileBackedStorage;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "astrolune-daemon-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
        command.arg("--data-dir").arg(&self.0);
        command.args(["--p2p-listen", "127.0.0.1:0", "--rpc-listen", "127.0.0.2:0"]);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn additional_blocks_extend_the_same_archive_after_process_restart() {
    let fixture = Fixture::new();
    let first = fixture.command().args(["--blocks", "3"]).output().unwrap();
    success(&first);
    let path = fixture.0.join("chain.bin");
    let storage = FileBackedStorage::open(&path).unwrap();
    let previous = *storage.checkpoint().unwrap();
    assert_eq!(previous.height, 2);
    drop(storage);
    let second = fixture.command().args(["--blocks", "2"]).output().unwrap();
    success(&second);
    assert!(String::from_utf8_lossy(&second.stdout).contains("next_height: 3"));
    let storage = FileBackedStorage::open(&path).unwrap();
    assert_eq!(storage.checkpoint().unwrap().height, 4);
    assert_eq!(storage.block_count(), 5);
    assert!(storage.get_block(&previous.block).is_some());
    drop(storage);
    let before = fs::read(&path).unwrap();
    success(&fixture.command().args(["--blocks", "0"]).output().unwrap());
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn dry_run_and_invalid_options_have_no_filesystem_effects() {
    let fixture = Fixture::new();
    success(&fixture.command().arg("--dry-run").output().unwrap());
    assert!(!fixture.0.exists());
    let invalid = fixture
        .command()
        .args(["--blocks", "bad"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!fixture.0.exists());
}

#[test]
fn locked_or_corrupt_archive_fails_without_overwriting_it() {
    let fixture = Fixture::new();
    success(&fixture.command().args(["--blocks", "1"]).output().unwrap());
    let path = fixture.0.join("chain.bin");
    let before = fs::read(&path).unwrap();
    let lock = FileBackedStorage::open(&path).unwrap();
    let output = fixture.command().args(["--blocks", "1"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("locked"));
    assert_eq!(before, fs::read(&path).unwrap());
    drop(lock);
    fs::write(&path, b"corrupt archive").unwrap();
    let output = fixture.command().args(["--blocks", "1"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), b"corrupt archive");
}

#[test]
fn listener_failure_prevents_block_production() {
    let fixture = Fixture::new();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--data-dir")
        .arg(&fixture.0)
        .args([
            "--blocks",
            "1",
            "--p2p-listen",
            "127.0.0.1:0",
            "--rpc-listen",
        ])
        .arg(occupied.local_addr().unwrap().to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let storage = FileBackedStorage::open(fixture.0.join("chain.bin")).unwrap();
    assert!(storage.checkpoint().is_none());
}

fn write_genesis(fixture: &Fixture) -> PathBuf {
    use codec::CanonicalEncode;
    fs::create_dir_all(&fixture.0).unwrap();
    let path = fixture.0.join("genesis.bin");
    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 42,
        capacity: types::Resources {
            compute: 10,
            memory: 20,
            io: 30,
            bandwidth: 40,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![genesis::GenesisValidator {
            id: types::ValidatorId([2; 32]),
            weight: 100,
        }],
        allocations: vec![genesis::Allocation {
            address: types::Address([3; 32]),
            amount: 1000,
        }],
    };
    fs::write(&path, genesis.to_bytes()).unwrap();
    path
}

#[test]
fn genesis_process_activation_restart_and_missing_identity() {
    use state::{StateDatabase, read_account};
    let fixture = Fixture::new();
    let input = Fixture::new();
    let genesis = write_genesis(&input);
    let run = |count| {
        fixture
            .command()
            .arg("--genesis")
            .arg(&genesis)
            .args(["--blocks", count])
            .output()
            .unwrap()
    };
    let first = run("0");
    success(&first);
    assert!(String::from_utf8_lossy(&first.stdout).contains("chain_id  : 42"));
    assert!(String::from_utf8_lossy(&first.stdout).contains("next_height: 1"));
    let path = fixture.0.join("chain.bin");
    let before = fs::read(&path).unwrap();
    success(&run("0"));
    assert_eq!(before, fs::read(&path).unwrap());
    let missing = fixture.command().args(["--blocks", "1"]).output().unwrap();
    assert!(!missing.status.success());
    assert_eq!(before, fs::read(&path).unwrap());
    success(&run("2"));
    success(&run("1"));
    let storage = FileBackedStorage::open(&path).unwrap();
    assert_eq!(storage.checkpoint().unwrap().height, 3);
    assert_eq!(storage.block_count(), 3);
    let snapshot = storage.state().snapshot().unwrap();
    assert_eq!(
        read_account(snapshot.as_ref(), types::Address([3; 32])).unwrap(),
        Some(types::AccountState {
            nonce: 0,
            balance: 1000
        })
    );
    drop(storage);
    let before = fs::read(&path).unwrap();
    let mut changed = fs::read(&genesis).unwrap();
    changed[2] = 43;
    fs::write(&genesis, changed).unwrap();
    assert!(!run("1").status.success());
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn genesis_dry_run_and_invalid_input_do_not_create_chain_data() {
    let fixture = Fixture::new();
    let input = Fixture::new();
    let path = write_genesis(&input);
    let dry = fixture
        .command()
        .arg("--genesis")
        .arg(&path)
        .arg("--dry-run")
        .output()
        .unwrap();
    success(&dry);
    assert!(!fixture.0.exists());
    for bytes in [vec![], vec![0; genesis::MAX_GENESIS_BYTES + 1]] {
        fs::write(&path, bytes).unwrap();
        let bad = fixture
            .command()
            .arg("--genesis")
            .arg(&path)
            .args(["--blocks", "1"])
            .output()
            .unwrap();
        assert_eq!(bad.status.code(), Some(2));
        assert!(!fixture.0.exists());
    }
}
