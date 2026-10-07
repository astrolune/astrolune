// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI request, protected approvals, quorum assembly and offline rechecking.

#![allow(clippy::too_many_lines)]

#[path = "../../../crates/consensus/tests/support/potb.rs"]
mod support;
use consensus::potb_transition::PotbVerifier;
use keystore::{DurableSigner, SigningContext};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        fs::remove_dir_all(path).unwrap();
    }
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

#[test]
fn request_and_protected_quorum_are_usable_offline_with_authenticated_history() {
    let directory = Fixture(std::env::temp_dir().join(format!(
        "astrolune-cli-potb-admission-{}",
        std::process::id()
    )));
    fs::create_dir(&directory.0).unwrap();
    let (genesis, keys) = support::fixture();
    fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    fs::write(directory.0.join("keys"), keys.concat()).unwrap();
    fs::write(directory.0.join("candidate"), [99; 32]).unwrap();
    let mut trust = PotbVerifier::new(&genesis, &keys).unwrap();
    let mut replies = vec![];
    for _ in 1..=2 {
        let handoff = support::handoff(&trust, support::batch(trust.current()));
        trust.apply(&handoff).unwrap();
        replies.push(handoff.to_bytes().unwrap());
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let worker = std::thread::spawn(move || {
        for bytes in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let size = u32::from_le_bytes(size) as usize;
            assert!(size < 1024);
            stream.read_exact(&mut vec![0; size]).unwrap();
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#, hex(&bytes));
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&directory.0)
            .args(args)
            .output()
            .unwrap()
    };
    success(run(&[
        "admission-request",
        "genesis",
        "keys",
        "candidate",
        "3",
        "request",
        &address,
    ]));
    worker.join().unwrap();
    assert!(directory.0.join("request.handoffs").exists());
    assert!(
        success(run(&["admission-inspect", "genesis", "keys", "request"]))
            .contains("candidate_consent: valid")
    );
    assert!(
        !run(&[
            "admission-request",
            "genesis",
            "keys",
            "candidate",
            "3",
            "request",
            &address
        ])
        .status
        .success()
    );

    let context = trust.current().committee().context().unwrap();
    let mut approvals = vec![];
    for seed in 1..=5 {
        let name = format!("seed-{seed}");
        let journal = format!("journal-{seed}");
        let approval = format!("approval-{seed}");
        fs::write(directory.0.join(&name), [seed; 32]).unwrap();
        let signer = DurableSigner::create_protected(
            directory.0.join(&journal),
            SigningContext {
                chain_id: genesis.genesis().chain_id,
                genesis: genesis.commitment(),
            },
            [seed; 32],
        )
        .unwrap();
        let id = types::ValidatorId(crypto::blake2s_hash(&signer.public_key()).0);
        drop(signer);
        let before = fs::read(directory.0.join(&journal)).unwrap();
        let result = run(&[
            "admission-approve",
            "genesis",
            "keys",
            "request",
            &name,
            &journal,
            &approval,
        ]);
        if context.voting_power(id).is_some() {
            success(result);
            approvals.push(approval.clone());
            assert!(
                !run(&[
                    "admission-approve",
                    "genesis",
                    "keys",
                    "request",
                    &name,
                    &journal,
                    &approval
                ])
                .status
                .success()
            );
        } else {
            assert!(!result.status.success());
            assert!(!directory.0.join(&approval).exists());
        }
        assert_eq!(fs::read(directory.0.join(&journal)).unwrap(), before);
    }
    assert_eq!(approvals.len(), 3);
    assert!(
        !run(&[
            "admission-assemble",
            "genesis",
            "keys",
            "request",
            "insufficient",
            &approvals[0],
            &approvals[1]
        ])
        .status
        .success()
    );
    assert!(!directory.0.join("insufficient").exists());
    assert!(
        !run(&[
            "admission-assemble",
            "genesis",
            "keys",
            "request",
            "duplicate",
            &approvals[0],
            &approvals[0],
            &approvals[2]
        ])
        .status
        .success()
    );
    let mut args = vec![
        "admission-assemble",
        "genesis",
        "keys",
        "request",
        "certificate",
    ];
    args.extend(approvals.iter().map(String::as_str));
    assert!(success(run(&args)).contains("valid incumbent weighted quorum"));
    assert!(
        success(run(&[
            "admission-verify",
            "genesis",
            "keys",
            "request",
            "certificate"
        ]))
        .contains("activation: not included")
    );
    let bytes = fs::read(directory.0.join("certificate")).unwrap();
    fs::write(directory.0.join("corrupt"), &bytes[..bytes.len() - 1]).unwrap();
    assert!(
        !run(&["admission-verify", "genesis", "keys", "request", "corrupt"])
            .status
            .success()
    );
    fs::rename(
        directory.0.join("request.handoffs"),
        directory.0.join("saved-history"),
    )
    .unwrap();
    assert!(
        !run(&["admission-inspect", "genesis", "keys", "request"])
            .status
            .success()
    );
    assert!(
        !run(&[
            "admission-approve",
            "genesis",
            "keys",
            "request",
            "seed-1",
            "journal-1",
            "no-history"
        ])
        .status
        .success()
    );
    assert!(!directory.0.join("no-history").exists());
}
