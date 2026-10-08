// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI anchor provisioning, consensus vaults, and rollback refusal.

use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::ed25519_public_key;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
use types::{Resources, ValidatorId};

const PASSWORD: &[u8] = b"correct horse battery staple\n";

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-custody-cli-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
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
        std::fs::write(path.join("genesis.bin"), genesis.to_bytes()).unwrap();
        std::fs::write(path.join("validator.seed"), [1; 32]).unwrap();
        Self(path)
    }
    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn with_password(&self, args: &[&str], password: &[u8]) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_cli"))
            .current_dir(&self.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        process.stdin.take().unwrap().write_all(password).unwrap();
        process.wait_with_output().unwrap()
    }
    fn anchor_command(&self, verb: &str, key: &str) -> Output {
        self.command(&[
            verb,
            "genesis.bin",
            key,
            "node/signing.journal",
            "signing.anchor",
        ])
    }
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Signs one protected decision through the paired anchor and returns the journal.
fn advance_one_decision(fixture: &Fixture, journal: &std::path::Path) -> Vec<u8> {
    let genesis =
        genesis::Genesis::decode(&std::fs::read(fixture.0.join("genesis.bin")).unwrap()).unwrap();
    let mut signer = keystore::DurableSigner::open_with_anchor(
        journal,
        keystore::SigningContext {
            chain_id: genesis.chain_id,
            genesis: genesis.commitment().unwrap(),
        },
        [1; 32],
        fixture.0.join("signing.anchor"),
    )
    .unwrap();
    let handle = signer.key_handle();
    signer
        .sign_protected(
            &handle,
            keystore::SigningPosition {
                height: 1,
                round: 0,
                phase: keystore::PREVOTE_PHASE,
            },
            types::Hash256([5; 32]),
            keystore::SigningSafety {
                committee_root: types::Hash256([9; 32]),
                locked: None,
            },
        )
        .unwrap();
    drop(signer);
    std::fs::read(journal).unwrap()
}

#[test]
fn anchor_provisioning_refuses_overwrites_and_rejects_a_restored_older_journal() {
    let fixture = Fixture::new("anchor");
    success(&fixture.command(&["init-validator", "genesis.bin", "validator.seed", "node"]));
    let journal = fixture.0.join("node/signing.journal");
    assert!(journal.is_file());
    let created = success(&fixture.anchor_command("signing-anchor-create", "validator.seed"));
    assert!(created.contains("witnessed_decisions: 0"));
    assert!(created.contains("last_position: none"));
    assert_eq!(
        std::fs::metadata(fixture.0.join("signing.anchor"))
            .unwrap()
            .len(),
        keystore::SIGNING_ANCHOR_BYTES as u64
    );
    let anchor = std::fs::read(fixture.0.join("signing.anchor")).unwrap();
    // Provisioning never overwrites an existing anchor.
    assert!(
        !fixture
            .anchor_command("signing-anchor-create", "validator.seed")
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(fixture.0.join("signing.anchor")).unwrap(),
        anchor
    );
    let verified = success(&fixture.anchor_command("verify-signing-anchor", "validator.seed"));
    assert!(verified.contains("verification: journal agrees with its independent anchor"));
    assert!(!verified.contains(&"01".repeat(32)));

    // A freshly provisioned replacement journal is behind the anchor only once the
    // anchor has witnessed a decision, so advance both together first.
    let advanced = advance_one_decision(&fixture, &journal);
    assert!(
        success(&fixture.anchor_command("verify-signing-anchor", "validator.seed"))
            .contains("witnessed_decisions: 1")
    );
    // The attack: provision a replacement journal for the same live identity.
    std::fs::create_dir(fixture.0.join("replacement")).unwrap();
    success(&fixture.command(&[
        "init-validator",
        "genesis.bin",
        "validator.seed",
        "replacement",
    ]));
    std::fs::copy(fixture.0.join("replacement/signing.journal"), &journal).unwrap();
    let rolled_back = fixture.anchor_command("verify-signing-anchor", "validator.seed");
    assert!(!rolled_back.status.success());
    assert!(
        String::from_utf8_lossy(&rolled_back.stderr).contains("precedes durable watermark"),
        "{}",
        String::from_utf8_lossy(&rolled_back.stderr)
    );
    std::fs::write(&journal, advanced).unwrap();
    success(&fixture.anchor_command("verify-signing-anchor", "validator.seed"));
    // An anchor provisioned for another key is never accepted for this journal.
    std::fs::write(fixture.0.join("other.seed"), [2; 32]).unwrap();
    assert!(
        !fixture
            .anchor_command("verify-signing-anchor", "other.seed")
            .status
            .success()
    );
    assert!(!fixture.command(&["signing-anchor-create"]).status.success());
}

#[test]
fn consensus_vaults_provision_validators_and_never_substitute_for_wallet_vaults() {
    let fixture = Fixture::new("vault");
    let created = success(&fixture.with_password(
        &["consensus-vault-encrypt", "validator.seed", "node.vault"],
        PASSWORD,
    ));
    assert!(!created.contains("correct horse"));
    assert!(!created.contains(&"01".repeat(32)));
    assert!(created.contains("encrypted_consensus_key: node.vault"));
    assert_eq!(
        std::fs::metadata(fixture.0.join("node.vault"))
            .unwrap()
            .len(),
        keystore::vault::CONSENSUS_VAULT_BYTES as u64
    );
    // The vault provisions exactly the journal the raw seed would have provisioned.
    success(&fixture.with_password(
        &["init-validator", "genesis.bin", "node.vault", "vaulted"],
        PASSWORD,
    ));
    success(&fixture.command(&["init-validator", "genesis.bin", "validator.seed", "raw"]));
    assert_eq!(
        std::fs::read(fixture.0.join("vaulted/signing.journal")).unwrap(),
        std::fs::read(fixture.0.join("raw/signing.journal")).unwrap()
    );
    // A wrong password never provisions anything.
    assert!(
        !fixture
            .with_password(
                &["init-validator", "genesis.bin", "node.vault", "wrong"],
                b"incorrect long password\n"
            )
            .status
            .success()
    );
    assert!(!fixture.0.join("wrong/signing.journal").exists());
    // A wallet vault is refused by consensus commands, and the reverse.
    success(&fixture.with_password(
        &["wallet-encrypt", "validator.seed", "wallet.vault"],
        PASSWORD,
    ));
    let refused = fixture.with_password(
        &["init-validator", "genesis.bin", "wallet.vault", "mixed"],
        PASSWORD,
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("this is a wallet vault"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !fixture
            .with_password(&["wallet-address", "node.vault"], PASSWORD)
            .status
            .success()
    );
    let reversed = fixture.with_password(&["wallet-address", "node.vault"], PASSWORD);
    assert!(
        String::from_utf8_lossy(&reversed.stderr).contains("this is a consensus vault"),
        "{}",
        String::from_utf8_lossy(&reversed.stderr)
    );
    // Created consensus vaults are random and never overwrite an existing output.
    let first = success(&fixture.with_password(&["consensus-vault-create", "a.vault"], PASSWORD));
    let second = success(&fixture.with_password(&["consensus-vault-create", "b.vault"], PASSWORD));
    assert_ne!(first.lines().next(), second.lines().next());
    assert!(
        !fixture
            .with_password(&["consensus-vault-create", "a.vault"], PASSWORD)
            .status
            .success()
    );
    // An empty stdin pipe supplies no password; passwords never come from argv.
    assert!(
        !fixture
            .command(&["consensus-vault-create", "c.vault"])
            .status
            .success()
    );
    assert!(
        !fixture
            .with_password(&["consensus-vault-create", "d.vault"], b"short\n")
            .status
            .success()
    );
}
