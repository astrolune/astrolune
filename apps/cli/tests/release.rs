// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real CLI release-manifest signing and offline verification against a supplied key.

use crypto::blake2s::ed25519_public_key;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
use types::Hash256;

const MANIFEST: &[u8] = br#"{
  "archive_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "files": {"cli": "22", "daemon": "33"},
  "release": true
}
"#;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-release-cli-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("MANIFEST.json"), MANIFEST).unwrap();
        std::fs::write(path.join("authority.seed"), [7; 32]).unwrap();
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
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn release_signatures_verify_offline_only_against_an_explicitly_supplied_authority() {
    let fixture = Fixture::new("authority");
    let authority = Hash256(ed25519_public_key(&[7; 32])).to_string();
    let signed = success(&fixture.command(&[
        "release-sign",
        "MANIFEST.json",
        "authority.seed",
        "MANIFEST.json.sig",
    ]));
    assert!(signed.contains(&format!("authority_public_key: {authority}")));
    assert!(signed.contains("publication: not performed"));
    assert!(!signed.contains(&"07".repeat(32)));
    let signature = std::fs::read(fixture.0.join("MANIFEST.json.sig")).unwrap();
    assert_eq!(signature.len(), keystore::release::RELEASE_SIGNATURE_BYTES);
    // Signing never overwrites an existing signature artifact.
    assert!(
        !fixture
            .command(&[
                "release-sign",
                "MANIFEST.json",
                "authority.seed",
                "MANIFEST.json.sig",
            ])
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(fixture.0.join("MANIFEST.json.sig")).unwrap(),
        signature
    );
    let verified = success(&fixture.command(&[
        "verify-release",
        "MANIFEST.json",
        &authority,
        "MANIFEST.json.sig",
    ]));
    assert!(verified.contains("verification: valid detached signature"));
    assert!(verified.contains("authority_trust: not established by this tool"));

    // A different authority key never verifies, and no key is implied by the file.
    let foreign = Hash256(ed25519_public_key(&[8; 32])).to_string();
    assert!(
        !fixture
            .command(&[
                "verify-release",
                "MANIFEST.json",
                &foreign,
                "MANIFEST.json.sig",
            ])
            .status
            .success()
    );
    // Any manifest change, including the release flag, invalidates the signature.
    std::fs::write(
        fixture.0.join("CHANGED.json"),
        String::from_utf8_lossy(MANIFEST).replace("true", "false"),
    )
    .unwrap();
    assert!(
        !fixture
            .command(&[
                "verify-release",
                "CHANGED.json",
                &authority,
                "MANIFEST.json.sig",
            ])
            .status
            .success()
    );
    // Any signature change fails, as do empty manifests and wrong argument counts.
    let mut forged = signature;
    forged[100] ^= 1;
    std::fs::write(fixture.0.join("forged.sig"), &forged).unwrap();
    assert!(
        !fixture
            .command(&["verify-release", "MANIFEST.json", &authority, "forged.sig"])
            .status
            .success()
    );
    std::fs::write(fixture.0.join("empty.json"), b"").unwrap();
    assert!(
        !fixture
            .command(&[
                "verify-release",
                "empty.json",
                &authority,
                "MANIFEST.json.sig"
            ])
            .status
            .success()
    );
    assert!(!fixture.command(&["verify-release"]).status.success());
    assert!(
        !fixture
            .command(&["release-sign", "MANIFEST.json"])
            .status
            .success()
    );
}

#[test]
fn a_release_authority_can_be_held_in_a_consensus_vault_without_plaintext_export() {
    let fixture = Fixture::new("vault");
    let password = b"correct horse battery staple\n";
    success(&fixture.with_password(
        &[
            "consensus-vault-encrypt",
            "authority.seed",
            "authority.vault",
        ],
        password,
    ));
    let signed = success(&fixture.with_password(
        &[
            "release-sign",
            "MANIFEST.json",
            "authority.vault",
            "vault.sig",
        ],
        password,
    ));
    assert!(!signed.contains("correct horse"));
    assert!(!signed.contains(&"07".repeat(32)));
    // The vault and the raw seed produce byte-identical deterministic signatures.
    success(&fixture.command(&["release-sign", "MANIFEST.json", "authority.seed", "raw.sig"]));
    assert_eq!(
        std::fs::read(fixture.0.join("vault.sig")).unwrap(),
        std::fs::read(fixture.0.join("raw.sig")).unwrap()
    );
    assert!(
        !fixture
            .with_password(
                &[
                    "release-sign",
                    "MANIFEST.json",
                    "authority.vault",
                    "wrong.sig"
                ],
                b"incorrect long password\n"
            )
            .status
            .success()
    );
    assert!(!fixture.0.join("wrong.sig").exists());
}
