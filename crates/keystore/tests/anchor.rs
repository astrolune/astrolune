// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Restored-journal rollback, anchor pairing, catch-up and cross-process regressions.

use keystore::{
    DurableSigner, KeystoreError, SIGNING_ANCHOR_BYTES, Signer, SigningContext, SigningLock,
    SigningPosition, SigningSafety,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use types::Hash256;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-anchor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("signing.journal")
    }
    // The anchor is provisioned separately and is intended to live on storage that
    // cannot be restored together with the journal. A sibling path is only a test.
    fn anchor(&self) -> PathBuf {
        self.0.join("signing.anchor")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context() -> SigningContext {
    SigningContext {
        chain_id: 7,
        genesis: Hash256([8; 32]),
    }
}
fn position(height: u64) -> SigningPosition {
    SigningPosition {
        height,
        round: 0,
        phase: keystore::PREVOTE_PHASE,
    }
}
fn safety() -> SigningSafety {
    SigningSafety {
        committee_root: Hash256([9; 32]),
        locked: None,
    }
}

#[test]
fn a_restored_older_journal_signs_alone_but_never_beside_its_independent_anchor() {
    let fixture = Fixture::new();
    drop(DurableSigner::create(fixture.journal(), context(), [1; 32]).unwrap());
    let mut signer =
        DurableSigner::create_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    let handle = signer.key_handle();
    assert_eq!(signer.anchor_sequence(), Some(0));
    assert_eq!(
        fs::metadata(fixture.anchor()).unwrap().len(),
        SIGNING_ANCHOR_BYTES as u64
    );
    signer
        .sign_consensus(&handle, position(1), Hash256([11; 32]))
        .unwrap();
    drop(signer);
    // One durable decision; this is the state an operator would restore from backup.
    let restored = fs::read(fixture.journal()).unwrap();
    let mut signer =
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    assert_eq!(signer.anchor_sequence(), Some(1));
    for height in 2u8..=4 {
        signer
            .sign_consensus(&handle, position(u64::from(height)), Hash256([height; 32]))
            .unwrap();
    }
    assert_eq!(signer.anchor_sequence(), Some(4));
    assert_eq!(signer.last_position(), Some(position(4)));
    drop(signer);

    // The attack: put back the older complete prefix. Its checksum chain is
    // self-consistent, so the journal alone accepts it as the current watermark and
    // happily signs a different decision at a height it already voted on.
    let current = fs::read(fixture.journal()).unwrap();
    let rolled_back = fixture.0.join("rolled-back.journal");
    fs::write(&rolled_back, &restored).unwrap();
    let mut alone = DurableSigner::open(&rolled_back, context(), [1; 32]).unwrap();
    assert_eq!(alone.last_position(), Some(position(1)));
    alone
        .sign_consensus(&handle, position(2), Hash256([99; 32]))
        .unwrap();
    drop(alone);

    // The same rollback beside a current anchor fails loudly and changes nothing.
    fs::write(fixture.journal(), &restored).unwrap();
    assert_eq!(
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::StalePosition
    );
    assert_eq!(fs::read(fixture.journal()).unwrap(), restored);
    assert_eq!(
        fs::metadata(fixture.anchor()).unwrap().len(),
        SIGNING_ANCHOR_BYTES as u64
    );
    // A journal rewound and then advanced to the anchor's own sequence with a
    // different history is a mismatched pair, not a watermark to merge.
    let mut diverged = DurableSigner::open(fixture.journal(), context(), [1; 32]).unwrap();
    for height in 2..=4 {
        diverged
            .sign_consensus(&handle, position(height), Hash256([77; 32]))
            .unwrap();
    }
    drop(diverged);
    assert_eq!(
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::ConflictingSign
    );
    // Restoring the real journal restores the pair.
    fs::write(fixture.journal(), &current).unwrap();
    let signer =
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    assert_eq!(signer.last_position(), Some(position(4)));
    assert_eq!(signer.anchor_sequence(), Some(4));
    assert!(signer.anchor_journal_identity().is_some());
    assert!(format!("{signer:?}").contains("anchored: true"));
}

#[test]
fn an_anchor_one_decision_behind_catches_up_and_a_further_gap_fails_closed() {
    let fixture = Fixture::new();
    drop(DurableSigner::create_protected(fixture.journal(), context(), [1; 32]).unwrap());
    let signer =
        DurableSigner::create_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    let handle = signer.key_handle();
    drop(signer);
    // Signing without the anchor reproduces exactly the state an interrupted anchor
    // write leaves behind: the journal is ahead, its decision already durable.
    let mut plain = DurableSigner::open(fixture.journal(), context(), [1; 32]).unwrap();
    plain
        .sign_protected(&handle, position(1), Hash256([11; 32]), safety())
        .unwrap();
    drop(plain);
    let mut signer =
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    assert_eq!(signer.anchor_sequence(), Some(1));
    // An exact retry neither advances the journal nor rewrites the anchor.
    signer
        .sign_protected(&handle, position(1), Hash256([11; 32]), safety())
        .unwrap();
    assert_eq!(signer.anchor_sequence(), Some(1));
    assert_eq!(
        signer.sign_protected(&handle, position(1), Hash256([12; 32]), safety()),
        Err(KeystoreError::ConflictingSign)
    );
    drop(signer);
    let witnessed = fs::read(fixture.anchor()).unwrap();

    // Two decisions without the anchor leave a gap the anchor refuses to bridge.
    let mut plain = DurableSigner::open(fixture.journal(), context(), [1; 32]).unwrap();
    for height in 2u8..=3 {
        plain
            .sign_protected(
                &handle,
                position(u64::from(height)),
                Hash256([height; 32]),
                SigningSafety {
                    locked: Some(SigningLock {
                        round: 0,
                        block: Hash256([7; 32]),
                    }),
                    ..safety()
                },
            )
            .unwrap();
    }
    drop(plain);
    assert_eq!(
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::StalePosition
    );
    assert_eq!(fs::read(fixture.anchor()).unwrap(), witnessed);
}

#[test]
fn anchors_are_explicitly_provisioned_and_bound_to_exactly_one_journal() {
    let fixture = Fixture::new();
    // Opening never creates a missing anchor, even with the key and journal present.
    drop(DurableSigner::create(fixture.journal(), context(), [1; 32]).unwrap());
    assert_eq!(
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::JournalFailure
    );
    assert!(!fixture.anchor().exists());
    // Provisioning requires an existing journal and refuses to overwrite an anchor.
    assert_eq!(
        DurableSigner::create_anchor(
            fixture.0.join("absent.journal"),
            context(),
            [1; 32],
            fixture.anchor()
        )
        .unwrap_err(),
        KeystoreError::JournalFailure
    );
    assert!(!fixture.anchor().exists());
    drop(
        DurableSigner::create_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap(),
    );
    let bytes = fs::read(fixture.anchor()).unwrap();
    assert_eq!(
        DurableSigner::create_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::AlreadyExists
    );
    assert_eq!(fs::read(fixture.anchor()).unwrap(), bytes);

    // An anchor provisioned for another key or namespace is never merged.
    let other = Fixture::new();
    drop(DurableSigner::create(other.journal(), context(), [2; 32]).unwrap());
    drop(
        DurableSigner::create_anchor(other.journal(), context(), [2; 32], other.anchor()).unwrap(),
    );
    assert_eq!(
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], other.anchor())
            .unwrap_err(),
        KeystoreError::ContextMismatch
    );
    assert_eq!(
        DurableSigner::open_with_anchor(other.journal(), context(), [2; 32], fixture.anchor())
            .unwrap_err(),
        KeystoreError::ContextMismatch
    );
    // Every single-byte change to the anchor fails closed without rewriting it.
    for index in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1;
        fs::write(fixture.anchor(), &damaged).unwrap();
        assert!(
            DurableSigner::open_with_anchor(
                fixture.journal(),
                context(),
                [1; 32],
                fixture.anchor()
            )
            .is_err(),
            "byte {index}"
        );
        assert_eq!(fs::read(fixture.anchor()).unwrap(), damaged);
    }
}

#[test]
fn an_anchored_decision_survives_process_exit_without_destructors() {
    let fixture = Fixture::new();
    drop(DurableSigner::create_protected(fixture.journal(), context(), [1; 32]).unwrap());
    drop(
        DurableSigner::create_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap(),
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "anchor_child", "--nocapture"])
        .env("ASTROLUNE_ANCHOR_TEST_PATH", fixture.journal())
        .env("ASTROLUNE_ANCHOR_TEST_ANCHOR", fixture.anchor())
        .env("ASTROLUNE_ANCHOR_TEST_MODE", "sign")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut signer =
        DurableSigner::open_with_anchor(fixture.journal(), context(), [1; 32], fixture.anchor())
            .unwrap();
    assert_eq!(signer.last_position(), Some(position(1)));
    assert_eq!(signer.anchor_sequence(), Some(1));
    assert_eq!(
        signer.sign_protected(
            &signer.key_handle(),
            position(1),
            Hash256([12; 32]),
            safety()
        ),
        Err(KeystoreError::ConflictingSign)
    );
    // The journal and anchor are both exclusively held while this signer lives.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "anchor_child", "--nocapture"])
        .env("ASTROLUNE_ANCHOR_TEST_PATH", fixture.journal())
        .env("ASTROLUNE_ANCHOR_TEST_ANCHOR", fixture.anchor())
        .env("ASTROLUNE_ANCHOR_TEST_MODE", "locked")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn anchor_child() {
    let Some(path) = std::env::var_os("ASTROLUNE_ANCHOR_TEST_PATH") else {
        return;
    };
    let anchor = std::env::var_os("ASTROLUNE_ANCHOR_TEST_ANCHOR").unwrap();
    if std::env::var("ASTROLUNE_ANCHOR_TEST_MODE").unwrap() == "locked" {
        assert_eq!(
            DurableSigner::open_with_anchor(path, context(), [1; 32], anchor).unwrap_err(),
            KeystoreError::Locked
        );
        return;
    }
    let mut signer = DurableSigner::open_with_anchor(path, context(), [1; 32], anchor).unwrap();
    signer
        .sign_protected(
            &signer.key_handle(),
            position(1),
            Hash256([11; 32]),
            safety(),
        )
        .unwrap();
    std::process::exit(0);
}
