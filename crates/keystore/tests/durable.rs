// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Durable signing, recovery, namespace isolation, and process locking regressions.

use keystore::{
    ChainSigner, DurableSigner, KeyPurpose, KeystoreError, MAX_JOURNAL_BYTES, Signer,
    SigningContext, SigningPosition,
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
            "astrolune-signing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("signing.bin")
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
fn position(height: u64, round: u32, phase: u8) -> SigningPosition {
    SigningPosition {
        height,
        round,
        phase,
    }
}

#[test]
fn restart_preserves_idempotency_conflicts_and_monotonic_watermark() {
    let fixture = Fixture::new();
    let mut signer = DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap();
    let handle = signer.key_handle();
    let public_key = signer.public_key();
    assert_eq!(signer.signing_context(), context());
    assert_eq!(signer.last_position(), None);
    let slot = position(1, 0, keystore::PREVOTE_PHASE);
    let hash = Hash256([5; 32]);
    let signature = signer.sign_consensus(&handle, slot, hash).unwrap();
    assert!(crypto::blake2s::ed25519_verify(
        &public_key,
        &hash.0,
        &signature
    ));
    assert_eq!(fs::metadata(fixture.path()).unwrap().len(), 193);
    assert_eq!(
        signer.sign_consensus(&handle, slot, hash).unwrap(),
        signature
    );
    drop(signer);
    let before = fs::read(fixture.path()).unwrap();
    let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.key_handle(), handle);
    assert_eq!(signer.last_position(), Some(slot));
    assert_eq!(
        signer.sign_consensus(&handle, slot, hash).unwrap(),
        signature
    );
    assert_eq!(
        signer.sign_consensus(&handle, slot, Hash256([6; 32])),
        Err(KeystoreError::ConflictingSign)
    );
    assert_eq!(
        signer.sign_consensus(&handle, position(0, 99, 2), hash),
        Err(KeystoreError::StalePosition)
    );
    drop(signer);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    let slots = [
        position(1, 0, 2),
        position(1, 1, 0),
        position(2, 0, 0),
        position(u64::MAX, u32::MAX, 2),
    ];
    for slot in slots {
        let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
        signer.sign_consensus(&handle, slot, hash).unwrap();
    }
    let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.last_position(), Some(slots[3]));
    for slot in slots[..3].iter().copied() {
        assert_eq!(
            signer.sign_consensus(&handle, slot, hash),
            Err(KeystoreError::StalePosition)
        );
    }
}

#[test]
fn namespaces_handles_phases_and_missing_journals_fail_without_rewriting() {
    let fixture = Fixture::new();
    assert_eq!(
        DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap_err(),
        KeystoreError::JournalFailure
    );
    assert!(!fixture.path().exists());
    assert!(
        DurableSigner::create(
            fixture.path(),
            SigningContext {
                genesis: Hash256::ZERO,
                ..context()
            },
            [1; 32]
        )
        .is_err()
    );
    assert!(!fixture.path().exists());
    let mut signer = DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap();
    let handle = signer.key_handle();
    for purpose in [KeyPurpose::Network, KeyPurpose::Service, KeyPurpose::Wallet] {
        let mut wrong = handle.clone();
        wrong.purpose = purpose;
        assert_eq!(
            signer.sign_consensus(&wrong, position(1, 0, 0), Hash256::ZERO),
            Err(KeystoreError::WrongPurpose)
        );
    }
    let mut wrong = handle.clone();
    wrong.id.push('x');
    assert_eq!(
        signer.sign_consensus(&wrong, position(1, 0, 0), Hash256::ZERO),
        Err(KeystoreError::UnknownKey)
    );
    for phase in 3..=255 {
        assert_eq!(
            signer.sign_consensus(&handle, position(1, 0, phase), Hash256::ZERO),
            Err(KeystoreError::InvalidPosition)
        );
    }
    assert_eq!(signer.last_position(), None);
    assert!(!format!("{signer:?}").contains("seed"));
    drop(signer);
    let before = fs::read(fixture.path()).unwrap();
    for (other, seed) in [
        (
            SigningContext {
                chain_id: 8,
                ..context()
            },
            [1; 32],
        ),
        (
            SigningContext {
                genesis: Hash256([9; 32]),
                ..context()
            },
            [1; 32],
        ),
        (context(), [2; 32]),
    ] {
        assert_eq!(
            DurableSigner::open(fixture.path(), other, seed).unwrap_err(),
            KeystoreError::ContextMismatch
        );
    }
    assert_eq!(
        DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap_err(),
        KeystoreError::AlreadyExists
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn corrupt_incomplete_and_oversized_files_are_never_repaired_implicitly() {
    let fixture = Fixture::new();
    let mut signer = DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap();
    signer
        .sign_consensus(&signer.key_handle(), position(1, 0, 0), Hash256([3; 32]))
        .unwrap();
    signer
        .sign_consensus(&signer.key_handle(), position(1, 0, 1), Hash256([4; 32]))
        .unwrap();
    drop(signer);
    let original = fs::read(fixture.path()).unwrap();
    for index in 0..original.len() {
        let mut damaged = original.clone();
        damaged[index] ^= 1;
        fs::write(fixture.path(), &damaged).unwrap();
        assert!(
            DurableSigner::open(fixture.path(), context(), [1; 32]).is_err(),
            "byte {index}"
        );
        assert_eq!(fs::read(fixture.path()).unwrap(), damaged);
    }
    // Complete prefix rollback needs an external monotonic anchor; partial frames fail.
    for length in 0..original.len() {
        if length >= 108 && (length - 108).is_multiple_of(85) {
            continue;
        }
        fs::write(fixture.path(), &original[..length]).unwrap();
        assert!(
            DurableSigner::open(fixture.path(), context(), [1; 32]).is_err(),
            "length {length}"
        );
        assert_eq!(
            fs::metadata(fixture.path()).unwrap().len(),
            u64::try_from(length).unwrap()
        );
    }
    fs::File::create(fixture.path())
        .unwrap()
        .set_len(MAX_JOURNAL_BYTES + 1)
        .unwrap();
    assert_eq!(
        DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap_err(),
        KeystoreError::InvalidJournal
    );
    assert_eq!(
        fs::metadata(fixture.path()).unwrap().len(),
        MAX_JOURNAL_BYTES + 1
    );
}

#[test]
fn independent_handles_and_processes_cannot_share_an_active_journal() {
    let fixture = Fixture::new();
    let signer = DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(
        DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap_err(),
        KeystoreError::Locked
    );
    let alias = fixture.0.join("alias.bin");
    fs::hard_link(fixture.path(), &alias).unwrap();
    assert_eq!(
        DurableSigner::open(&alias, context(), [1; 32]).unwrap_err(),
        KeystoreError::Locked
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "journal_child", "--nocapture"])
        .env("ASTROLUNE_JOURNAL_TEST_PATH", fixture.path())
        .env("ASTROLUNE_JOURNAL_TEST_ACTION", "locked")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(signer);
    assert!(DurableSigner::open(&alias, context(), [1; 32]).is_ok());
}

#[test]
fn decision_survives_process_exit_without_destructors() {
    let fixture = Fixture::new();
    drop(DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap());
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "journal_child", "--nocapture"])
        .env("ASTROLUNE_JOURNAL_TEST_PATH", fixture.path())
        .env("ASTROLUNE_JOURNAL_TEST_ACTION", "exit")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.last_position(), Some(position(1, 0, 1)));
    assert_eq!(
        signer.sign_consensus(&signer.key_handle(), position(1, 0, 1), Hash256([8; 32])),
        Err(KeystoreError::ConflictingSign)
    );
    assert!(
        signer
            .sign_consensus(&signer.key_handle(), position(1, 0, 1), Hash256([7; 32]))
            .is_ok()
    );
}

#[test]
fn journal_child() {
    let Some(path) = std::env::var_os("ASTROLUNE_JOURNAL_TEST_PATH") else {
        return;
    };
    if std::env::var("ASTROLUNE_JOURNAL_TEST_ACTION").unwrap() == "locked" {
        assert_eq!(
            DurableSigner::open(path, context(), [1; 32]).unwrap_err(),
            KeystoreError::Locked
        );
        return;
    }
    let mut signer = DurableSigner::open(path, context(), [1; 32]).unwrap();
    signer
        .sign_consensus(&signer.key_handle(), position(1, 0, 1), Hash256([7; 32]))
        .unwrap();
    std::process::exit(0);
}

#[test]
fn protected_journal_preserves_lock_and_rejects_mode_or_safety_downgrades() {
    use keystore::{SigningLock, SigningSafety};
    let fixture = Fixture::new();
    let mut signer = DurableSigner::create_protected(fixture.path(), context(), [1; 32]).unwrap();
    let handle = signer.key_handle();
    assert!(signer.is_protected());
    let safety = SigningSafety {
        committee_root: Hash256([9; 32]),
        locked: None,
    };
    let digest = Hash256([6; 32]);
    assert_eq!(
        signer.sign_consensus(&handle, position(1, 0, 1), digest),
        Err(KeystoreError::InvalidSafety)
    );
    signer
        .sign_protected(&handle, position(1, 0, 1), digest, safety)
        .unwrap();
    let locked = SigningSafety {
        locked: Some(SigningLock {
            round: 0,
            block: Hash256([7; 32]),
        }),
        ..safety
    };
    let signature = signer
        .sign_protected(&handle, position(1, 0, 2), digest, locked)
        .unwrap();
    drop(signer);
    let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert!(signer.is_protected());
    assert_eq!(signer.safety(), Some(locked));
    assert_eq!(
        signer
            .sign_protected(&handle, position(1, 0, 2), digest, locked)
            .unwrap(),
        signature
    );
    assert_eq!(
        signer.sign_protected(&handle, position(1, 0, 2), digest, safety),
        Err(KeystoreError::ConflictingSign)
    );
    for invalid in [
        safety,
        SigningSafety {
            committee_root: Hash256([10; 32]),
            ..locked
        },
        SigningSafety {
            locked: Some(SigningLock {
                round: 0,
                block: Hash256([8; 32]),
            }),
            ..safety
        },
        SigningSafety {
            locked: Some(SigningLock {
                round: 2,
                block: Hash256([7; 32]),
            }),
            ..safety
        },
    ] {
        assert_eq!(
            signer.sign_protected(&handle, position(1, 1, 1), digest, invalid),
            Err(KeystoreError::InvalidSafety)
        );
    }
    assert_eq!(signer.last_position(), Some(position(1, 0, 2)));
    signer
        .sign_protected(&handle, position(1, 1, 1), digest, locked)
        .unwrap();
    signer
        .sign_protected(&handle, position(1, 1, 2), digest, locked)
        .unwrap();
    // An independently trusted later height can begin without the previous height's lock.
    signer
        .sign_protected(&handle, position(2, 0, 1), digest, safety)
        .unwrap();
    drop(signer);
    let signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.safety(), Some(safety));
    drop(signer);
    let legacy = fixture.0.join("legacy.bin");
    let mut signer = DurableSigner::create(&legacy, context(), [1; 32]).unwrap();
    assert_eq!(
        signer.sign_protected(&handle, position(1, 0, 1), digest, safety),
        Err(KeystoreError::InvalidSafety)
    );
}

#[cfg(unix)]
#[test]
fn symbolic_journal_alias_is_rejected() {
    let fixture = Fixture::new();
    drop(DurableSigner::create(fixture.path(), context(), [1; 32]).unwrap());
    let alias = fixture.0.join("alias.bin");
    std::os::unix::fs::symlink(fixture.path(), &alias).unwrap();
    assert_eq!(
        DurableSigner::open(&alias, context(), [1; 32]).unwrap_err(),
        KeystoreError::InvalidJournal
    );
}

#[test]
fn vrf_proofs_are_non_exporting_namespaced_and_do_not_consume_a_vote_position() {
    let fixture = Fixture::new();
    let signer = DurableSigner::create_protected(fixture.path(), context(), [1; 32]).unwrap();
    let input = crypto::VrfInput {
        chain_id: 7,
        genesis: context().genesis,
        epoch: 2,
        height: 2,
        parent_randomness: Hash256([9; 32]),
        round: 0,
        role: crypto::VrfRole::Committee,
    };
    drop(signer);
    let before = fs::read(fixture.path()).unwrap();
    let signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    let proof = signer.prove_vrf(input).unwrap();
    crypto::vrf::verify_vrf(&signer.public_key(), input.seed(), &proof).unwrap();
    assert_eq!(proof, signer.prove_vrf(input).unwrap());
    assert_eq!(signer.last_position(), None);
    for mutation in 0..5 {
        let mut changed = input;
        match mutation {
            0 => changed.chain_id += 1,
            1 => changed.genesis.0[0] ^= 1,
            2 => changed.round = 1,
            3 => changed.epoch += 1,
            _ => {
                changed.height = 1;
                changed.epoch = 1;
            }
        }
        assert!(signer.prove_vrf(changed).is_err());
    }
    let other = signer
        .prove_vrf(crypto::VrfInput {
            role: crypto::VrfRole::Producer,
            ..input
        })
        .unwrap();
    assert_ne!(other, proof);
    drop(signer);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    let reopened = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(reopened.prove_vrf(input).unwrap(), proof);
    drop(reopened);
    let unprotected = Fixture::new();
    let signer = DurableSigner::create(unprotected.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.prove_vrf(input), Err(KeystoreError::InvalidSafety));
}
