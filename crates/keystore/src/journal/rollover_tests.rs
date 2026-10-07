// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real-size rollover fixtures. The threshold is never lowered for testing.

use super::*;
use crate::{DurableSigner, SigningLock};
use std::process::Command;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-rollover-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        fs::write(fixture.path(), prefix()).unwrap();
        fixture
    }
    fn path(&self) -> PathBuf {
        self.0.join("signing.journal")
    }
    fn open(&self) -> Journal {
        Journal::open(&self.path(), context(), public()).unwrap()
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
fn public() -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&[1; 32])
}
fn position(sequence: u64) -> SigningPosition {
    SigningPosition {
        height: 42,
        round: u32::try_from(sequence).unwrap(),
        phase: 1,
    }
}
fn safety() -> SigningSafety {
    SigningSafety {
        committee_root: Hash256([9; 32]),
        locked: Some(SigningLock {
            round: 0,
            block: Hash256([7; 32]),
        }),
    }
}
fn prefix() -> &'static [u8] {
    static PREFIX: OnceLock<Vec<u8>> = OnceLock::new();
    PREFIX.get_or_init(|| {
        let header = header_version(context(), public(), true);
        let mut bytes = header.to_vec();
        let mut tip = domain_hash(HEADER_DOMAIN, &header[..76]);
        for sequence in 1..=MAX_JOURNAL_RECORDS {
            let entry = protected_record(
                sequence,
                position(sequence),
                Hash256([6; 32]),
                tip,
                safety(),
            );
            tip = Hash256(entry[122..].try_into().unwrap());
            bytes.extend_from_slice(&entry);
        }
        bytes
    })
}

#[test]
fn signatures_continue_past_the_old_limit_with_constant_size_and_preserved_locks() {
    let fixture = Fixture::new();
    let mut signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    let handle = signer.key_handle();
    let digest = Hash256([6; 32]);
    let invalid = SigningSafety {
        locked: None,
        ..safety()
    };
    assert_eq!(
        signer.sign_protected(&handle, position(MAX_JOURNAL_RECORDS + 1), digest, invalid),
        Err(KeystoreError::InvalidSafety)
    );
    assert_eq!(
        fs::metadata(fixture.path()).unwrap().len(),
        MAX_PROTECTED_JOURNAL_BYTES
    );
    // Capture an alias before activation: rollover must never replace the locked inode.
    let alias = fixture.0.join("alias.journal");
    fs::hard_link(fixture.path(), &alias).unwrap();
    for sequence in MAX_JOURNAL_RECORDS + 1..=MAX_JOURNAL_RECORDS + 12 {
        let signature = signer
            .sign_protected(&handle, position(sequence), digest, safety())
            .unwrap();
        assert!(crypto::blake2s::ed25519_verify(
            &public(),
            &digest.0,
            &signature
        ));
        assert_eq!(
            signer
                .sign_protected(&handle, position(sequence), digest, safety())
                .unwrap(),
            signature
        );
        assert_eq!(
            signer.sign_protected(&handle, position(sequence), Hash256([5; 32]), safety()),
            Err(KeystoreError::ConflictingSign)
        );
        assert_eq!(
            signer.sign_protected(&handle, position(sequence - 1), digest, safety()),
            Err(KeystoreError::StalePosition)
        );
        assert_eq!(
            fs::metadata(fixture.path()).unwrap().len(),
            MAX_ROLLOVER_JOURNAL_BYTES
        );
        assert_eq!(
            fs::metadata(&alias).unwrap().len(),
            MAX_ROLLOVER_JOURNAL_BYTES
        );
        assert_eq!(
            DurableSigner::open(&alias, context(), [1; 32]).unwrap_err(),
            KeystoreError::Locked
        );
    }
    drop(signer);
    let bytes = fs::read(fixture.path()).unwrap();
    assert_eq!(&bytes[..prefix().len()], prefix());
    let mut signer = DurableSigner::open(&alias, context(), [1; 32]).unwrap();
    assert_eq!(
        signer.last_position(),
        Some(position(MAX_JOURNAL_RECORDS + 12))
    );
    assert_eq!(signer.safety(), Some(safety()));
    assert_eq!(
        signer.sign_protected(&handle, position(MAX_JOURNAL_RECORDS + 13), digest, invalid),
        Err(KeystoreError::InvalidSafety)
    );
    let next_height = SigningPosition {
        height: 43,
        round: 0,
        phase: 0,
    };
    signer
        .sign_protected(&handle, next_height, digest, invalid)
        .unwrap();
    drop(signer);
    let signer = DurableSigner::open(fixture.path(), context(), [1; 32]).unwrap();
    assert_eq!(signer.safety(), Some(invalid));
    assert_eq!(signer.last_position(), Some(next_height));
}

#[test]
fn interrupted_activation_never_discards_the_original_watermark_or_partial_extension() {
    for written in [0, 1, 40, 194, rollover::EXTENSION_BYTES] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        assert_eq!(
            journal.activate_rollover(|file, bytes| {
                file.write_all(&bytes[..written])?;
                Err(std::io::Error::other("injected activation sync failure"))
            }),
            Err(KeystoreError::DurabilityUnknown)
        );
        assert_eq!(
            journal.reserve_protected(
                position(MAX_JOURNAL_RECORDS + 1),
                Hash256([6; 32]),
                safety()
            ),
            Err(KeystoreError::DurabilityUnknown)
        );
        drop(journal);
        let bytes = fs::read(fixture.path()).unwrap();
        let result = Journal::open(&fixture.path(), context(), public());
        if written == 0 || written == rollover::EXTENSION_BYTES {
            let mut journal = result.unwrap();
            assert_eq!(journal.last_position(), Some(position(MAX_JOURNAL_RECORDS)));
            assert_eq!(journal.safety(), Some(safety()));
            journal
                .reserve_protected(position(MAX_JOURNAL_RECORDS), Hash256([6; 32]), safety())
                .unwrap();
        } else {
            assert!(matches!(result, Err(KeystoreError::InvalidJournal)));
        }
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    }
}

#[test]
fn uncertain_slot_writes_never_fall_back_past_a_possible_signed_decision() {
    for written in [0, 12, 53, 122, PROTECTED_RECORD_BYTES] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .reserve_protected(
                position(MAX_JOURNAL_RECORDS + 1),
                Hash256([6; 32]),
                safety(),
            )
            .unwrap();
        let next = position(MAX_JOURNAL_RECORDS + 2);
        // Different digest, later lock and coordinate must publish as one watermark.
        let next_safety = SigningSafety {
            locked: Some(SigningLock {
                round: 1,
                block: Hash256([5; 32]),
            }),
            ..safety()
        };
        assert_eq!(
            journal.reserve_entry(next, Hash256([4; 32]), Some(next_safety), |file, bytes| {
                file.write_all(&bytes[..written])?;
                Err(std::io::Error::other(
                    "injected slot synchronization failure",
                ))
            }),
            Err(KeystoreError::DurabilityUnknown)
        );
        assert_eq!(
            journal.reserve_protected(next, Hash256([4; 32]), next_safety),
            Err(KeystoreError::DurabilityUnknown)
        );
        drop(journal);
        let bytes = fs::read(fixture.path()).unwrap();
        let result = Journal::open(&fixture.path(), context(), public());
        if written == 0 {
            let recovered = result.unwrap();
            assert_eq!(
                recovered.last_position(),
                Some(position(MAX_JOURNAL_RECORDS + 1))
            );
            assert_eq!(recovered.safety(), Some(safety()));
        } else if written == PROTECTED_RECORD_BYTES {
            let mut recovered = result.unwrap();
            assert_eq!(recovered.last_position(), Some(next));
            assert_eq!(recovered.safety(), Some(next_safety));
            recovered
                .reserve_protected(next, Hash256([4; 32]), next_safety)
                .unwrap();
            assert_eq!(
                recovered.reserve_protected(next, Hash256([6; 32]), next_safety),
                Err(KeystoreError::ConflictingSign)
            );
        } else {
            assert!(matches!(result, Err(KeystoreError::InvalidJournal)));
        }
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    }
}

#[test]
fn unexpected_slot_mutation_or_truncation_disables_even_identical_retries() {
    for truncate in [false, true] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let position = position(MAX_JOURNAL_RECORDS + 1);
        journal
            .reserve_protected(position, Hash256([6; 32]), safety())
            .unwrap();
        // Windows correctly blocks another handle's I/O; inject through the owned handle.
        let other = &mut journal.file;
        if truncate {
            other.set_len(MAX_ROLLOVER_JOURNAL_BYTES - 1).unwrap();
        } else {
            other
                .seek(SeekFrom::Start(MAX_PROTECTED_JOURNAL_BYTES + 8))
                .unwrap();
            other.write_all(&[255]).unwrap();
        }
        assert_eq!(
            journal.reserve_protected(position, Hash256([6; 32]), safety()),
            Err(KeystoreError::InvalidJournal)
        );
        assert_eq!(
            journal.reserve_protected(position, Hash256([6; 32]), safety()),
            Err(KeystoreError::DurabilityUnknown)
        );
    }
}

#[test]
fn rollover_child() {
    let Some(path) = std::env::var_os("ASTROLUNE_ROLLOVER_CHILD") else {
        return;
    };
    if std::env::var_os("ASTROLUNE_ROLLOVER_LOCKED").is_some() {
        assert_eq!(
            DurableSigner::open(path, context(), [1; 32]).unwrap_err(),
            KeystoreError::Locked
        );
        return;
    }
    let mut signer = DurableSigner::open(path, context(), [1; 32]).unwrap();
    let next = SigningPosition {
        round: signer.last_position().unwrap().round + 1,
        ..position(MAX_JOURNAL_RECORDS)
    };
    signer
        .sign_protected(&signer.key_handle(), next, Hash256([6; 32]), safety())
        .unwrap();
    std::process::exit(0);
}

#[test]
fn file_lock_and_protected_watermark_survive_rollover_and_abrupt_process_exit() {
    let fixture = Fixture::new();
    let alias = fixture.0.join("alias.journal");
    fs::hard_link(fixture.path(), &alias).unwrap();
    let child = || {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "journal::rollover_tests::rollover_child"])
            .env("ASTROLUNE_ROLLOVER_CHILD", &alias);
        command
    };
    for sequence in MAX_JOURNAL_RECORDS + 1..=MAX_JOURNAL_RECORDS + 3 {
        assert!(child().status().unwrap().success());
        let journal = fixture.open();
        assert_eq!(journal.last_position(), Some(position(sequence)));
        assert_eq!(journal.safety(), Some(safety()));
        assert!(
            child()
                .env("ASTROLUNE_ROLLOVER_LOCKED", "1")
                .status()
                .unwrap()
                .success()
        );
    }
}
