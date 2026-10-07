// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Admission authorization must not consume, weaken or bypass BFT safety slots.

#![allow(clippy::too_many_lines)]

use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
use keystore::{
    DurableSigner, KeystoreError, SigningContext, SigningPosition, SigningSafety,
    admission::AdmissionIntent,
};
use types::{Hash256, ValidatorId};

#[test]
fn typed_approval_respects_namespace_watermark_and_preserves_journal() {
    let directory = std::env::temp_dir().join(format!(
        "astrolune-admission-keystore-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let journal = directory.join("protected");
    let context = SigningContext {
        chain_id: 7,
        genesis: Hash256([7; 32]),
    };
    let signer = DurableSigner::create_protected(&journal, context, [1; 32]).unwrap();
    let intent = AdmissionIntent {
        chain_id: 7,
        genesis: context.genesis,
        height: 3,
        parent: Hash256([2; 32]),
        committee_root: Hash256([3; 32]),
        public_key: ed25519_public_key(&[99; 32]),
    };
    let consent = ed25519_sign(&[99; 32], &intent.consent_hash().0);
    let voter = ValidatorId(crypto::blake2s_hash(&signer.public_key()).0);
    drop(signer);
    let before = std::fs::read(&journal).unwrap();
    let signer = DurableSigner::open(&journal, context, [1; 32]).unwrap();
    let signature = signer.approve_admission(&intent, &consent).unwrap();
    assert!(ed25519_verify(
        &signer.public_key(),
        &intent.approval_hash(&consent, voter).0,
        &signature
    ));
    assert!(!ed25519_verify(
        &signer.public_key(),
        &intent.consent_hash().0,
        &signature
    ));
    assert_eq!(
        signature,
        signer.approve_admission(&intent, &consent).unwrap()
    );
    assert_eq!(signer.last_position(), None);
    drop(signer);
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    let mut signer = DurableSigner::open(&journal, context, [1; 32]).unwrap();
    let mut corrupt = consent;
    corrupt[0] ^= 1;
    assert_eq!(
        signer.approve_admission(&intent, &corrupt),
        Err(KeystoreError::InvalidSafety)
    );
    for wrong in [
        AdmissionIntent {
            chain_id: 8,
            ..intent
        },
        AdmissionIntent {
            genesis: Hash256([9; 32]),
            ..intent
        },
    ] {
        let consent = ed25519_sign(&[99; 32], &wrong.consent_hash().0);
        assert_eq!(
            signer.approve_admission(&wrong, &consent),
            Err(KeystoreError::ContextMismatch)
        );
    }
    for wrong in [
        AdmissionIntent {
            height: 0,
            ..intent
        },
        AdmissionIntent {
            height: u64::MAX,
            ..intent
        },
        AdmissionIntent {
            public_key: [0; 32],
            ..intent
        },
    ] {
        assert!(wrong.validate().is_err());
        assert!(signer.approve_admission(&wrong, &consent).is_err());
    }
    let safety = SigningSafety {
        committee_root: intent.committee_root,
        locked: None,
    };
    signer
        .sign_protected(
            &signer.key_handle(),
            SigningPosition {
                height: 3,
                round: 0,
                phase: keystore::PREVOTE_PHASE,
            },
            Hash256([5; 32]),
            safety,
        )
        .unwrap();
    assert_eq!(
        signature,
        signer.approve_admission(&intent, &consent).unwrap()
    );
    let wrong = AdmissionIntent {
        committee_root: Hash256([44; 32]),
        ..intent
    };
    assert_eq!(
        signer.approve_admission(&wrong, &ed25519_sign(&[99; 32], &wrong.consent_hash().0)),
        Err(KeystoreError::InvalidSafety)
    );
    drop(signer);
    let mut signer = DurableSigner::open(&journal, context, [1; 32]).unwrap();
    assert_eq!(
        signature,
        signer.approve_admission(&intent, &consent).unwrap()
    );
    signer
        .sign_protected(
            &signer.key_handle(),
            SigningPosition {
                height: 4,
                round: 0,
                phase: keystore::PREVOTE_PHASE,
            },
            Hash256([6; 32]),
            safety,
        )
        .unwrap();
    assert_eq!(
        signer.approve_admission(&intent, &consent),
        Err(KeystoreError::StalePosition)
    );
    drop(signer);
    let raw = DurableSigner::create(directory.join("raw"), context, [1; 32]).unwrap();
    assert_eq!(
        raw.approve_admission(&intent, &consent),
        Err(KeystoreError::InvalidSafety)
    );
    drop(raw);
    let canonical = directory.canonicalize().unwrap();
    assert_eq!(
        canonical.parent(),
        Some(std::env::temp_dir().canonicalize().unwrap().as_path())
    );
    std::fs::remove_dir_all(canonical).unwrap();
}
