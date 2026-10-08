// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached release-manifest signing, offline verification and rejection paths.

use keystore::release::{
    MAX_RELEASE_MANIFEST_BYTES, RELEASE_SIGNATURE_BYTES, ReleaseError, release_manifest_digest,
    sign_release_manifest, verify_release_manifest,
};

const MANIFEST: &[u8] = br#"{
  "archive_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "files": {"cli": "11", "daemon": "22"},
  "release": true
}
"#;

#[test]
fn verification_requires_the_explicitly_supplied_authority_and_exact_manifest_bytes() {
    let signature = sign_release_manifest(&[1; 32], MANIFEST).unwrap();
    assert_eq!(signature.len(), RELEASE_SIGNATURE_BYTES);
    let authority = crypto::blake2s::ed25519_public_key(&[1; 32]);
    let digest = verify_release_manifest(&authority, MANIFEST, &signature).unwrap();
    assert_eq!(digest, release_manifest_digest(MANIFEST).unwrap());
    // Signing is deterministic, so a reproduced build signs byte-identically.
    assert_eq!(
        sign_release_manifest(&[1; 32], MANIFEST).unwrap(),
        signature
    );
    // No authority is implied by the artifact: a different key never verifies.
    for other in [[2; 32], [0; 32], [255; 32]] {
        assert_eq!(
            verify_release_manifest(
                &crypto::blake2s::ed25519_public_key(&other),
                MANIFEST,
                &signature
            ),
            Err(ReleaseError::Authentication)
        );
    }
    // Flipping the release flag, or any other manifest byte, breaks the signature.
    let mut altered = MANIFEST.to_vec();
    let at = MANIFEST.len() - 10;
    altered[at] ^= 1;
    assert_eq!(
        verify_release_manifest(&authority, &altered, &signature),
        Err(ReleaseError::Authentication)
    );
    assert_eq!(
        verify_release_manifest(&authority, b"", &signature),
        Err(ReleaseError::InvalidFormat)
    );
    assert_eq!(
        verify_release_manifest(
            &authority,
            &vec![b'x'; MAX_RELEASE_MANIFEST_BYTES + 1],
            &signature
        ),
        Err(ReleaseError::InvalidFormat)
    );
}

#[test]
fn every_signature_truncation_and_single_byte_mutation_fails_closed() {
    let signature = sign_release_manifest(&[3; 32], MANIFEST).unwrap();
    let authority = crypto::blake2s::ed25519_public_key(&[3; 32]);
    for index in 0..signature.len() {
        for mask in [1u8, 128, 255] {
            let mut altered = signature.clone();
            altered[index] ^= mask;
            assert!(
                verify_release_manifest(&authority, MANIFEST, &altered).is_err(),
                "byte {index}"
            );
        }
    }
    for length in 0..signature.len() {
        assert_eq!(
            verify_release_manifest(&authority, MANIFEST, &signature[..length]),
            Err(ReleaseError::InvalidFormat)
        );
    }
    let mut trailing = signature;
    trailing.push(0);
    assert_eq!(
        verify_release_manifest(&authority, MANIFEST, &trailing),
        Err(ReleaseError::InvalidFormat)
    );
}
