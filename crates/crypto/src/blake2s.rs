// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Standard BLAKE2s-256 hashing and strict Ed25519 verification.

use std::collections::BTreeMap;

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use types::{Hash256, ValidatorId};

/// Computes the standard unkeyed BLAKE2s-256 digest.
#[must_use]
pub fn blake2s(data: &[u8]) -> Hash256 {
    Hash256(Blake2s256::digest(data).into())
}

pub use types::hash::domain_hash;

/// Derives deterministic key material from a high-entropy seed and context.
///
/// This is not a password-hardening function.
#[must_use]
pub fn derive_key(seed: &[u8], domain: &str) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(b"astrolune.key.derive.v1.");
    hash.update((domain.len() as u64).to_le_bytes());
    hash.update(domain.as_bytes());
    hash.update((seed.len() as u64).to_le_bytes());
    hash.update(seed);
    hash.finalize().into()
}

/// Derives an Ed25519 public key from a 32-byte secret seed.
#[must_use]
pub fn ed25519_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

/// Signs a message using Ed25519 and a 32-byte secret seed.
#[must_use]
pub fn ed25519_sign(secret_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(secret_key).sign(message).to_bytes()
}

/// Verifies Ed25519 with weak-key and signature-malleability rejection.
#[must_use]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
        key.to_edwards().compress().to_bytes() == *public_key
            && key
                .verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
    })
}

/// BLAKE2s hashing and signature verification against registered validator keys.
///
/// VRF verification uses canonical RFC 9381 ECVRF proofs and the same key registry.
#[derive(Default)]
pub struct Blake2sProvider {
    keys: BTreeMap<ValidatorId, VerifyingKey>,
}

impl Blake2sProvider {
    /// Creates a provider without registered validators.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a public key under its BLAKE2s-256 validator identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed or weak Ed25519 keys.
    pub fn register_validator(
        &mut self,
        public_key: [u8; 32],
    ) -> Result<ValidatorId, crate::CryptoError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| crate::CryptoError::InvalidPublicKey)?;
        if key.is_weak() || key.to_edwards().compress().to_bytes() != public_key {
            return Err(crate::CryptoError::InvalidPublicKey);
        }
        let id = ValidatorId(blake2s(&public_key).0);
        self.keys.insert(id, key);
        Ok(id)
    }

    /// Returns the canonical registered public key of a validator, if registered.
    ///
    /// Registration already rejected malformed, weak and non-canonically encoded
    /// keys, so for a registered identity
    /// `ed25519_verify(&registered_key(id).unwrap(), message, signature)` decides
    /// exactly as [`CryptoProvider::verify_signature`] does. Callers that batch
    /// independent verifications use this to obtain the key bytes.
    #[must_use]
    pub fn registered_key(&self, validator: ValidatorId) -> Option<[u8; 32]> {
        self.keys.get(&validator).map(VerifyingKey::to_bytes)
    }
}

impl crate::CryptoProvider for Blake2sProvider {
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256 {
        domain_hash(domain, message)
    }

    fn verify_signature(&self, signer: ValidatorId, message: &[u8], signature: &[u8; 64]) -> bool {
        self.keys.get(&signer).is_some_and(|key| {
            key.verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
        })
    }

    fn verify_vrf(&self, validator: ValidatorId, seed: Hash256, output: &crate::VrfOutput) -> bool {
        self.keys
            .get(&validator)
            .is_some_and(|key| crate::vrf::verify_vrf(&key.to_bytes(), seed, output).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2s_deterministic() {
        let h1 = blake2s(b"test input");
        let h2 = blake2s(b"test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2s_differs_by_input() {
        let h1 = blake2s(b"input_a");
        let h2 = blake2s(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake2s_empty_input() {
        let h = blake2s(b"");
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn blake2s_large_input() {
        let data = vec![0xAB; 1024];
        let h = blake2s(&data);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn blake2s_exact_block_boundary() {
        let data = [0x42; 64];
        let h1 = blake2s(&data);
        let data2 = [0x42; 65];
        let h2 = blake2s(&data2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_hash_separates_domains() {
        let h1 = domain_hash(b"transaction", b"payload");
        let h2 = domain_hash(b"block_header", b"payload");
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_hash_deterministic() {
        let h1 = domain_hash(b"test", b"data");
        let h2 = domain_hash(b"test", b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_key(b"seed", "domain");
        let k2 = derive_key(b"seed", "domain");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_varies_by_domain() {
        let k1 = derive_key(b"seed", "consensus");
        let k2 = derive_key(b"seed", "network");
        assert_ne!(k1, k2);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let secret = [42u8; 32];
        let pubkey = ed25519_public_key(&secret);
        let message = b"hello astrolune";
        let sig = ed25519_sign(&secret, message);
        assert!(ed25519_verify(&pubkey, message, &sig));
    }

    #[test]
    fn ed25519_rejects_wrong_message() {
        let secret = [1u8; 32];
        let pubkey = ed25519_public_key(&secret);
        let sig = ed25519_sign(&secret, b"correct");
        assert!(!ed25519_verify(&pubkey, b"wrong", &sig));
    }

    #[test]
    fn ed25519_rejects_wrong_key() {
        let secret = [1u8; 32];
        let wrong_pubkey = [99u8; 32];
        let sig = ed25519_sign(&secret, b"message");
        assert!(!ed25519_verify(&wrong_pubkey, b"message", &sig));
    }

    #[test]
    fn ed25519_different_keys_different_sigs() {
        let msg = b"shared message";
        let sig1 = ed25519_sign(&[1u8; 32], msg);
        let sig2 = ed25519_sign(&[2u8; 32], msg);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn registered_key_round_trips_and_decides_like_the_provider() {
        use crate::CryptoProvider;
        let mut provider = Blake2sProvider::new();
        let public = ed25519_public_key(&[9u8; 32]);
        let id = provider.register_validator(public).expect("strong key");
        assert_eq!(provider.registered_key(id), Some(public));
        assert_eq!(provider.registered_key(ValidatorId::ZERO), None);
        let signature = ed25519_sign(&[9u8; 32], b"vote");
        for (message, candidate) in [
            (&b"vote"[..], signature),
            (&b"vote"[..], [0xFF; 64]),
            (&b"other"[..], signature),
        ] {
            assert_eq!(
                ed25519_verify(&public, message, &candidate),
                provider.verify_signature(id, message, &candidate)
            );
        }
    }
}
