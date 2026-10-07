// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! In-memory Ed25519 key management and signing operations.
//!
//! Uses ed25519-dalek signing keys. Signing positions are retained in memory;
//! durable anti-equivocation across restarts requires a separate journal.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use types::ValidatorId;
use zeroize::Zeroizing;

use crate::blake2s::{blake2s, derive_key, ed25519_verify};
use crate::error::CryptoError;

/// A unique identifier for a key in the keystore.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyId(String);

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Metadata stored alongside each key.
pub struct KeyEntry {
    signing_key: SigningKey,
    /// 32-byte public key derived from the secret key.
    public_key: [u8; 32],
    /// Validator identity derived deterministically from the public key.
    validator_id: ValidatorId,
    /// Human-readable label for the key.
    #[allow(dead_code)]
    label: String,
}

/// Ed25519 keystore with deterministic key generation.
///
/// Keys are derived from seeds using Blake2s-based key derivation. Each key
/// is associated with a validator identity and a human-readable label.
/// The keystore tracks signing positions to prevent equivocation.
pub struct Ed25519Keystore {
    keys: BTreeMap<String, KeyEntry>,
    /// Maps (`key_id`, height, round, phase) to the signed message hash.
    /// Prevents signing different messages at the same position.
    signed_positions: BTreeMap<(String, u64, u32, u32), [u8; 32]>,
}

impl Ed25519Keystore {
    /// Creates an empty keystore.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            signed_positions: BTreeMap::new(),
        }
    }

    /// Generates a new key from a deterministic seed and registers it.
    ///
    /// The key ID must not already exist. The seed is combined with the key ID
    /// using Blake2s to produce the secret key material.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DuplicateKey`] if the key ID already exists.
    pub fn generate_key(&mut self, key_id: String, seed: [u8; 32]) -> Result<KeyId, CryptoError> {
        if self.keys.contains_key(&key_id) {
            return Err(CryptoError::DuplicateKey);
        }

        let seed = Zeroizing::new(seed);
        let secret_key = Zeroizing::new(derive_key(seed.as_ref(), &format!("ed25519.{key_id}")));
        let signing_key = SigningKey::from_bytes(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes();
        let vid_hash = blake2s(&public_key);
        let validator_id = ValidatorId::from_bytes(*vid_hash.as_bytes());

        let entry = KeyEntry {
            signing_key,
            public_key,
            validator_id,
            label: key_id.clone(),
        };

        self.keys.insert(key_id.clone(), entry);
        Ok(KeyId(key_id))
    }

    /// Returns the public key for a registered key ID.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyNotFound`] if the key ID is not registered.
    pub fn public_key(&self, key_id: &KeyId) -> Result<[u8; 32], CryptoError> {
        let entry = self.keys.get(&key_id.0).ok_or(CryptoError::KeyNotFound)?;
        Ok(entry.public_key)
    }

    /// Returns the validator identity for a registered key ID.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyNotFound`] if the key ID is not registered.
    pub fn validator_id(&self, key_id: &KeyId) -> Result<ValidatorId, CryptoError> {
        let entry = self.keys.get(&key_id.0).ok_or(CryptoError::KeyNotFound)?;
        Ok(entry.validator_id)
    }

    /// Signs a message with the specified key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyNotFound`] if the key ID is not registered.
    pub fn sign(&self, key_id: &KeyId, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let entry = self.keys.get(&key_id.0).ok_or(CryptoError::KeyNotFound)?;
        Ok(entry.signing_key.sign(message).to_bytes())
    }

    /// Produces a context-bound VRF proof without exposing the signing seed.
    pub fn prove_vrf(
        &self,
        key_id: &KeyId,
        input: crate::VrfInput,
    ) -> Result<crate::VrfOutput, CryptoError> {
        let entry = self.keys.get(&key_id.0).ok_or(CryptoError::KeyNotFound)?;
        let secret = Zeroizing::new(entry.signing_key.to_bytes());
        crate::prove_vrf(&secret, input)
    }

    /// Signs a consensus message at a specific position with equivocation protection.
    ///
    /// The position is (height, round, phase). Once a message is signed at a
    /// position, signing a different message at the same position fails.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyNotFound`] or [`CryptoError::EquivocationDetected`].
    pub fn sign_at_position(
        &mut self,
        key_id: &KeyId,
        height: u64,
        round: u32,
        phase: u32,
        message_hash: [u8; 32],
    ) -> Result<[u8; 64], CryptoError> {
        let pos_key = (key_id.0.clone(), height, round, phase);

        // Check for equivocation: different message at same position
        if let Some(existing) = self.signed_positions.get(&pos_key)
            && *existing != message_hash
        {
            return Err(CryptoError::EquivocationDetected);
        }

        let entry = self.keys.get(&key_id.0).ok_or(CryptoError::KeyNotFound)?;
        let signature = entry.signing_key.sign(&message_hash).to_bytes();
        self.signed_positions.insert(pos_key, message_hash);
        Ok(signature)
    }

    /// Verifies a signature against a public key and message.
    ///
    /// This is a static method that does not require keystore state.
    #[must_use]
    pub fn verify_pubkey(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        ed25519_verify(public_key, message, signature)
    }

    /// Verifies a signature against a validator identity.
    ///
    /// Looks up the public key by scanning all registered keys for the
    /// matching validator ID.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyNotFound`] if no key matches the validator ID.
    pub fn verify(
        &self,
        validator_id: ValidatorId,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, CryptoError> {
        for entry in self.keys.values() {
            if entry.validator_id == validator_id {
                return Ok(ed25519_verify(&entry.public_key, message, signature));
            }
        }
        Err(CryptoError::KeyNotFound)
    }

    /// Returns the number of registered keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if no keys are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for Ed25519Keystore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_lookup() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks
            .generate_key("test-key".into(), [1u8; 32])
            .expect("generate");
        assert_eq!(kid.as_ref(), "test-key");
        assert_eq!(ks.len(), 1);
        assert!(!ks.is_empty());
    }

    #[test]
    fn duplicate_key_rejected() {
        let mut ks = Ed25519Keystore::new();
        ks.generate_key("k1".into(), [1u8; 32]).expect("k1");
        assert_eq!(
            ks.generate_key("k1".into(), [2u8; 32]),
            Err(CryptoError::DuplicateKey)
        );
    }

    #[test]
    fn public_key_is_valid_32_bytes() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("k".into(), [42u8; 32]).expect("gen");
        let pubkey = ks.public_key(&kid).expect("pubkey");
        // Public key should not be all zeros
        assert_ne!(pubkey, [0u8; 32]);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("signer".into(), [7u8; 32]).expect("gen");
        let vid = ks.validator_id(&kid).expect("vid");

        let message = b"test message";
        let sig = ks.sign(&kid, message).expect("sign");

        let result = ks.verify(vid, message, &sig).expect("verify");
        assert!(result);
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("v".into(), [3u8; 32]).expect("gen");
        let vid = ks.validator_id(&kid).expect("vid");

        let sig = ks.sign(&kid, b"correct").expect("sign");
        assert!(!ks.verify(vid, b"wrong", &sig).expect("verify"));
    }

    #[test]
    fn sign_at_position_allows_same_message() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("pos".into(), [5u8; 32]).expect("gen");
        let msg = [42u8; 32];

        let sig1 = ks.sign_at_position(&kid, 1, 0, 0, msg).expect("first sign");
        let sig2 = ks
            .sign_at_position(&kid, 1, 0, 0, msg)
            .expect("re-sign same msg");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_at_position_rejects_equivocation() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("eq".into(), [9u8; 32]).expect("gen");

        let msg1 = [1u8; 32];
        let msg2 = [2u8; 32];

        ks.sign_at_position(&kid, 1, 0, 0, msg1).expect("first");
        assert_eq!(
            ks.sign_at_position(&kid, 1, 0, 0, msg2),
            Err(CryptoError::EquivocationDetected)
        );
    }

    #[test]
    fn different_positions_allow_different_messages() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("diff".into(), [11u8; 32]).expect("gen");

        ks.sign_at_position(&kid, 1, 0, 0, [1u8; 32])
            .expect("pos a");
        ks.sign_at_position(&kid, 1, 0, 1, [2u8; 32])
            .expect("pos b");
    }

    #[test]
    fn verify_rejects_unknown_validator() {
        let ks = Ed25519Keystore::new();
        let unknown = ValidatorId::from_bytes([99u8; 32]);
        assert_eq!(
            ks.verify(unknown, b"msg", &[0u8; 64]),
            Err(CryptoError::KeyNotFound)
        );
    }

    #[test]
    fn different_keys_different_pubkeys() {
        let mut ks = Ed25519Keystore::new();
        let k1 = ks.generate_key("a".into(), [1u8; 32]).expect("a");
        let k2 = ks.generate_key("b".into(), [2u8; 32]).expect("b");

        let pk1 = ks.public_key(&k1).expect("pk1");
        let pk2 = ks.public_key(&k2).expect("pk2");
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn different_keys_different_validator_ids() {
        let mut ks = Ed25519Keystore::new();
        let k1 = ks.generate_key("a".into(), [1u8; 32]).expect("a");
        let k2 = ks.generate_key("b".into(), [2u8; 32]).expect("b");

        let vid1 = ks.validator_id(&k1).expect("vid1");
        let vid2 = ks.validator_id(&k2).expect("vid2");
        assert_ne!(vid1, vid2);
    }

    #[test]
    fn verify_pubkey_static_method() {
        let mut ks = Ed25519Keystore::new();
        let kid = ks.generate_key("static".into(), [42u8; 32]).expect("gen");
        let pubkey = ks.public_key(&kid).expect("pubkey");
        let msg = b"static verify test";
        let sig = ks.sign(&kid, msg).expect("sign");

        assert!(Ed25519Keystore::verify_pubkey(&pubkey, msg, &sig));
    }

    #[test]
    fn default_is_empty() {
        let ks = Ed25519Keystore::default();
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
    }
}
