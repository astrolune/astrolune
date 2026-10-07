// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Cryptographic operations for consensus, transactions, and `AstroLune` ID.
//!
//! This crate provides domain-separated hashing, digital signature interfaces,
//! and Merkle tree construction. Hashing uses `RustCrypto` BLAKE2s-256 and
//! signatures use ed25519-dalek strict verification. The `MockCryptoProvider`
//! is only for tests and local demonstrations. VRF uses RFC 9381 ECVRF.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod blake2s;
pub mod ed25519_provider;
pub mod error;
pub mod vrf;

pub use blake2s::{Blake2sProvider, blake2s as blake2s_hash};
pub use ed25519_provider::Ed25519Keystore;
pub use error::CryptoError;
pub use vrf::{VrfInput, VrfRole, prove_vrf};

use types::{Hash256, ValidatorId};

/// An RFC 9381 ECVRF proof and its domain-hashed 256-bit output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VrfOutput {
    /// Pseudorandom output interpreted as a big-endian integer.
    pub randomness: Hash256,
    /// Exactly 80 canonical ECVRF-EDWARDS25519-SHA512-TAI proof bytes.
    pub proof: Vec<u8>,
}

/// Cryptographic operations required by the protocol.
pub trait CryptoProvider: Send + Sync {
    /// Hashes a domain tag and message using the canonical protocol hash.
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256;

    /// Verifies a validator signature.
    fn verify_signature(&self, signer: ValidatorId, message: &[u8], signature: &[u8; 64]) -> bool;

    /// Verifies a registered validator's VRF against a [`VrfInput::seed`] digest.
    fn verify_vrf(&self, validator: ValidatorId, seed: Hash256, output: &VrfOutput) -> bool;
}

/// Mock cryptographic provider for testing.
///
/// Signatures are valid if not all-zeros. Hashing uses XOR-fold. VRF always
/// returns true. Never use in production.
pub struct MockCryptoProvider;

impl MockCryptoProvider {
    /// Creates a new mock provider.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for MockCryptoProvider {
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256 {
        let mut h = [0u8; 32];
        for (i, byte) in domain.iter().chain(message.iter()).enumerate() {
            h[i % 32] ^= byte;
            h[(i + 13) % 32] = h[(i + 13) % 32].wrapping_add(*byte);
        }
        Hash256(h)
    }

    fn verify_signature(
        &self,
        _signer: ValidatorId,
        _message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        *signature != [0u8; 64]
    }

    fn verify_vrf(&self, _validator: ValidatorId, _seed: Hash256, _output: &VrfOutput) -> bool {
        true
    }
}

/// Computes a receipts root from receipt commitments using a binary Merkle tree.
///
/// Pairs of commitments are hashed together, and odd elements are promoted
/// unchanged. Empty input yields `Hash256::ZERO`.
#[must_use]
pub fn compute_receipts_root(commitments: &[Hash256]) -> Hash256 {
    merkle_root(commitments)
}

/// Computes a transactions root from transaction hashes.
///
/// Uses the same binary Merkle tree as [`compute_receipts_root`].
/// Empty input yields `Hash256::ZERO`.
#[must_use]
pub fn compute_transactions_root(tx_hashes: &[Hash256]) -> Hash256 {
    merkle_root(tx_hashes)
}

/// Builds a binary Merkle root from leaf hashes.
///
/// Algorithm:
/// 1. Empty input returns `Hash256::ZERO`.
/// 2. Single element returns itself.
/// 3. Adjacent pairs are combined with a domain-separated interior hash.
/// 4. Odd elements at any level are promoted without pairing.
/// 5. Repeat until one root remains.
fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    match leaves.len() {
        0 => Hash256::ZERO,
        1 => leaves[0],
        _ => {
            let mut current = leaves.to_vec();
            while current.len() > 1 {
                let mut next = Vec::with_capacity(current.len().div_ceil(2));
                for pair in current.chunks(2) {
                    if pair.len() == 2 {
                        // Interior node: domain-separate to prevent second-preimage
                        let mut data = [0u8; 69];
                        data[0] = 0x01; // interior node tag
                        data[1..33].copy_from_slice(&pair[0].0);
                        data[33..65].copy_from_slice(&pair[1].0);
                        let hash = blake2s::blake2s(&data);
                        next.push(hash);
                    } else {
                        // Odd element: promote unchanged to next level
                        next.push(pair[0]);
                    }
                }
                current = next;
            }
            current[0]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_hash_deterministic() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain", b"message");
        let h2 = provider.hash(b"domain", b"message");
        assert_eq!(h1, h2);
    }

    #[test]
    fn mock_hash_differs_by_domain() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain_a", b"message");
        let h2 = provider.hash(b"domain_b", b"message");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mock_hash_differs_by_message() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain", b"msg_a");
        let h2 = provider.hash(b"domain", b"msg_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mock_accepts_nonzero_signature() {
        let provider = MockCryptoProvider::new();
        let signer = ValidatorId::from_bytes([1u8; 32]);
        let sig = [0xFF; 64];
        assert!(provider.verify_signature(signer, b"msg", &sig));
    }

    #[test]
    fn mock_rejects_zero_signature() {
        let provider = MockCryptoProvider::new();
        let signer = ValidatorId::from_bytes([1u8; 32]);
        assert!(!provider.verify_signature(signer, b"msg", &[0u8; 64]));
    }

    #[test]
    fn blake2s_hash_deterministic() {
        let provider = Blake2sProvider::new();
        let h1 = provider.hash(b"domain", b"message");
        let h2 = provider.hash(b"domain", b"message");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2s_hash_differs_by_domain() {
        let provider = Blake2sProvider::new();
        let h1 = provider.hash(b"domain_a", b"message");
        let h2 = provider.hash(b"domain_b", b"message");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake2s_hash_differs_by_message() {
        let provider = Blake2sProvider::new();
        let h1 = provider.hash(b"domain", b"msg_a");
        let h2 = provider.hash(b"domain", b"msg_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake2s_hash_not_xor_fold() {
        let blake = Blake2sProvider::new();
        let mock = MockCryptoProvider::new();
        let h1 = blake.hash(b"domain", b"message");
        let h2 = mock.hash(b"domain", b"message");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake2s_raw_hash_deterministic() {
        let h1 = blake2s::blake2s(b"test input data");
        let h2 = blake2s::blake2s(b"test input data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2s_raw_hash_differs_by_input() {
        let h1 = blake2s::blake2s(b"input_a");
        let h2 = blake2s::blake2s(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn ed25519_sign_and_verify_roundtrip() {
        let mut keystore = Ed25519Keystore::new();
        let seed = [42u8; 32];
        let key_id = keystore
            .generate_key("test-validator".into(), seed)
            .expect("key generation should succeed");

        let message = b"test message for signing";
        let signature = keystore
            .sign(&key_id, message)
            .expect("signing should succeed");

        let pubkey = keystore.public_key(&key_id).expect("key should exist");
        assert!(
            Ed25519Keystore::verify_pubkey(&pubkey, message, &signature),
            "Ed25519 signature should verify"
        );
    }

    #[test]
    fn ed25519_signature_rejects_wrong_message() {
        let mut keystore = Ed25519Keystore::new();
        let key_id = keystore
            .generate_key("validator".into(), [1u8; 32])
            .expect("key gen");

        let message = b"correct message";
        let signature = keystore.sign(&key_id, message).expect("sign");

        let pubkey = keystore.public_key(&key_id).expect("pubkey");
        let wrong = b"wrong message";
        assert!(!Ed25519Keystore::verify_pubkey(&pubkey, wrong, &signature));
    }

    #[test]
    fn ed25519_different_keys_different_signatures() {
        let mut keystore = Ed25519Keystore::new();
        let key1 = keystore.generate_key("k1".into(), [1u8; 32]).expect("k1");
        let key2 = keystore.generate_key("k2".into(), [2u8; 32]).expect("k2");

        let msg = b"shared message";
        let sig1 = keystore.sign(&key1, msg).expect("sig1");
        let sig2 = keystore.sign(&key2, msg).expect("sig2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn receipts_root_empty() {
        assert_eq!(compute_receipts_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn receipts_root_single() {
        let receipt = types::ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: types::Resources {
                compute: 10,
                memory: 0,
                io: 0,
                bandwidth: 0,
            },
            output_root: Hash256([2u8; 32]),
        };
        let root = compute_receipts_root(&[receipt.commitment()]);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn receipts_root_order_matters() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let root_ab = compute_receipts_root(&[a, b]);
        let root_ba = compute_receipts_root(&[b, a]);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn transactions_root_empty() {
        assert_eq!(compute_transactions_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn transactions_root_deterministic() {
        let hashes = vec![Hash256([1u8; 32]), Hash256([2u8; 32]), Hash256([3u8; 32])];
        let r1 = compute_transactions_root(&hashes);
        let r2 = compute_transactions_root(&hashes);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_four_elements() {
        let leaves = vec![
            Hash256([1u8; 32]),
            Hash256([2u8; 32]),
            Hash256([3u8; 32]),
            Hash256([4u8; 32]),
        ];
        let root = compute_receipts_root(&leaves);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn merkle_root_three_elements() {
        let leaves = vec![Hash256([1u8; 32]), Hash256([2u8; 32]), Hash256([3u8; 32])];
        let root = compute_receipts_root(&leaves);
        assert_ne!(root, Hash256::ZERO);
    }
}
