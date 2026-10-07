// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Standard vectors and negative signature-verification cases.

use crypto::blake2s::{blake2s, domain_hash, ed25519_public_key, ed25519_sign, ed25519_verify};
use crypto::{Blake2sProvider, CryptoError, CryptoProvider, Ed25519Keystore, VrfOutput};
use types::{Hash256, ValidatorId};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn blake2s_standard_vectors_and_block_boundaries() {
    assert_eq!(
        blake2s(b"abc").0,
        hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    );
    for (length, expected) in [
        (
            0,
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        ),
        (
            63,
            "e57cb79487dd57902432b250733813bd96a84efce59f650fac26e6696aefafc3",
        ),
        (
            64,
            "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e",
        ),
        (
            65,
            "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472",
        ),
        (
            128,
            "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796",
        ),
    ] {
        let input: Vec<u8> = (0..length).collect();
        assert_eq!(blake2s(&input).0, hex(expected));
    }
}

#[test]
fn rfc8032_ed25519_empty_message() {
    let secret = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    assert_eq!(ed25519_public_key(&secret), public);
    assert_eq!(ed25519_sign(&secret, b""), signature);
    assert!(ed25519_verify(&public, b"", &signature));
    assert!(!ed25519_verify(&public, b"changed", &signature));
    for position in 0..signature.len() {
        let mut altered = signature;
        altered[position] ^= 1;
        assert!(!ed25519_verify(&public, b"", &altered));
    }
}

#[test]
fn rejects_weak_keys_and_noncanonical_scalars() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut forged = [0; 64];
    forged[0] = 1;
    assert!(!ed25519_verify(&identity, b"forged", &forged));
    assert_eq!(
        Blake2sProvider::new().register_validator(identity),
        Err(CryptoError::InvalidPublicKey)
    );

    let public = ed25519_public_key(&[7; 32]);
    let mut signature = ed25519_sign(&[7; 32], b"message");
    signature[32..].fill(0xff);
    assert!(!ed25519_verify(&public, b"message", &signature));
}

#[test]
fn provider_requires_registered_identity_and_valid_signature() {
    let mut keystore = Ed25519Keystore::new();
    let key = keystore.generate_key("validator".into(), [7; 32]).unwrap();
    let id = keystore.validator_id(&key).unwrap();
    let signature = keystore.sign(&key, b"vote").unwrap();
    let mut provider = Blake2sProvider::new();
    assert!(!provider.verify_signature(id, b"vote", &signature));
    assert_eq!(
        provider.register_validator(keystore.public_key(&key).unwrap()),
        Ok(id)
    );
    assert!(provider.verify_signature(id, b"vote", &signature));
    assert!(!provider.verify_signature(id, b"another vote", &signature));
    assert!(!provider.verify_signature(id, b"vote", &[0xff; 64]));
    assert!(!provider.verify_signature(ValidatorId::ZERO, b"vote", &signature));
    assert!(!provider.verify_vrf(
        id,
        Hash256::ZERO,
        &VrfOutput {
            randomness: Hash256::ZERO,
            proof: vec![1],
        }
    ));
}

#[test]
fn domain_message_boundaries_are_unambiguous() {
    assert_ne!(domain_hash(b"a", b"bc"), domain_hash(b"ab", b"c"));
    assert_ne!(domain_hash(b"", b"abc"), domain_hash(b"abc", b""));
}
