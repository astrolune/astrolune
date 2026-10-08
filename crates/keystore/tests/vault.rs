// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Vault format, independent randomness, authentication and bounded work parameters.

use keystore::vault::{
    CONSENSUS_VAULT_BYTES, CONSENSUS_VAULT_PURPOSE, VaultError, WALLET_VAULT_BYTES,
    WALLET_VAULT_PURPOSE, decrypt_consensus_seed, decrypt_wallet_seed, encrypt_consensus_seed,
    encrypt_wallet_seed, generate_consensus_seed, generate_wallet_seed, vault_purpose,
};

#[test]
fn original_provider_vault_remains_readable_after_dependency_upgrades() {
    let bytes = include_bytes!("fixtures/wallet-v1.bin");
    let seed = decrypt_wallet_seed(bytes, b"astrolune-vault-fixture-v1").unwrap();
    assert_eq!(
        *seed,
        [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]
    );
}

#[test]
fn a_consensus_vault_is_never_interchangeable_with_a_wallet_vault() {
    let password = b"correct horse battery staple";
    let wallet = include_bytes!("fixtures/wallet-v1.bin");
    assert_eq!(vault_purpose(wallet), Some(WALLET_VAULT_PURPOSE));
    assert_eq!(vault_purpose(&wallet[..64]), None);
    assert_eq!(vault_purpose(b"not a vault at all"), None);
    let seed = generate_consensus_seed().unwrap();
    assert_ne!(*seed, *generate_wallet_seed().unwrap());
    let vault = encrypt_consensus_seed(&seed, password).unwrap();
    assert_eq!(vault.len(), CONSENSUS_VAULT_BYTES);
    assert_eq!(CONSENSUS_VAULT_BYTES, WALLET_VAULT_BYTES);
    assert_eq!(vault_purpose(&vault), Some(CONSENSUS_VAULT_PURPOSE));
    assert_eq!(*decrypt_consensus_seed(&vault, password).unwrap(), *seed);
    // The authenticated purpose byte is checked before any key derivation work.
    assert_eq!(
        decrypt_wallet_seed(&vault, password).unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        decrypt_consensus_seed(wallet, b"astrolune-vault-fixture-v1").unwrap_err(),
        VaultError::InvalidFormat
    );
    for offset in 0..24 {
        let mut changed = vault.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decrypt_consensus_seed(&changed, password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    for length in 0..vault.len() {
        assert_eq!(
            decrypt_consensus_seed(&vault[..length], password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    assert_eq!(
        encrypt_consensus_seed(&seed, b"short").unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        encrypt_consensus_seed(&seed, &[1; 1025]).unwrap_err(),
        VaultError::InvalidFormat
    );
}

#[test]
fn random_vaults_round_trip_and_authenticate_every_header_class() {
    let password = b"correct horse battery staple";
    let seed = generate_wallet_seed().unwrap();
    assert_ne!(*seed, *generate_wallet_seed().unwrap());
    let first = encrypt_wallet_seed(&seed, password).unwrap();
    let second = encrypt_wallet_seed(&seed, password).unwrap();
    assert_eq!(first.len(), WALLET_VAULT_BYTES);
    assert_ne!(&first[24..64], &second[24..64]);
    assert_ne!(&first[96..], &second[96..]);
    assert_eq!(*decrypt_wallet_seed(&first, password).unwrap(), *seed);
    assert_eq!(
        decrypt_wallet_seed(&first, b"different long password").unwrap_err(),
        VaultError::Authentication
    );
    for offset in [24, 40, 64, 96, 143] {
        let mut changed = first.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decrypt_wallet_seed(&changed, password).unwrap_err(),
            VaultError::Authentication
        );
    }
    for offset in 0..24 {
        let mut changed = first.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decrypt_wallet_seed(&changed, password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    for length in 0..first.len() {
        assert_eq!(
            decrypt_wallet_seed(&first[..length], password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    let mut trailing = first;
    trailing.push(0);
    assert_eq!(
        decrypt_wallet_seed(&trailing, password).unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        encrypt_wallet_seed(&seed, b"short").unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        encrypt_wallet_seed(&seed, &[1; 1025]).unwrap_err(),
        VaultError::InvalidFormat
    );
}
