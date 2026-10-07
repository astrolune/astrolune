// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fixed-cost encrypted wallet seed files with authenticated headers.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const HEADER: usize = 96;
/// Exact vault-v1 file length, including its authentication tag.
pub const WALLET_VAULT_BYTES: usize = HEADER + 32 + 16;
/// Maximum password bytes; passwords are opaque bytes without Unicode normalization.
pub const MAX_VAULT_PASSWORD: usize = 1024;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;

/// Vault failure; authentication failures never reveal derived key or seed data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    /// Unsupported framing, parameters, purpose or password bounds.
    InvalidFormat,
    /// Password or authenticated ciphertext/header is incorrect.
    Authentication,
    /// Operating system randomness or key derivation failed.
    Provider,
}
impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid wallet vault format or password length",
            Self::Authentication => "wallet vault authentication failed",
            Self::Provider => "wallet vault cryptographic provider failed",
        })
    }
}
impl std::error::Error for VaultError {}

/// Generates a wallet seed from the operating system CSPRNG.
///
/// # Errors
/// Fails closed if operating system entropy is unavailable.
pub fn generate_wallet_seed() -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| VaultError::Provider)?;
    Ok(seed)
}

/// Encrypts a wallet seed using Argon2id v19 and XChaCha20-Poly1305.
///
/// # Errors
/// Requires 12..1024 password bytes and successful OS entropy/key derivation.
pub fn encrypt_wallet_seed(seed: &[u8; 32], password: &[u8]) -> Result<Vec<u8>, VaultError> {
    let mut bytes = vec![0; WALLET_VAULT_BYTES];
    bytes[..8].copy_from_slice(b"ALVAULT1");
    bytes[8] = 1; // wallet purpose, never a consensus journal
    bytes[9] = 1; // fixed KDF/AEAD profile
    bytes[12..16].copy_from_slice(&MEMORY_KIB.to_le_bytes());
    bytes[16..20].copy_from_slice(&ITERATIONS.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    getrandom::fill(&mut bytes[24..64]).map_err(|_| VaultError::Provider)?;
    bytes[64..HEADER].copy_from_slice(&crypto::blake2s::ed25519_public_key(seed));
    let key = derive(password, &bytes[24..40])?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut secret = Zeroizing::new(*seed);
    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(&bytes[40..64]).map_err(|_| VaultError::InvalidFormat)?,
            &bytes[..HEADER],
            secret.as_mut_slice().into(),
        )
        .map_err(|_| VaultError::Provider)?;
    bytes[HEADER..HEADER + 32].copy_from_slice(secret.as_ref());
    bytes[HEADER + 32..].copy_from_slice(&tag);
    Ok(bytes)
}

/// Unlocks only the fixed wallet format. Validates all work parameters before the KDF.
///
/// # Errors
/// Rejects unknown formats, weak/oversized passwords, bad tags and inconsistent public keys.
pub fn decrypt_wallet_seed(
    bytes: &[u8],
    password: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if bytes.len() != WALLET_VAULT_BYTES
        || &bytes[..8] != b"ALVAULT1"
        || bytes[8..12] != [1, 1, 0, 0]
        || bytes[12..16] != MEMORY_KIB.to_le_bytes()
        || bytes[16..20] != ITERATIONS.to_le_bytes()
        || bytes[20..24] != 1u32.to_le_bytes()
    {
        return Err(VaultError::InvalidFormat);
    }
    let key = derive(password, &bytes[24..40])?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes[HEADER..HEADER + 32]);
    cipher
        .decrypt_inout_detached(
            <&XNonce>::try_from(&bytes[40..64]).map_err(|_| VaultError::InvalidFormat)?,
            &bytes[..HEADER],
            seed.as_mut_slice().into(),
            <&Tag>::try_from(&bytes[HEADER + 32..]).map_err(|_| VaultError::InvalidFormat)?,
        )
        .map_err(|_| VaultError::Authentication)?;
    if crypto::blake2s::ed25519_public_key(&seed) != bytes[64..HEADER] {
        return Err(VaultError::Authentication);
    }
    Ok(seed)
}

fn derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if !(12..=MAX_VAULT_PASSWORD).contains(&password.len()) {
        return Err(VaultError::InvalidFormat);
    }
    let params =
        Params::new(MEMORY_KIB, ITERATIONS, 1, Some(32)).map_err(|_| VaultError::Provider)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // Use the explicit-memory API: zeroize the entire KDF workspace on every exit.
    let mut memory = Zeroizing::new(vec![Block::default(); MEMORY_KIB as usize]);
    let mut key = Zeroizing::new([0; 32]);
    kdf.hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|_| VaultError::Provider)?;
    Ok(key)
}
