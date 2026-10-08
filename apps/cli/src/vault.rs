// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Encrypted wallet and consensus custody with bounded password input, never through argv.

use crate::{
    CliError,
    wallet::{read_raw_seed, write_new},
};
use keystore::vault::{
    CONSENSUS_VAULT_BYTES, CONSENSUS_VAULT_PURPOSE, MAX_VAULT_PASSWORD, WALLET_VAULT_PURPOSE,
    decrypt_consensus_seed, encrypt_consensus_seed, encrypt_wallet_seed, generate_consensus_seed,
    generate_wallet_seed, vault_purpose,
};
use std::{
    ffi::OsString,
    fs::File,
    io::{BufRead, IsTerminal, Read},
    path::Path,
};
use zeroize::Zeroizing;

fn error(message: impl std::fmt::Display) -> CliError {
    CliError::Wallet(message.to_string())
}

pub(super) fn password() -> Result<Zeroizing<Vec<u8>>, CliError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(error(
            "supply the vault password through a private stdin pipe; terminal echo is not accepted",
        ));
    }
    let mut password = Zeroizing::new(Vec::with_capacity(MAX_VAULT_PASSWORD + 3));
    stdin
        .lock()
        .take(MAX_VAULT_PASSWORD as u64 + 3)
        .read_until(b'\n', &mut password)
        .map_err(error)?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if !(12..=MAX_VAULT_PASSWORD).contains(&password.len()) {
        return Err(error("vault password must be 12..1024 bytes"));
    }
    Ok(password)
}

/// Accepts a raw 32-byte consensus seed or a consensus vault, never a wallet vault.
pub(super) fn read_consensus_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CONSENSUS_VAULT_BYTES + 1));
    File::open(path)
        .map_err(error)?
        .take(CONSENSUS_VAULT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    match vault_purpose(&bytes) {
        Some(CONSENSUS_VAULT_PURPOSE) => {
            decrypt_consensus_seed(&bytes, &password()?).map_err(error)
        }
        Some(WALLET_VAULT_PURPOSE) => Err(error(
            "this is a wallet vault; consensus commands require a consensus vault or raw seed",
        )),
        Some(_) => Err(error("unsupported vault purpose")),
        None if bytes.starts_with(b"ALVAULT1") => Err(error("truncated or oversized vault")),
        None => Ok(Zeroizing::new(
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| error("expected a 32-byte raw seed or consensus vault"))?,
        )),
    }
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let (consensus, seed, output) = match (command, args) {
        ("wallet-create", [output]) => (false, generate_wallet_seed().map_err(error)?, output),
        ("wallet-encrypt", [source, output]) => (false, read_raw_seed(Path::new(source))?, output),
        ("consensus-vault-create", [output]) => {
            (true, generate_consensus_seed().map_err(error)?, output)
        }
        ("consensus-vault-encrypt", [source, output]) => {
            (true, read_raw_seed(Path::new(source))?, output)
        }
        _ => {
            return Err(error(
                "usage: wallet-create <new-vault>, wallet-encrypt <raw-seed> <new-vault>, consensus-vault-create <new-vault> or consensus-vault-encrypt <raw-seed> <new-vault>",
            ));
        }
    };
    if Path::new(output).exists() {
        return Err(error("output already exists"));
    }
    let password = password()?;
    let bytes = if consensus {
        encrypt_consensus_seed(&seed, &password).map_err(error)?
    } else {
        encrypt_wallet_seed(&seed, &password).map_err(error)?
    };
    write_new(Path::new(output), &bytes)?;
    let public_key = crypto::blake2s::ed25519_public_key(&seed);
    if consensus {
        println!(
            "validator: {:?}",
            types::ValidatorId(crypto::blake2s::blake2s(&public_key).0)
        );
        println!("public_key: {}", types::Hash256(public_key));
        println!("encrypted_consensus_key: {}", Path::new(output).display());
        println!("journal: provision separately with init-validator");
    } else {
        println!(
            "address: {}",
            transaction::address_from_public_key(&public_key)
        );
        println!("public_key: {}", types::Hash256(public_key));
        println!("encrypted_wallet: {}", Path::new(output).display());
    }
    Ok(())
}
