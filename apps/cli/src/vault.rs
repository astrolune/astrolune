// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Encrypted wallet creation and bounded password input, never through argv.

use crate::{
    CliError,
    wallet::{read_raw_seed, write_new},
};
use keystore::vault::{MAX_VAULT_PASSWORD, encrypt_wallet_seed, generate_wallet_seed};
use std::{
    ffi::OsString,
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

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let (seed, output) = match (command, args) {
        ("wallet-create", [output]) => (generate_wallet_seed().map_err(error)?, output),
        ("wallet-encrypt", [source, output]) => (read_raw_seed(Path::new(source))?, output),
        _ => {
            return Err(error(
                "usage: wallet-create <new-vault> or wallet-encrypt <raw-seed> <new-vault>",
            ));
        }
    };
    if Path::new(output).exists() {
        return Err(error("output already exists"));
    }
    let password = password()?;
    let bytes = encrypt_wallet_seed(&seed, &password).map_err(error)?;
    write_new(Path::new(output), &bytes)?;
    let public_key = crypto::blake2s::ed25519_public_key(&seed);
    println!(
        "address: {}",
        transaction::address_from_public_key(&public_key)
    );
    println!("public_key: {}", types::Hash256(public_key));
    println!("encrypted_wallet: {}", Path::new(output).display());
    Ok(())
}
