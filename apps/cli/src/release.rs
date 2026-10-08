// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached release-manifest signing and offline verification against a supplied authority.

use crate::{CliError, vault::read_consensus_seed, wallet::write_new};
use keystore::release::{
    MAX_RELEASE_MANIFEST_BYTES, RELEASE_SIGNATURE_BYTES, sign_release_manifest,
    verify_release_manifest,
};
use std::{ffi::OsString, fs::File, io::Read, path::Path};
use types::Hash256;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

fn read(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > maximum {
        return Err(error(format!("{label} exceeds its size limit")));
    }
    Ok(bytes)
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let [manifest_path, key, signature_path] = args else {
        return Err(error(
            "usage: release-sign <manifest> <seed-or-vault> <new-signature> or verify-release <manifest> <authority-public-key> <signature>",
        ));
    };
    let manifest = read(
        Path::new(manifest_path),
        MAX_RELEASE_MANIFEST_BYTES,
        "release manifest",
    )?;
    let (authority, digest) = if command == "release-sign" {
        if Path::new(signature_path).exists() {
            return Err(error("output already exists"));
        }
        let seed = read_consensus_seed(Path::new(key))?;
        let signature = sign_release_manifest(&seed, &manifest).map_err(error)?;
        write_new(Path::new(signature_path), &signature)?;
        let authority = crypto::blake2s::ed25519_public_key(&seed);
        (
            authority,
            verify_release_manifest(&authority, &manifest, &signature).map_err(error)?,
        )
    } else {
        // Verification never adopts the key embedded in the artifact: the authority
        // must be supplied explicitly and compared. This repository defines none.
        let authority = rpc::client::decode_hex(crate::wallet::text(key)?).map_err(error)?;
        let signature = read(
            Path::new(signature_path),
            RELEASE_SIGNATURE_BYTES,
            "release signature",
        )?;
        (
            authority,
            verify_release_manifest(&authority, &manifest, &signature).map_err(error)?,
        )
    };
    println!("manifest: {}", Path::new(manifest_path).display());
    println!("manifest_digest: {digest}");
    println!("authority_public_key: {}", Hash256(authority));
    println!("signature: {}", Path::new(signature_path).display());
    if command == "release-sign" {
        println!("publication: not performed");
    } else {
        println!("verification: valid detached signature over this exact manifest");
        println!("authority_trust: not established by this tool; confirm the key out of band");
    }
    Ok(())
}
