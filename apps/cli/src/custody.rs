// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independent signing-anchor provisioning and offline journal/anchor pairing checks.

use crate::{CliError, network::load_signing_context, vault::read_consensus_seed};
use crypto::blake2s::{blake2s, ed25519_public_key};
use keystore::DurableSigner;
use std::{ffi::OsString, path::Path};
use types::{Hash256, ValidatorId};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let [genesis, key, journal, anchor] = args else {
        return Err(error(
            "usage: signing-anchor-create <genesis> <seed-or-vault> <journal> <new-anchor> or verify-signing-anchor <genesis> <seed-or-vault> <journal> <anchor>",
        ));
    };
    let (_, context) = load_signing_context(Path::new(genesis))?;
    let create = command == "signing-anchor-create";
    if create && Path::new(anchor).exists() {
        return Err(error("output already exists"));
    }
    let seed = read_consensus_seed(Path::new(key))?;
    // Both files are opened under exclusive locks. A validator holding its journal
    // must be stopped first; verification completes an interrupted anchor update.
    let signer = if create {
        DurableSigner::create_anchor(Path::new(journal), context, *seed, Path::new(anchor))?
    } else {
        DurableSigner::open_with_anchor(Path::new(journal), context, *seed, Path::new(anchor))?
    };
    let public_key = ed25519_public_key(&seed);
    println!("validator: {:?}", ValidatorId(blake2s(&public_key).0));
    println!("public_key: {}", Hash256(public_key));
    println!(
        "journal_origin: {}",
        signer
            .anchor_journal_identity()
            .ok_or_else(|| error("anchor was not paired"))?
    );
    println!(
        "witnessed_decisions: {}",
        signer
            .anchor_sequence()
            .ok_or_else(|| error("anchor was not paired"))?
    );
    match signer.last_position() {
        Some(position) => println!(
            "last_position: height {} round {} phase {}",
            position.height, position.round, position.phase
        ),
        None => println!("last_position: none"),
    }
    println!("anchor: {}", Path::new(anchor).display());
    if create {
        println!("custody: move this anchor to storage the journal cannot restore");
    } else {
        println!("verification: journal agrees with its independent anchor");
    }
    Ok(())
}
