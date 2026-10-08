// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline VRF operations against the trusted genesis registry.

use crate::{
    CliError,
    vault::read_consensus_seed,
    wallet::{integer, text, write_new},
};
use codec::CanonicalDecode;
use crypto::{Blake2sProvider, CryptoProvider, VrfInput, VrfOutput, VrfRole, prove_vrf};
use std::{ffi::OsString, fs::File, io::Read, path::Path};
use types::Hash256;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > maximum {
        return Err(error("VRF input exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let [genesis_path, key, epoch, height, parent, role, round, path] = args else {
        return Err(error("invalid VRF arguments; run cli help"));
    };
    let genesis =
        genesis::Genesis::decode(&read(Path::new(genesis_path), genesis::MAX_GENESIS_BYTES)?)
            .map_err(error)?;
    let input = VrfInput {
        chain_id: genesis.chain_id,
        genesis: genesis.commitment().map_err(error)?,
        epoch: integer(epoch)?,
        height: integer(height)?,
        parent_randomness: Hash256(rpc::client::decode_hex(text(parent)?).map_err(error)?),
        role: match text(role)? {
            "committee" => VrfRole::Committee,
            "producer" => VrfRole::Producer,
            _ => return Err(error("VRF role must be committee or producer")),
        },
        round: u32::try_from(integer(round)?).map_err(error)?,
    };
    if input.height == 0 || (input.role == VrfRole::Committee && input.round != 0) {
        return Err(error(
            "VRF height must be positive; committee round must be zero",
        ));
    }
    let seed = if command == "vrf-prove" {
        Some(read_consensus_seed(Path::new(key))?)
    } else {
        None
    };
    let public = if let Some(ref seed) = seed {
        crypto::blake2s::ed25519_public_key(seed)
    } else {
        rpc::client::decode_hex(text(key)?).map_err(error)?
    };
    let mut provider = Blake2sProvider::new();
    let id = provider.register_validator(public).map_err(error)?;
    if !genesis
        .validators
        .iter()
        .any(|v| v.id == id && v.weight > 0)
    {
        return Err(error("VRF key is not an eligible genesis validator"));
    }
    let output = if let Some(ref seed) = seed {
        prove_vrf(seed, input).map_err(error)?
    } else {
        VrfOutput::decode(&read(Path::new(path), crypto::vrf::VRF_ENVELOPE_BYTES)?)
            .map_err(error)?
    };
    if !provider.verify_vrf(id, input.seed(), &output) {
        return Err(error("invalid VRF proof or context"));
    }
    if seed.is_some() {
        write_new(Path::new(path), &output.encode().map_err(error)?)?;
    }
    println!("validator: {id}");
    println!("public_key: {}", Hash256(public));
    println!("input: {}", input.seed());
    println!("randomness: {}", output.randomness);
    println!("verification: valid ECVRF-EDWARDS25519-SHA512-TAI proof");
    Ok(())
}
