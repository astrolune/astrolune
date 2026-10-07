// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fetch and independently authenticate bounded finalized-state witnesses.

use crate::{CliError, contracts::read_bounded, wallet};
use codec::{CanonicalDecode, CanonicalEncode};
use rpc::CertifiedStateProof;
use std::{ffi::OsString, path::Path};
use types::StateKey;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Wallet(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let fetch = matches!(command, "state-proof" | "state-proof-at");
    if !(args.len() == 5 || (fetch && args.len() == 6)) {
        return Err(error(
            "usage: cli state-proof|state-proof-at|verify-state-proof <genesis> <validators> <key-hex> <height> <proof-file> [rpc-address]; state-proof-at requires that exact height",
        ));
    }
    let (genesis, keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let key = parse_key(wallet::text(&args[2])?)?;
    let minimum = wallet::integer(&args[3])?;
    let path = Path::new(&args[4]);
    if fetch && path.exists() {
        return Err(error("output already exists"));
    }
    let client = fetch.then(|| wallet::client(args.get(5))).transpose()?;
    let proof = if let Some(client) = &client {
        if command == "state-proof-at" {
            client
                .state_proof_at(&key, minimum)
                .map_err(error)?
                .ok_or_else(|| error("requested historical state is unavailable"))?
        } else {
            client.state_proof(&key).map_err(error)?
        }
    } else {
        CertifiedStateProof::from_bytes(&read_bounded(path, CertifiedStateProof::MAX_BYTES)?)
            .map_err(error)?
    };
    let height = proof.header.map_or(0, |header| header.height);
    if height < minimum {
        return Err(error("state proof precedes minimum height"));
    }
    let handoffs = if genesis.version == genesis::ROTATING_GENESIS_VERSION && height > 0 {
        Some(crate::handoffs::anchor(
            path,
            &genesis,
            &keys,
            height,
            client.as_ref(),
        )?)
    } else {
        None
    };
    let value = match &handoffs {
        Some(trust) => trust.verifier.verify_state(&proof, &key, minimum),
        None => match &genesis {
            Anchor::Potb(profile) => proof.verify_potb_genesis(profile, &keys, &key),
            Anchor::Genesis(genesis) => proof.verify(genesis, &keys, &key, minimum),
        },
    }.map_err(|_| error("state proof authentication failed for the trusted genesis, registry, key or minimum height"))?;
    if fetch {
        if let Some(trust) = &handoffs {
            trust.publish()?;
        }
        wallet::write_new(path, &proof.to_bytes().map_err(error)?)?;
    }
    println!(
        "verified_height: {}",
        proof.header.map_or(0, |header| header.height)
    );
    println!("state_root: {}", proof.root);
    match value {
        None => println!("value: absent"),
        Some(bytes) => {
            print!("value: 0x");
            for byte in bytes {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(())
}

fn parse_key(text: &str) -> Result<StateKey, CliError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() > state::MAX_STATE_KEY_BYTES * 2
        || !text.len().is_multiple_of(2)
        || !text.is_ascii()
    {
        return Err(error(
            "state key must contain at most 256 bytes of hexadecimal data",
        ));
    }
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(error)?;
            u8::from_str_radix(pair, 16).map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateKey(bytes))
}

pub(super) fn anchors(
    genesis_path: &Path,
    registry_path: &Path,
) -> Result<(Anchor, Vec<[u8; 32]>), CliError> {
    let bytes = read_bounded(
        genesis_path,
        consensus::potb_transition::PotbConfiguration::MAX_BYTES,
    )?;
    let genesis = if consensus::potb_transition::PotbConfiguration::is_envelope(&bytes) {
        Anchor::Potb(
            consensus::potb_transition::PotbConfiguration::from_bytes(&bytes).map_err(error)?,
        )
    } else {
        Anchor::Genesis(genesis::Genesis::decode(&bytes).map_err(error)?)
    };
    let registry = read_bounded(registry_path, genesis::MAX_GENESIS_VALIDATORS * 32)?;
    if registry.is_empty() || !registry.len().is_multiple_of(32) {
        return Err(error(
            "validator registry must contain consecutive 32-byte public keys",
        ));
    }
    let keys: Vec<[u8; 32]> = registry.as_chunks::<32>().0.to_vec();
    Ok((genesis, keys))
}

#[derive(Clone)]
pub(super) enum Anchor {
    Genesis(genesis::Genesis),
    Potb(consensus::potb_transition::PotbConfiguration),
}
impl std::ops::Deref for Anchor {
    type Target = genesis::Genesis;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Genesis(value) => value,
            Self::Potb(value) => value.genesis(),
        }
    }
}
impl Anchor {
    pub(super) fn commitment(&self) -> Result<types::Hash256, CliError> {
        match self {
            Self::Genesis(value) => value.commitment().map_err(error),
            Self::Potb(value) => Ok(value.commitment()),
        }
    }
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Genesis(value) => value.to_bytes(),
            Self::Potb(value) => value.to_bytes(),
        }
    }
    pub(super) fn network(
        &self,
        keys: Vec<[u8; 32]>,
    ) -> Result<node::network::StaticNetwork, CliError> {
        match self {
            Self::Genesis(value) => node::network::StaticNetwork::new(value.clone(), keys),
            Self::Potb(value) => node::network::StaticNetwork::with_potb(value.clone(), keys),
        }
        .map_err(error)
    }
}
