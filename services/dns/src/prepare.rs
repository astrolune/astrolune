// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Creates bounded canonical call input and matching contract-local access keys.

use contract_sdk::registry::{self, RegistryAction, RegistryCall, RegistryRecord};
use std::{fs::OpenOptions, io::Write, path::Path};

pub(super) fn run(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("invalid prepare arguments".into());
    }

    let name = dns::certified::canonical_name(&args[1])?;

    let data;
    let action = match (args[0].as_str(), &args[2..]) {
        ("register", [duration, kind, value, _]) => {
            data = record(kind, value)?;
            RegistryAction::Register(
                number(duration)?,
                RegistryRecord {
                    kind: data.0,
                    value: &data.1,
                },
            )
        }
        ("update", [kind, value, _]) => {
            data = record(kind, value)?;
            RegistryAction::Update(RegistryRecord {
                kind: data.0,
                value: &data.1,
            })
        }
        ("renew", [duration, _]) => RegistryAction::Renew(number(duration)?),
        ("transfer", [owner, _]) => {
            let owner = rpc::client::decode_hex(owner).map_err(|error| error.to_string())?;
            if owner == [0; 32] {
                return Err("owner cannot be zero".into());
            }

            RegistryAction::Transfer(owner)
        }
        ("release", [_]) => RegistryAction::Release,
        _ => return Err("invalid prepare arguments; see dns --help".into()),
    };

    let mut input = [0; registry::MAX_CALL];
    let size = RegistryCall {
        name: name.as_bytes(),
        action,
    }
    .encode(&mut input)
    .map_err(|error| format!("invalid call: {error:?}"))?;

    let mut key = [0; registry::MAX_NAME + 7];
    let length = registry::registry_key(name.as_bytes(), &mut key)
        .map_err(|error| format!("invalid key: {error:?}"))?;

    let path = Path::new(args.last().ok_or("missing output directory")?);
    std::fs::create_dir(path).map_err(|error| error.to_string())?;

    write(&path.join("input.bin"), &input[..size])?;
    write(
        &path.join("keys.txt"),
        format!("{}\n", super::hex(&key[..length])).as_bytes(),
    )?;

    println!("prepared_name: {name}");
    println!("input: {}", path.join("input.bin").display());
    println!("keys: {}", path.join("keys.txt").display());

    Ok(())
}

fn record(kind: &str, value: &str) -> Result<(u8, Vec<u8>), String> {
    match kind {
        "address" => rpc::client::decode_hex::<32>(value)
            .map(|bytes| (0, bytes.to_vec()))
            .map_err(|error| error.to_string()),
        "service" if value.len() <= registry::MAX_RECORD => Ok((1, value.as_bytes().to_vec())),
        _ => {
            Err("record must be address or a service description of at most 256 ASCII bytes".into())
        }
    }
}

fn number(text: &str) -> Result<u64, String> {
    let value = text.parse::<u64>().map_err(|_| "invalid lease duration")?;
    if value == 0 || value > registry::MAX_DURATION {
        return Err("duration must be 1..1000000 blocks".into());
    }

    Ok(value)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|error| error.to_string())
}
