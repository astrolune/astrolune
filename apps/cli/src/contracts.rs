// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline contract envelopes, explicitly activated by genesis profile 2.

use crate::{
    CliError,
    wallet::{integer, read_seed, text, write_new},
};
use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
use runtime::{ModuleValidator, WASM_VERSION, WasmRuntime};
use std::{ffi::OsString, io::Read, path::Path};
use transaction::{
    ContractAction, ContractPayload, address_from_public_key, contract_address, contract_code_key,
    contract_state_key, signing_hash,
};
use types::{Address, Resources, Transaction, TransactionLane};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Wallet(value.to_string())
}

pub(super) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(error)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > max {
        return Err(error("file exceeds its protocol size limit"));
    }
    Ok(bytes)
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let (genesis_file, seed_file, nonce, expires, output, action, compute) = match (command, args) {
        ("sign-deploy", [genesis, seed, wasm, nonce, expires, output]) => {
            // Leave envelope headroom inside the reference network's 64 KiB limit.
            let code = read_bounded(Path::new(wasm), 60 * 1024)?;
            WasmRuntime::new()
                .validate(&code, WASM_VERSION)
                .map_err(error)?;
            (
                genesis,
                seed,
                nonce,
                expires,
                output,
                ContractAction::Deploy(code),
                None,
            )
        }
        (
            "sign-call",
            [
                genesis,
                seed,
                address,
                input,
                keys,
                nonce,
                expires,
                compute,
                output,
            ],
        ) => {
            let address = Address(rpc::client::decode_hex(text(address)?).map_err(error)?);
            let input = read_bounded(Path::new(input), 60 * 1024)?;
            let keys = read_keys(Path::new(keys))?;
            (
                genesis,
                seed,
                nonce,
                expires,
                output,
                ContractAction::Call {
                    address,
                    input,
                    keys,
                },
                Some(integer(compute)?),
            )
        }
        _ => return Err(error("invalid contract arguments; run cli help")),
    };
    let genesis = genesis::Genesis::decode(&read_bounded(
        Path::new(genesis_file),
        genesis::MAX_GENESIS_BYTES,
    )?)
    .map_err(error)?;
    if genesis.runtime_version != 2 {
        return Err(error("genesis must activate runtime_version 2"));
    }
    let seed = read_seed(Path::new(seed_file))?;
    let public_key = ed25519_public_key(&seed);
    let mut tx = Transaction {
        version: 1,
        chain_id: genesis.chain_id,
        sender: address_from_public_key(&public_key),
        nonce: integer(nonce)?,
        expires_at: integer(expires)?,
        lane: TransactionLane::Contracts,
        access_list: vec![],
        resource_prices: execution::PAYMENT_PRICES,
        resource_limit: Resources::ZERO,
        payload: ContractPayload { public_key, action }.to_bytes(),
        signature: [0; 64],
    };
    let payload = ContractPayload::decode(&tx.payload).map_err(error)?;
    tx.access_list = access(&tx, &payload.action);
    tx.resource_limit = match &payload.action {
        ContractAction::Deploy(code) => Resources {
            compute: 100 + code.len() as u64,
            memory: code.len() as u64 + 32,
            io: code.len() as u64 + 32,
            bandwidth: transaction::estimate_encoded_len(&tx) as u64,
        },
        ContractAction::Call { .. } => Resources {
            compute: compute.ok_or_else(|| error("missing compute budget"))?,
            memory: genesis.capacity.memory.min(16 * 1024 * 1024 + 32),
            io: genesis.capacity.io.min(1024 * 1024),
            bandwidth: genesis.capacity.bandwidth.min(256 * 1024),
        },
    };
    if !tx.resource_limit.fits_in(genesis.capacity) {
        return Err(error("contract budget exceeds genesis capacity"));
    }
    tx.signature = ed25519_sign(&seed, signing_hash(&tx).as_bytes());
    validate(&tx)?;
    write_new(Path::new(output), &tx.to_bytes())?;
    print(&tx)?;
    println!("saved: {}", Path::new(output).display());
    println!("submission: not sent");
    Ok(())
}

fn read_keys(path: &Path) -> Result<Vec<Vec<u8>>, CliError> {
    let bytes = read_bounded(path, 64 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(error)?;
    let mut keys = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.len() > 512 || line.len() % 2 != 0 {
            return Err(error("each key must be 1..256 hex-encoded bytes"));
        }
        let key = line
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let hex = std::str::from_utf8(pair).map_err(error)?;
                u8::from_str_radix(hex, 16).map_err(error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        keys.push(key);
        if keys.len() > transaction::contract::MAX_CONTRACT_KEYS {
            return Err(error("too many keys"));
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn access(tx: &Transaction, action: &ContractAction) -> Vec<types::StateKey> {
    let mut keys = vec![state::account_key(tx.sender)];
    match action {
        ContractAction::Deploy(_) => keys.push(contract_code_key(contract_address(
            tx.chain_id,
            tx.sender,
            tx.nonce,
        ))),
        ContractAction::Call {
            address,
            keys: local,
            ..
        } => {
            keys.push(contract_code_key(*address));
            keys.extend(local.iter().map(|key| contract_state_key(*address, key)));
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

pub(super) fn validate(tx: &Transaction) -> Result<ContractPayload, CliError> {
    let payload = ContractPayload::decode(&tx.payload).map_err(error)?;
    if tx.version != 1
        || tx.chain_id == 0
        || tx.nonce == u64::MAX
        || tx.expires_at == 0
        || tx.lane != TransactionLane::Contracts
        || tx.resource_limit.checked_cost(tx.resource_prices).is_none()
        || tx.resource_limit.compute == 0
        || tx.resource_limit.compute > 10_000_000
        || tx.access_list != access(tx, &payload.action)
        || tx.sender != address_from_public_key(&payload.public_key)
        || tx.to_bytes().len() > rpc::client::MAX_TRANSACTION_BYTES
        || !ed25519_verify(
            &payload.public_key,
            signing_hash(tx).as_bytes(),
            &tx.signature,
        )
    {
        return Err(error("invalid contract envelope, signature or budget"));
    }
    Ok(payload)
}

pub(super) fn print(tx: &Transaction) -> Result<(), CliError> {
    let payload = validate(tx)?;
    println!("transaction_id: {}", transaction::compute_tx_id(tx));
    println!("chain_id: {}", tx.chain_id);
    println!("sender: {}", tx.sender);
    match payload.action {
        ContractAction::Deploy(_) => println!(
            "deploy_address: {}",
            contract_address(tx.chain_id, tx.sender, tx.nonce)
        ),
        ContractAction::Call { address, .. } => println!("contract: {address}"),
    }
    println!(
        "maximum_fee: {}",
        tx.resource_limit
            .checked_cost(tx.resource_prices)
            .ok_or_else(|| error("fee overflow"))?
    );
    println!("nonce: {}", tx.nonce);
    println!("expires_at: {}", tx.expires_at);
    Ok(())
}
