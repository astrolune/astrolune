// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline native-payment signing and explicit submission of saved transactions.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Duration,
};

use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
use rpc::{
    ClientError, TcpRpcClient,
    client::{MAX_TRANSACTION_BYTES, decode_hex},
};
use transaction::{Payment, address_from_public_key, compute_tx_id, signing_hash};
use types::{Address, Resources, Transaction, TransactionLane};
use zeroize::Zeroizing;

use crate::CliError;

fn error(message: impl std::fmt::Display) -> CliError {
    CliError::Wallet(message.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    match (command, args) {
        ("status", [] | [_]) => {
            let status = client(args.first())?.chain_status().map_err(error)?;
            println!("chain_id: {}", status.chain_id);
            println!("finalized_height: {}", status.finalized_height);
            println!("finalized_block: {}", status.finalized_block);
            Ok(())
        }
        ("account", [address] | [address, _]) => {
            let address = parse_address(address)?;
            if let Some(account) = client(args.get(1))?.account(address).map_err(error)? {
                println!("address: {address}");
                println!("balance: {}", account.balance);
                println!("next_nonce: {}", account.nonce);
            } else {
                println!("address: {address}");
                println!("account: absent");
            }
            Ok(())
        }
        ("keys" | "wallet-address", [path]) => {
            let seed = read_seed(Path::new(path))?;
            let public_key = ed25519_public_key(&seed);
            println!("address: {}", address_from_public_key(&public_key));
            println!("public_key: {}", types::Hash256(public_key));
            Ok(())
        }
        ("sign-payment", [chain, seed, recipient, amount, nonce, expires, output]) => {
            let chain_id = u32::try_from(integer(chain)?).map_err(error)?;
            let seed = read_seed(Path::new(seed))?;
            let recipient = parse_address(recipient)?;
            let payment = signed_payment(
                chain_id,
                &seed,
                recipient,
                integer(amount)?,
                integer(nonce)?,
                integer(expires)?,
            )?;
            write_new(Path::new(output), &payment.to_bytes())?;
            print_payment(&payment)?;
            println!("saved: {}", Path::new(output).display());
            println!("submission: not sent");
            Ok(())
        }
        ("reprice-transaction", [path, seed, prices, output]) => {
            reprice(path, seed, prices, output)
        }
        ("inspect-payment", [path]) => print_payment(&read_payment(Path::new(path))?),
        ("inspect-transaction", [path]) => print_transaction(&read_transaction(Path::new(path))?),
        ("submit", [path] | [path, _]) => submit(Path::new(path), &client(args.get(1))?),
        _ => Err(error("invalid arguments; run cli help for command usage")),
    }
}

fn reprice(
    path: &OsString,
    seed: &OsString,
    prices: &OsString,
    output: &OsString,
) -> Result<(), CliError> {
    if Path::new(output).exists() {
        return Err(error("output already exists"));
    }
    let mut tx = read_transaction(Path::new(path))?;
    let seed = read_seed(Path::new(seed))?;
    if address_from_public_key(&ed25519_public_key(&seed)) != tx.sender {
        return Err(error("signer does not match transaction sender"));
    }
    tx.resource_prices = crate::governance::resources(prices)?;
    tx.signature = ed25519_sign(&seed, signing_hash(&tx).as_bytes());
    print_transaction(&tx)?;
    write_new(Path::new(output), &tx.to_bytes())?;
    Ok(())
}

pub(super) fn client(address: Option<&OsString>) -> Result<TcpRpcClient, CliError> {
    let address = address
        .cloned()
        .or_else(|| std::env::var_os("ASTROLUNE_RPC_ADDR"))
        .unwrap_or_else(|| "127.0.0.1:17331".into());
    let address = text(&address)?
        .parse()
        .map_err(|_| error("RPC address must be a numeric IP:port, e.g. 127.0.0.1:17331"))?;
    TcpRpcClient::new(address, Duration::from_secs(5)).map_err(error)
}

pub(super) fn text(value: &OsStr) -> Result<&str, CliError> {
    value
        .to_str()
        .ok_or_else(|| error("argument must be valid UTF-8"))
}

pub(super) fn integer(value: &OsStr) -> Result<u64, CliError> {
    let value = text(value)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error("expected an unsigned decimal integer"));
    }
    value.parse().map_err(error)
}

fn parse_address(value: &OsStr) -> Result<Address, CliError> {
    decode_hex(text(value)?).map(Address).map_err(error)
}

pub(super) fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(keystore::vault::WALLET_VAULT_BYTES + 1));
    File::open(path)
        .map_err(error)?
        .take(keystore::vault::WALLET_VAULT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() == keystore::vault::WALLET_VAULT_BYTES {
        return keystore::vault::decrypt_wallet_seed(&bytes, &crate::vault::password()?)
            .map_err(error);
    }
    if bytes.starts_with(b"ALVAULT1") {
        return Err(error("truncated or oversized wallet vault"));
    }
    let seed = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| error("expected a 32-byte raw seed or wallet vault"))?;
    Ok(Zeroizing::new(seed))
}

pub(super) fn read_raw_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    File::open(path)
        .map_err(error)?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| error("seed file must contain exactly 32 raw bytes"))?;
    Ok(Zeroizing::new(seed))
}

fn signed_payment(
    chain_id: u32,
    seed: &[u8; 32],
    recipient: Address,
    amount: u64,
    nonce: u64,
    expires_at: u64,
) -> Result<Transaction, CliError> {
    let public_key = ed25519_public_key(seed);
    let sender = address_from_public_key(&public_key);
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id,
        sender,
        nonce,
        expires_at,
        lane: TransactionLane::Payments,
        resource_prices: execution::PAYMENT_PRICES,
        resource_limit: Resources::ZERO,
        access_list: payment_access(sender, recipient),
        payload: Payment {
            public_key,
            recipient,
            amount,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).map_err(error)?;
    tx.signature = ed25519_sign(seed, signing_hash(&tx).as_bytes());
    validate_payment(&tx)?;
    Ok(tx)
}

fn payment_access(sender: Address, recipient: Address) -> Vec<types::StateKey> {
    let mut access = vec![state::account_key(sender), state::account_key(recipient)];
    access.sort();
    access.dedup();
    access
}

// The wallet supports precisely the current native-payment policy, not arbitrary
// executable transactions. State-dependent admission remains the node's job.
fn validate_payment(tx: &Transaction) -> Result<Payment, CliError> {
    let payment = Payment::decode(&tx.payload).map_err(error)?;
    if tx.version != types::TRANSACTION_VERSION
        || tx.chain_id == 0
        || tx.nonce == u64::MAX
        || tx.expires_at == 0
        || payment.amount == u64::MAX
        || tx.lane != TransactionLane::Payments
        || tx
            .resource_limit
            .checked_cost(tx.resource_prices)
            .and_then(|fee| fee.checked_add(payment.amount))
            .is_none()
        || tx.resource_limit != execution::payment_resources(tx).map_err(error)?
        || tx.access_list != payment_access(tx.sender, payment.recipient)
        || tx.sender != address_from_public_key(&payment.public_key)
    {
        return Err(error(
            "transaction does not match the supported native-payment policy",
        ));
    }
    if !ed25519_verify(
        &payment.public_key,
        signing_hash(tx).as_bytes(),
        &tx.signature,
    ) {
        return Err(error("invalid payment signature"));
    }
    Ok(payment)
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(error)?;
    #[cfg(unix)]
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|directory| directory.sync_all())
    .map_err(error)?;
    Ok(())
}

fn read_payment(path: &Path) -> Result<Transaction, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(error)?
        .take(MAX_TRANSACTION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(error("payment file exceeds 64 KiB"));
    }
    let tx = Transaction::decode(&bytes).map_err(error)?;
    validate_payment(&tx)?;
    Ok(tx)
}

fn print_payment(tx: &Transaction) -> Result<(), CliError> {
    let payment = validate_payment(tx)?;
    println!("transaction_id: {}", compute_tx_id(tx));
    println!("chain_id: {}", tx.chain_id);
    println!("sender: {}", tx.sender);
    println!("recipient: {}", payment.recipient);
    println!("amount: {}", payment.amount);
    println!(
        "fee: {}",
        tx.resource_limit
            .checked_cost(tx.resource_prices)
            .ok_or_else(|| error("fee overflow"))?
    );
    println!("nonce: {}", tx.nonce);
    println!("expires_at: {}", tx.expires_at);
    Ok(())
}

fn submit(path: &Path, client: &TcpRpcClient) -> Result<(), CliError> {
    let tx = read_transaction(path)?;
    let status = client.chain_status().map_err(error)?;
    if status.chain_id != tx.chain_id {
        return Err(error(
            "payment chain id differs from the contacted node; nothing sent",
        ));
    }
    if status.finalized_height >= tx.expires_at {
        return Err(error(
            "payment has expired for the next block; nothing sent",
        ));
    }
    print_transaction(&tx)?;
    let expected = compute_tx_id(&tx);
    match client.submit_transaction(&tx.to_bytes()) {
        Ok(received) if received == expected => {
            println!("submission: accepted (not finalized)");
            Ok(())
        }
        Err(remote @ ClientError::Remote { .. }) => Err(error(remote)),
        result => Err(error(format!(
            "submission outcome unknown for {expected}: {}; keep the saved payment and check the node before retrying the SAME file",
            match result {
                Ok(_) => "node returned a different transaction id".into(),
                Err(failure) => failure.to_string(),
            }
        ))),
    }
}

fn read_transaction(path: &Path) -> Result<Transaction, CliError> {
    let bytes = crate::contracts::read_bounded(path, MAX_TRANSACTION_BYTES)?;
    let tx = Transaction::decode(&bytes).map_err(error)?;
    match tx.lane {
        TransactionLane::Contracts => {
            crate::contracts::validate(&tx)?;
        }
        _ => {
            validate_payment(&tx)?;
        }
    }
    Ok(tx)
}

fn print_transaction(tx: &Transaction) -> Result<(), CliError> {
    if tx.lane == TransactionLane::Contracts {
        crate::contracts::print(tx)
    } else {
        print_payment(tx)
    }
}
