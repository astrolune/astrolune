// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! `AstroLune` operator and developer command-line entry point.
//!
//! Subcommands:
//! - `status` / `account` - read finalized state through RPC
//! - `keys` / `wallet-address` - derive a public wallet identity
//! - `sign-payment` / `inspect-payment` / `submit` - signed native payments
//! - `verify` — validate a node configuration
//! - `genesis <file>` — verify canonical genesis and derive the initial state root
//! - `signing-anchor-create` / `verify-signing-anchor` — independent rollback anchors
//! - `release-sign` / `verify-release` — detached release-manifest authority

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use config::{NetworkConfig, NodeConfig, SecretRef};

mod admission;
mod contracts;
mod custody;
mod evidence;
mod governance;
mod handoffs;
mod network;
mod potb;
mod proofs;
mod receipts;
mod recovery;
mod release;
mod vault;
mod vrf;
mod wallet;

/// Application error type.
#[derive(Debug)]
enum CliError {
    /// Genesis input or materialization failed.
    Genesis(String),
    /// Configuration validation failure.
    Config(String),
    /// Keystore operation failed.
    Keystore(keystore::KeystoreError),
    /// Wallet input, signing, or RPC operation failed.
    Wallet(String),
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(msg) => write!(f, "genesis error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Keystore(err) => write!(f, "keystore error: {err}"),
            Self::Wallet(msg) => write!(f, "wallet error: {msg}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<keystore::KeystoreError> for CliError {
    fn from(e: keystore::KeystoreError) -> Self {
        Self::Keystore(e)
    }
}

const HELP: &str = "\
AstroLune command-line interface

Usage: cli <command> [options]

Commands:
  status [rpc-address]  Read the node's finalized chain status
  account <address> [rpc-address]  Read finalized balance and next nonce
  receipt <genesis> <validators> <tx-id> <minimum-height> <output> [rpc-address] [block-height]
           Fetch, authenticate and save a finalized receipt proof
  verify-receipt <genesis> <validators> <tx-id> <minimum-height> <file>
           Authenticate a saved receipt offline
  wait-finality <genesis> <validators> <tx-id> <timeout-seconds> <output> [rpc-address]
           Wait for a certified receipt without resubmitting the transaction
  state-proof <genesis> <validators> <key-hex> <minimum-height> <output> [rpc-address]
  state-proof-at <genesis> <validators> <key-hex> <exact-height> <output> [rpc-address]
           Fetch, authenticate and save finalized state membership or absence
  verify-state-proof <genesis> <validators> <key-hex> <minimum-height> <file>
           Authenticate a saved state proof offline
  wallet-address <seed-file>  Derive public wallet identity (alias: keys)
  wallet-create <new-vault>  Create a random encrypted wallet; password from stdin
  wallet-encrypt <raw-seed> <new-vault>  Encrypt an existing wallet; password from stdin
  consensus-vault-create <new-vault>  Create a random encrypted consensus key; password from stdin
  consensus-vault-encrypt <raw-seed> <new-vault>  Encrypt an existing consensus seed
           Consensus vaults are never accepted by wallet commands, or the reverse
  sign-payment <chain-id> <seed-file> <recipient> <amount> <nonce> <expires-at> <output>
           Sign a payment offline and save it without overwriting any file
  reprice-transaction <file> <seed-or-vault> <prices> <output>  Sign with explicit resource prices
  inspect-payment <file>  Verify and display a signed payment offline
  sign-deploy <genesis> <seed-file> <wasm> <nonce> <expires-at> <output>
           Sign ABI-v2 deployment offline (genesis runtime_version must be 2)
  sign-call <genesis> <seed-file> <contract> <input-file> <keys-file> <nonce> <expires-at> <max-compute> <output>
           Sign a contract call; keys-file contains one hex local key per line
  inspect-transaction <file>  Verify and display a payment or contract envelope
  submit <file> [rpc-address]  Send a saved transaction once; acceptance is not finality
  evidence-create <genesis> <validators> <vote-a> <vote-b> <output> [rpc-address]  Verify and save a double-vote proof
  evidence-verify <genesis> <validators> <proof>  Independently verify a double-vote proof
  admission-request <genesis> <validators> <candidate-seed-or-vault> <height> <output> [rpc-address]
           Save candidate consent with independently authenticated committee history
  admission-inspect <genesis> <validators> <request>
           Inspect candidate consent and exact admission context offline
  admission-approve <genesis> <validators> <request> <validator-seed> <journal> <output>
           Explicitly approve using the incumbent's protected signer
  admission-assemble <genesis> <validators> <request> <output> <approval>...
           Require more than two thirds of incumbent voting power
  admission-verify <genesis> <validators> <request> <certificate>
           Verify saved authorization against the independently trusted profile
  admission-submit <genesis> <validators> <request> <certificate> [rpc-address]
           Submit quorum authorization for inclusion in the current PoTB height
  governance-config <potb-configuration> <epoch-blocks> <minimum-capacity> <maximum-capacity> <maximum-prices> <output>
           Create a separate network identity with immutable governance bounds
  governance-request <configuration> <validators> <height> <capacity> <prices> <output> [rpc-address]
           Prepare a next-epoch update with authenticated history
  governance-inspect <configuration> <validators> <request>
  governance-approve <configuration> <validators> <request> <validator-seed> <journal> <output>
  governance-assemble <configuration> <validators> <request> <output> <approval>...
  governance-verify <configuration> <validators> <request> <certificate>
  governance-submit <configuration> <validators> <request> <certificate> [rpc-address]
           Resource vectors use compute,memory,io,bandwidth (unsigned integers)
  potb-config <genesis-v2> <epoch-blocks> <initial-weight> <age-increment> <maximum-weight> <output>
           Create an explicit PoTB configuration with a separate network identity
  potb-evidence <configuration> <validators> <double-vote> <inclusion-height> <output> [rpc-address]
           Authenticate history and prepare evidence for the specified PoTB frontier
  potb-submit-evidence <configuration> <validators> <evidence> [rpc-address]
           Authenticate and submit historical evidence to a validator endpoint
  vrf-prove <genesis> <seed-file> <epoch> <height> <parent-randomness> <committee|producer> <round> <output>
           Create a registered validator's context-bound VRF proof offline
  vrf-verify <genesis> <public-key> <epoch> <height> <parent-randomness> <committee|producer> <round> <proof>
           Independently verify the proof and claimed randomness
  export-retained <genesis> <validators> <directory> <minimum-height> <retain-blocks> <new-directory> [checkpoint-file checkpoint-id]
  verify-retained <genesis> <validators> <directory> <minimum-height> <checkpoint-file> <checkpoint-id>
           Export a bounded suffix or verify history from an independently pinned checkpoint
  verify-history <genesis> <validators> <directory> <minimum-height>
           Exclusively recover and authenticate existing finalized history
  export-history <genesis> <validators> <directory> <minimum-height> <new-directory>
           Export verified history for an observer, without copying signing authority
  verify   Validate a node configuration
  genesis <file>  Verify binary genesis and derive its initial state root
  devnet <directory> [validators] [--observer] [--contracts] [--vrf|--potb]  Create a local test network (default: 4)
  init-validator <genesis> <seed-or-vault> <directory>  Provision a protected signing journal
  signing-anchor-create <genesis> <seed-or-vault> <journal> <new-anchor>
           Provision an independent rollback anchor; keep it on separate storage
  verify-signing-anchor <genesis> <seed-or-vault> <journal> <anchor>
           Check offline that a journal is not behind its independent anchor
  release-sign <manifest> <seed-or-vault> <new-signature>
           Sign a release manifest; the operator supplies the release authority key
  verify-release <manifest> <authority-public-key> <signature>
           Verify a detached release signature against an explicitly supplied key
  init-network-tls <directory> [peers]  Create independent TLS identities (default: 4)
  help     Show this message
  version  Show version

RPC defaults to ASTROLUNE_RPC_ADDR or 127.0.0.1:17331 (numeric IP:port).
Proof, receipt, admission and history commands accept explicit PoTB configurations as genesis.
Amounts are integer smallest units; expires-at is the last valid block height.
Seed files contain exactly 32 raw bytes. Never pass seed bytes on the command line.
Anchor and release commands acquire exclusive file locks; stop the validator first.
This repository defines no release authority identity or key.
";

fn main() {
    let result = run();
    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), CliError> {
    match std::env::args().nth(1).as_deref() {
        None | Some("help" | "--help" | "-h") => {
            print!("{HELP}");
            Ok(())
        }
        Some("version" | "--version" | "-V") => {
            println!("cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(
            command @ ("status"
            | "account"
            | "keys"
            | "wallet-address"
            | "sign-payment"
            | "reprice-transaction"
            | "inspect-payment"
            | "inspect-transaction"
            | "submit"),
        ) => wallet::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some(command @ ("state-proof" | "state-proof-at" | "verify-state-proof")) => {
            proofs::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(command @ ("receipt" | "verify-receipt" | "wait-finality")) => {
            receipts::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(
            command @ ("verify-history" | "export-history" | "verify-retained" | "export-retained"),
        ) => recovery::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some("verify") => cmd_verify(),
        Some(
            command @ ("wallet-create"
            | "wallet-encrypt"
            | "consensus-vault-create"
            | "consensus-vault-encrypt"),
        ) => vault::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some(command @ ("signing-anchor-create" | "verify-signing-anchor")) => {
            custody::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(command @ ("release-sign" | "verify-release")) => {
            release::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(command @ ("sign-deploy" | "sign-call")) => {
            contracts::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(command @ ("evidence-create" | "evidence-verify")) => evidence::run(command),
        Some(
            command @ ("admission-request" | "admission-inspect" | "admission-approve"
            | "admission-assemble" | "admission-verify" | "admission-submit"),
        ) => admission::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some(
            command @ ("governance-config"
            | "governance-request"
            | "governance-inspect"
            | "governance-approve"
            | "governance-assemble"
            | "governance-verify"
            | "governance-submit"),
        ) => governance::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some(command @ ("potb-config" | "potb-evidence" | "potb-submit-evidence")) => {
            potb::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some(command @ ("vrf-prove" | "vrf-verify")) => {
            vrf::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>())
        }
        Some("genesis") => cmd_genesis(),
        Some("devnet") => network::devnet(),
        Some("init-validator") => network::init_validator(),
        Some("init-network-tls") => network::init_network_tls(),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

/// Validate bounded genesis input and report commitments without changing state.
fn cmd_genesis() -> Result<(), CliError> {
    use codec::CanonicalDecode;
    use std::io::Read;

    let mut arguments = std::env::args_os().skip(2);
    let path = arguments
        .next()
        .filter(|_| arguments.next().is_none())
        .ok_or_else(|| CliError::Genesis("usage: cli genesis <file>".into()))?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(genesis::MAX_GENESIS_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    let genesis =
        genesis::Genesis::decode(&bytes).map_err(|error| CliError::Genesis(error.to_string()))?;
    let commitment = genesis
        .commitment()
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    let state = genesis
        .materialize()
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    println!("chain_id: {}", genesis.chain_id);
    println!("genesis_hash: {commitment}");
    println!("state_root: {}", state.root());
    println!("validators: {}", genesis.validators.len());
    println!("allocations: {}", genesis.allocations.len());
    Ok(())
}

/// Validate a node configuration.
fn cmd_verify() -> Result<(), CliError> {
    let data_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "node-data".into());

    let config = NodeConfig {
        chain_id: 7,
        data_dir: PathBuf::from(&data_dir),
        validator_key: Some(
            SecretRef::new("default-key").map_err(|e| CliError::Config(format!("{e:?}")))?,
        ),
        network: NetworkConfig {
            p2p_listen: "127.0.0.1:17330".into(),
            rpc_listen: "127.0.0.1:17331".into(),
            max_peers: 32,
        },
    };

    config
        .validate()
        .map_err(|e| CliError::Config(format!("{e:?}")))?;

    println!("Configuration is valid");
    println!("  chain_id  : {}", config.chain_id);
    println!("  data_dir  : {}", config.data_dir.display());
    println!("  p2p       : {}", config.network.p2p_listen);
    println!("  rpc       : {}", config.network.rpc_listen);
    println!("  max_peers : {}", config.network.max_peers);
    Ok(())
}
