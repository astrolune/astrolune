// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Certified validator/observer networking and a separate local demonstration mode.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::sync::{Arc, Mutex};

use node::{FullNodeService, NodeService, ProducerConfig};
use rpc::TcpRpcServer;

mod network;
mod options;
mod status;

#[derive(Debug)]
enum DaemonError {
    Config(String),
    Io(String),
}

impl core::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Io(msg) => write!(f, "I/O or storage error: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}

fn main() {
    if let Err(error) = run() {
        eprintln!("fatal: {error}");
        std::process::exit(match error {
            DaemonError::Config(_) => 2,
            DaemonError::Io(_) => 1,
        });
    }
}

fn run() -> Result<(), DaemonError> {
    let options = match options::parse(std::env::args_os().skip(1))? {
        options::Command::Help => {
            print!("{}", options::HELP);
            return Ok(());
        }
        options::Command::Version => {
            println!("daemon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        options::Command::Run(options) => options,
    };
    if options.validators.is_some() {
        return network::run(&options);
    }
    let genesis = options.genesis.as_deref().map(read_genesis).transpose()?;
    run_demonstration(*options, genesis.as_ref())
}

fn run_demonstration(
    options: options::Options,
    genesis: Option<&genesis::Genesis>,
) -> Result<(), DaemonError> {
    if options.config.data_dir.join("signing.journal").exists()
        || options.config.data_dir.join("consensus-cache.bin").exists()
        || options
            .config
            .data_dir
            .join(node::observer::OBSERVER_MARKER)
            .exists()
    {
        return Err(DaemonError::Config(
            "a certified network directory requires --validators and its original node role".into(),
        ));
    }
    let mut config = options.config;
    let mut producer_config = ProducerConfig::default();
    if let Some(genesis) = genesis {
        config.chain_id = genesis.chain_id;
        producer_config.block_capacity = genesis.capacity;
        println!(
            "genesis_hash: {:?}",
            genesis.commitment().map_err(io_error)?
        );
    }
    producer_config.chain_id = config.chain_id;
    println!(
        "AstroLune local demonstration daemon v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("chain_id  : {}", config.chain_id);
    println!("data_dir  : {}", config.data_dir.display());
    if options.dry_run {
        println!("[dry-run] configuration valid; no files written or listeners opened.");
        return Ok(());
    }

    std::fs::create_dir_all(&config.data_dir).map_err(io_error)?;
    let path = config.data_dir.join("chain.bin");
    let mut service = if let Some(genesis) = genesis {
        FullNodeService::open_with_genesis(producer_config, path, genesis)
    } else {
        FullNodeService::open(producer_config, path)
    }
    .map_err(io_error)?;
    if genesis.is_none() {
        service.setup_committee(vec![consensus::CommitteeMember {
            id: types::ValidatorId::from_bytes([1; 32]),
            power: consensus::PotbWeight(100),
        }]);
    }
    println!("next_height: {}", service.height());
    if options.max_blocks == Some(0) {
        println!("Recovery complete; no blocks requested.");
        return Ok(());
    }

    let service = Arc::new(Mutex::new(service));
    let rpc_service = Arc::new(Mutex::new(status::ChainStatus {
        chain_id: config.chain_id,
        accounts_enabled: genesis.is_some(),
        node: service.clone(),
    }));
    start_listeners(&config.network, rpc_service)?;

    let mut produced = 0u64;
    while options.max_blocks.is_none_or(|max| produced < max) {
        let mut node = service.lock().map_err(|_| io_error("node lock poisoned"))?;
        let previous_height = node.height();
        for _ in 0..5 {
            node.advance().map_err(io_error)?;
        }
        if node.height()
            != previous_height
                .checked_add(1)
                .ok_or_else(|| io_error("height exhausted"))?
        {
            return Err(io_error("pipeline did not commit a block"));
        }
        let checkpoint = node
            .storage()
            .checkpoint()
            .copied()
            .ok_or_else(|| io_error("committed checkpoint missing"))?;
        drop(node);
        produced += 1;
        println!(
            "block #{produced} committed at height {}",
            checkpoint.height
        );
        println!("state_root: {:?}", checkpoint.state_root);
        if options.max_blocks.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    println!("Stopped after {produced} durable blocks.");
    Ok(())
}

fn start_listeners(
    network: &config::NetworkConfig,
    rpc_service: Arc<Mutex<status::ChainStatus>>,
) -> Result<(), DaemonError> {
    // Bind both sockets before spawning workers or producing any blocks.
    let peer_manager = Arc::new(p2p::PeerManager::with_limit(network.max_peers));
    let peer_listener =
        p2p::TcpPeerListener::bind(&network.p2p_listen, peer_manager).map_err(io_error)?;
    let rpc_server = TcpRpcServer::bind(rpc_service, &network.rpc_listen).map_err(io_error)?;
    println!(
        "p2p       : {}",
        peer_listener.local_addr().map_err(io_error)?
    );
    println!("rpc       : {}", rpc_server.local_addr().map_err(io_error)?);
    let _p2p_handle = std::thread::Builder::new()
        .name("p2p-listener".into())
        .spawn(move || {
            if let Err(error) = peer_listener.run() {
                eprintln!("p2p listener: {error}");
            }
        })
        .map_err(io_error)?;
    let _rpc_handle = std::thread::Builder::new()
        .name("rpc-server".into())
        .spawn(move || {
            if let Err(error) = rpc_server.run() {
                eprintln!("rpc server: {error}");
            }
        })
        .map_err(io_error)?;

    Ok(())
}

fn io_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Io(error.to_string())
}

fn read_genesis(path: &std::path::Path) -> Result<genesis::Genesis, DaemonError> {
    use codec::CanonicalDecode;
    use std::io::Read;

    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(io_error)?
        .take(genesis::MAX_GENESIS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    genesis::Genesis::decode(&bytes)
        .map_err(|error| DaemonError::Config(format!("invalid genesis: {error}")))
}
