// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Certified daemon, bounded peer polling, and committed account RPC.

use crate::{DaemonError, io_error, options::Options};
use codec::{CanonicalDecode, CanonicalEncode};
use node::network::{NetworkNodeError, PreparedExchange, StaticNetwork};
use p2p::tls::{PeerStream, PeerTlsConfig};
use rpc::{RpcError, RpcRequest, RpcResponse, RpcService, TcpRpcServer};
use state::StateDatabase;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

mod metrics;
mod peers;
mod role;
use role::PeerNode;
use telemetry::{NodeMetric, NodeMetrics};

struct NetworkIdentity {
    network: StaticNetwork,
    seed: Option<zeroize::Zeroizing<[u8; 32]>>,
}

pub(crate) fn run(options: &Options) -> Result<(), DaemonError> {
    let NetworkIdentity { network, seed } = load_identity(options)?;
    let transport = PeerTransport(
        options
            .tls_dir
            .as_deref()
            .map(PeerTlsConfig::from_directory)
            .transpose()
            .map_err(io_error)?,
    );
    print_identity(options, &network, &transport);
    if options.dry_run {
        if options.observer {
            node::observer::ObserverNode::validate_directory(&network, &options.config.data_dir)
                .map_err(io_error)?;
        }
        println!("[dry-run] network configuration valid; no files written or listeners opened.");
        return Ok(());
    }
    let mut node = PeerNode::open(options, network.clone(), seed)?;
    println!(
        "storage   : {}",
        if node.storage().is_legacy_archive() {
            "legacy archive (4096 checkpoints / 256 MiB)"
        } else {
            "append-only chain log"
        }
    );
    println!("next_height: {}", node.request().height);
    if options.max_blocks == Some(0) {
        println!("Certified history and node-role recovery complete.");
        return Ok(());
    }
    node.enable_execution_pipeline().map_err(io_error)?;
    let initial_height = node.request().height;
    let metrics = Arc::new(NodeMetrics::new(initial_height - 1, options.observer));
    let node = Arc::new(Mutex::new(node));
    let storage_failed = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind(&options.config.network.p2p_listen).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    let _metrics_server = options
        .metrics_listen
        .map(|address| metrics::MetricsServer::start(address, metrics.clone()))
        .transpose()
        .map_err(io_error)?;
    let peers = peers::PeerRuntime::new(
        options,
        listener.local_addr().map_err(io_error)?,
        node.clone(),
        transport.clone(),
        metrics.clone(),
    )?;
    let rpc = Arc::new(Mutex::new(NetworkStatus {
        node: node.clone(),
        chain_id: network.chain_id(),
        metrics: metrics.clone(),
        storage_failed: storage_failed.clone(),
    }));
    let rpc = TcpRpcServer::bind(rpc, &options.config.network.rpc_listen).map_err(io_error)?;
    println!("p2p       : {}", listener.local_addr().map_err(io_error)?);
    println!("rpc       : {}", rpc.local_addr().map_err(io_error)?);
    std::thread::Builder::new()
        .name("network-rpc".into())
        .spawn(move || {
            if let Err(error) = rpc.run() {
                eprintln!("RPC listener: {error}");
            }
        })
        .map_err(io_error)?;
    let workers = peers.spawn()?;
    let signals = DriveSignals {
        active: Arc::new(AtomicUsize::new(0)),
        storage_failed,
        peers,
    };
    let result = drive(
        options,
        &node,
        &listener,
        &signals,
        initial_height,
        &workers.receiver,
    );
    signals.peers.stop();
    for worker in workers.handles {
        let _ = worker.join();
    }
    result
}

fn print_identity(options: &Options, network: &StaticNetwork, transport: &PeerTransport) {
    println!(
        "AstroLune certified network ({})",
        if network.rotating() {
            "VRF rotation / full-roster availability"
        } else {
            "fixed committee / round-robin"
        }
    );
    println!("chain_id  : {}", network.chain_id());
    println!("genesis_hash: {}", network.genesis_hash());
    println!(
        "role      : {}",
        if options.observer {
            "observer (no consensus signing)"
        } else {
            "validator"
        }
    );
    println!(
        "transport : {}",
        if transport.0.is_some() {
            "TLS 1.3 / mutual authentication"
        } else {
            "INSECURE loopback plaintext"
        }
    );
}

fn load_identity(options: &Options) -> Result<NetworkIdentity, DaemonError> {
    let registry = read_bounded(
        options
            .validators
            .as_deref()
            .ok_or_else(|| io_error("missing registry"))?,
        32 * 32,
    )?;
    if registry.is_empty() || registry.len() % 32 != 0 {
        return Err(DaemonError::Config(
            "validator registry must contain complete 32-byte public keys".into(),
        ));
    }
    let keys = registry.as_chunks::<32>().0.to_vec();
    let configuration = read_bounded(
        options
            .genesis
            .as_deref()
            .ok_or_else(|| io_error("missing genesis"))?,
        consensus::potb_transition::PotbConfiguration::MAX_BYTES,
    )?;
    let mut network = StaticNetwork::decode(&configuration, keys).map_err(io_error)?;
    if let Some(path) = &options.checkpoint {
        let bytes = read_bounded(path, node::network::RecoveryCheckpoint::MAX_BYTES)?;
        let pin = options
            .checkpoint_id
            .ok_or_else(|| io_error("missing checkpoint pin"))?;
        let checkpoint =
            node::network::RecoveryCheckpoint::from_bytes(&bytes, pin).map_err(io_error)?;
        network = network.with_checkpoint(checkpoint).map_err(io_error)?;
    }
    if options.observer {
        return Ok(NetworkIdentity {
            network,
            seed: None,
        });
    }
    let seed = zeroize::Zeroizing::new(read_bounded(
        options
            .validator_key
            .as_deref()
            .ok_or_else(|| io_error("missing seed path"))?,
        32,
    )?);
    let seed = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| DaemonError::Config("validator seed must be exactly 32 bytes".into()))?,
    );
    let id =
        types::ValidatorId(crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&seed)).0);
    if !network.potb()
        && network
            .committee(1)
            .map_err(io_error)?
            .voting_power(id)
            .is_none()
    {
        return Err(DaemonError::Config(
            "validator key is not registered in genesis".into(),
        ));
    }
    Ok(NetworkIdentity {
        network,
        seed: Some(seed),
    })
}

struct Workers {
    receiver: mpsc::Receiver<PreparedExchange>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct PeerTransport(Option<PeerTlsConfig>);

impl PeerTransport {
    fn connect(&self, stream: TcpStream) -> std::io::Result<PeerStream> {
        match &self.0 {
            Some(tls) => tls.connect(stream, IO_TIMEOUT),
            None => PeerStream::plaintext_local(stream, IO_TIMEOUT),
        }
    }

    fn accept(&self, stream: TcpStream) -> std::io::Result<PeerStream> {
        match &self.0 {
            Some(tls) => tls.accept(stream, IO_TIMEOUT),
            None => PeerStream::plaintext_local(stream, IO_TIMEOUT),
        }
    }
}

struct ConnectionSlot(Arc<AtomicUsize>, Arc<NodeMetrics>);
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
        self.1.subtract(NodeMetric::IncomingSessions, 1);
    }
}

struct DriveSignals {
    active: Arc<AtomicUsize>,
    storage_failed: Arc<AtomicBool>,
    peers: peers::PeerRuntime,
}

fn drive(
    options: &Options,
    node: &Arc<Mutex<PeerNode>>,
    listener: &TcpListener,
    signals: &DriveSignals,
    initial_height: u64,
    receiver: &mpsc::Receiver<PreparedExchange>,
) -> Result<(), DaemonError> {
    let mut reported = initial_height;
    loop {
        // The fixed accept budget also prevents a connection flood from starving consensus.
        for _ in 0..8 {
            match listener.accept() {
                Ok((stream, _)) => {
                    if signals.active.load(Ordering::Acquire) >= options.config.network.max_peers {
                        signals.peers.metrics.add(NodeMetric::SessionLimitDrops, 1);
                        continue;
                    }
                    signals.active.fetch_add(1, Ordering::AcqRel);
                    signals.peers.metrics.add(NodeMetric::IncomingSessions, 1);
                    let slot =
                        ConnectionSlot(signals.active.clone(), signals.peers.metrics.clone());
                    let peers = signals.peers.clone();
                    let storage_failed = signals.storage_failed.clone();
                    std::thread::Builder::new()
                        .name("peer-request".into())
                        .spawn(move || {
                            let _slot = slot;
                            let _ = peers.serve(stream, &storage_failed);
                        })
                        .map_err(io_error)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(io_error(error)),
            }
        }
        if signals.peers.failed() {
            return Err(io_error("peer worker failed; restart required"));
        }
        let mut node = node.lock().map_err(|_| io_error("node lock poisoned"))?;
        if signals.storage_failed.load(Ordering::Acquire) {
            return Err(io_error(
                "finalized history read failed; storage recovery required",
            ));
        }
        for _ in 0..4 {
            if !node.can_receive() {
                break;
            }
            let Ok(exchange) = receiver.try_recv() else {
                break;
            };
            match node.receive_prepared(exchange) {
                Ok(rejected) => signals
                    .peers
                    .metrics
                    .add(NodeMetric::RejectedMessages, rejected as u64),
                Err(NetworkNodeError::Input(_)) => {
                    signals.peers.metrics.add(NodeMetric::RejectedMessages, 1);
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        let rejected = node.poll_execution().map_err(io_error)?;
        signals
            .peers
            .metrics
            .add(NodeMetric::RejectedMessages, rejected as u64);
        node.tick(Instant::now()).map_err(io_error)?;
        let height = node.request().height;
        if height != reported {
            println!("certified block committed at height {}", height - 1);
            println!("state_root: {}", node.storage().state().root());
            reported = height;
            signals.peers.metrics.finalized(height - 1);
        }
        if options
            .max_blocks
            .is_some_and(|count| height.saturating_sub(initial_height) >= count)
        {
            println!(
                "Stopped after {} certified blocks.",
                height - initial_height
            );
            return Ok(());
        }
        drop(node);
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>, DaemonError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(io_error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(DaemonError::Config(
            "configuration file exceeds its size bound".into(),
        ));
    }
    Ok(bytes)
}

struct NetworkStatus {
    node: Arc<Mutex<PeerNode>>,
    chain_id: u32,
    metrics: Arc<NodeMetrics>,
    storage_failed: Arc<AtomicBool>,
}
impl NetworkStatus {
    fn state_proof(
        &self,
        node: &PeerNode,
        key: &types::StateKey,
        requested: Option<u64>,
    ) -> Result<RpcResponse, RpcError> {
        let height = requested
            .or_else(|| node.storage().checkpoint().map(|cp| cp.height))
            .ok_or(RpcError::Unavailable)?;
        let Some((_, state)) = node.storage().read_state_at(height).map_err(|error| {
            self.storage_failed.store(true, Ordering::Release);
            self.metrics.add(NodeMetric::LocalFailures, 1);
            eprintln!("Historical state read failed: {error}");
            RpcError::Unavailable
        })?
        else {
            return Ok(RpcResponse::StateProofAt(None));
        };
        let finality = if height == 0 {
            None
        } else {
            let Some((block, certificate)) =
                node.storage().read_finalized(height).map_err(|error| {
                    self.storage_failed.store(true, Ordering::Release);
                    self.metrics.add(NodeMetric::LocalFailures, 1);
                    eprintln!("Finalized proof read failed: {error}");
                    RpcError::Unavailable
                })?
            else {
                return if requested.is_some() {
                    Ok(RpcResponse::StateProofAt(None))
                } else {
                    Err(RpcError::Unavailable)
                };
            };
            Some((block.header, certificate))
        };
        let bytes = rpc::CertifiedStateProof::create(&state, key, finality)?.to_bytes()?;
        Ok(if requested.is_some() {
            RpcResponse::StateProofAt(Some(bytes))
        } else {
            RpcResponse::StateProof(bytes)
        })
    }

    fn receipt(
        &self,
        node: &PeerNode,
        id: types::Hash256,
        height: Option<u64>,
    ) -> Result<RpcResponse, RpcError> {
        let height = height.or_else(|| {
            node.storage()
                .transaction_location(id)
                .map(|(height, _)| height)
        });
        let Some(height) = height else {
            return Ok(RpcResponse::Receipt(None));
        };
        let stored = node.storage().read_receipts(height).map_err(|error| {
            self.storage_failed.store(true, Ordering::Release);
            self.metrics.add(NodeMetric::LocalFailures, 1);
            eprintln!("Finalized receipt read failed: {error}");
            RpcError::Unavailable
        })?;
        let proof = stored
            .filter(|stored| {
                stored
                    .effects
                    .receipts
                    .iter()
                    .any(|receipt| receipt.transaction == id)
            })
            .map(|stored| rpc::CertifiedReceiptProof(stored).to_bytes())
            .transpose()?;
        Ok(RpcResponse::Receipt(proof))
    }
}
impl RpcService for NetworkStatus {
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError> {
        let mut node = self.node.lock().map_err(|_| RpcError::Unavailable)?;
        match request {
            request @ (RpcRequest::SubmitPotbAdmission(_)
            | RpcRequest::SubmitPotbEvidence(_)
            | RpcRequest::SubmitGovernance(_)) => self.submit_potb(&mut node, request),
            RpcRequest::PotbHandoff(height) => self.potb_handoff(&node, height),
            RpcRequest::Receipt { id, height } => self.receipt(&node, id, height),
            RpcRequest::CommitteeHandoff(height) => {
                let handoff =
                    node::handoff::read_handoff(node.storage(), height).map_err(|error| {
                        self.storage_failed.store(true, Ordering::Release);
                        self.metrics.add(NodeMetric::LocalFailures, 1);
                        eprintln!("Finalized handoff read failed: {error}");
                        RpcError::Unavailable
                    })?;
                let bytes = handoff
                    .map(|handoff| handoff.to_bytes())
                    .transpose()
                    .map_err(|_| RpcError::Unavailable)?;
                Ok(RpcResponse::CommitteeHandoff(bytes))
            }
            RpcRequest::StateProof(key) => self.state_proof(&node, &key, None),
            RpcRequest::StateProofAt { key, height } => self.state_proof(&node, &key, Some(height)),
            RpcRequest::Block(height) => {
                let block = node.storage().read_finalized(height).map_err(|error| {
                    // A locally corrupt certified block must stop voting even when
                    // RPC discovers it before peer catch-up does.
                    self.storage_failed.store(true, Ordering::Release);
                    self.metrics.add(NodeMetric::LocalFailures, 1);
                    eprintln!("Finalized history read failed: {error}");
                    RpcError::Unavailable
                })?;
                Ok(RpcResponse::Block(block.map(|(block, _)| Box::new(block))))
            }
            RpcRequest::ChainStatus => {
                let checkpoint = node.storage().checkpoint().ok_or(RpcError::Unavailable)?;
                Ok(RpcResponse::ChainStatus {
                    chain_id: self.chain_id,
                    finalized_height: checkpoint.height,
                    finalized_block: checkpoint.block,
                })
            }
            RpcRequest::Account(address) => {
                let snapshot = node
                    .storage()
                    .state()
                    .snapshot()
                    .map_err(|_| RpcError::Unavailable)?;
                let account = state::read_account(snapshot.as_ref(), address)
                    .map_err(|_| RpcError::Unavailable)?;
                Ok(RpcResponse::Account(
                    account.map(|account| account.to_bytes()),
                ))
            }
            RpcRequest::SubmitTransaction(bytes) => {
                if bytes.len() > node::network_wire::MAX_TRANSACTION_BYTES {
                    return Err(RpcError::LimitExceeded);
                }
                let tx =
                    types::Transaction::decode(&bytes).map_err(|_| RpcError::InvalidRequest)?;
                node.submit_transaction(tx)
                    .inspect(|_| self.metrics.add(NodeMetric::TransactionsAccepted, 1))
                    .inspect_err(|_| self.metrics.add(NodeMetric::TransactionsRejected, 1))
                    .map(RpcResponse::TransactionAccepted)
                    .map_err(|error| match error {
                        NetworkNodeError::Input(_) => RpcError::InvalidRequest,
                        NetworkNodeError::Local(_) => RpcError::Unavailable,
                    })
            }
        }
    }
}

impl NetworkStatus {
    fn submit_potb(
        &self,
        node: &mut PeerNode,
        request: RpcRequest,
    ) -> Result<RpcResponse, RpcError> {
        let message = match request {
            RpcRequest::SubmitGovernance(bytes) => node::network_wire::NetworkMessage::Governance(
                consensus::governance::GovernanceCertificate::from_bytes(&bytes)
                    .map_err(|_| RpcError::InvalidRequest)?,
            ),
            RpcRequest::SubmitPotbAdmission(bytes) => {
                node::network_wire::NetworkMessage::PotbAdmission(
                    consensus::admission::AdmissionCertificate::from_bytes(&bytes)
                        .map_err(|_| RpcError::InvalidRequest)?,
                )
            }
            RpcRequest::SubmitPotbEvidence(bytes) => {
                node::network_wire::NetworkMessage::PotbEvidence(
                    consensus::history::HistoricalEvidence::from_bytes(&bytes)
                        .map_err(|_| RpcError::InvalidRequest)?,
                )
            }
            _ => unreachable!(),
        };
        node.submit_potb(message)
            .map(RpcResponse::PotbAccepted)
            .map_err(|error| match error {
                NetworkNodeError::Input(_) => RpcError::InvalidRequest,
                NetworkNodeError::Local(_) => {
                    self.storage_failed.store(true, Ordering::Release);
                    RpcError::Unavailable
                }
            })
    }
}

impl NetworkStatus {
    fn potb_handoff(&self, node: &PeerNode, height: u64) -> Result<RpcResponse, RpcError> {
        let handoff = node::handoff::read_potb_handoff(node.storage(), height).map_err(|_| {
            self.storage_failed.store(true, Ordering::Release);
            self.metrics.add(NodeMetric::LocalFailures, 1);
            RpcError::Unavailable
        })?;
        Ok(RpcResponse::PotbHandoff(
            handoff
                .map(|value| value.to_bytes())
                .transpose()
                .map_err(|_| RpcError::Unavailable)?,
        ))
    }
}
