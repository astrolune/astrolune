// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded authenticated sessions, scoped discovery and reconnect backoff.

use super::{
    DaemonError, IO_TIMEOUT, NetworkNodeError, Options, PeerNode, PeerTransport, Workers, io_error,
};
use node::{
    compact_wire::{CompactRequest, MAX_COMPACT_REQUEST_BYTES},
    network::PreparedExchange,
    network_wire::{MAX_EXCHANGE_BYTES, SyncRequest},
};
use p2p::{
    PeerId,
    admission::{AdmissionConfig, AdmissionController, MessageClass, Offence},
    discovery::{self, PeerDirectory},
    exchange::{read_packet, write_packet},
    tls::PeerStream,
};
use std::{
    collections::BTreeMap,
    io,
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use telemetry::{NodeMetric, NodeMetrics};
use types::Hash256;

const SESSION_MESSAGES: u32 = 128;
const SESSION_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(super) struct PeerRuntime {
    directory: Arc<Mutex<PeerDirectory>>,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    transport: PeerTransport,
    node: Arc<Mutex<PeerNode>>,
    genesis: Hash256,
    discovery: bool,
    compact_blocks: bool,
    /// Bounded admission control shared by the accept loop and every session.
    admission: Arc<Mutex<AdmissionController>>,
    /// Origin of the monotonic tick this runtime supplies to admission.
    started: Instant,
    pub(super) metrics: Arc<NodeMetrics>,
}
impl PeerRuntime {
    pub(super) fn new(
        options: &Options,
        local: SocketAddr,
        node: Arc<Mutex<PeerNode>>,
        transport: PeerTransport,
        metrics: Arc<NodeMetrics>,
    ) -> Result<Self, DaemonError> {
        let directory =
            PeerDirectory::new(options.discovery, local, &options.peers).map_err(io_error)?;
        let genesis = node
            .lock()
            .map_err(|_| io_error("node lock poisoned"))?
            .request()
            .genesis;
        metrics.set(NodeMetric::KnownPeers, directory.addresses().len() as u64);
        Ok(Self {
            directory: Arc::new(Mutex::new(directory)),
            stop: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            transport,
            node,
            genesis,
            discovery: options.discovery.is_some(),
            compact_blocks: options.compact_blocks,
            admission: Arc::new(Mutex::new(AdmissionController::new(
                AdmissionConfig::default()
                    .with_max_total_connections(options.config.network.max_peers),
            ))),
            started: Instant::now(),
            metrics,
        })
    }

    /// Milliseconds since this runtime was created.
    ///
    /// The admission module never reads a clock. The daemon reads one on its
    /// behalf and supplies a tick that cannot decrease within one process.
    fn tick(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether bounded admission refuses an inbound connection from `peer`.
    ///
    /// A poisoned controller refuses: an unenforced limit is worse than a closed
    /// connection. A granted slot is returned by `release_inbound`.
    pub(super) fn refuse_inbound(&self, peer: &PeerId) -> bool {
        let tick = self.tick();
        !self
            .admission
            .lock()
            .is_ok_and(|mut admission| admission.admit_inbound(peer, tick).is_ok())
    }

    /// Returns one admitted inbound slot to the controller.
    pub(super) fn release_inbound(&self, peer: &PeerId) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.release_connection(peer);
        }
    }

    /// Whether bounded admission is currently refusing this remote address.
    fn banned(&self, peer: &PeerId) -> bool {
        let tick = self.tick();
        self.admission
            .lock()
            .is_ok_and(|mut admission| admission.is_banned(peer, tick))
    }

    /// Records one offence against the source address of `peer`.
    fn score(&self, peer: &PeerId, offence: Offence) {
        let tick = self.tick();
        if let Ok(mut admission) = self.admission.lock() {
            admission.record_offence(peer, offence, tick);
        }
    }

    /// Records the offence an I/O failure implies, if it implies one at all.
    ///
    /// Only a decode failure is scored. A closed connection, an expired deadline
    /// and an orderly session rotation are ordinary and never offences.
    fn score_io(&self, peer: &PeerId, error: &io::Error) {
        if error.kind() == io::ErrorKind::InvalidData {
            self.score(peer, Offence::InvalidFrame);
        }
    }

    /// Charges one inbound request against bounded admission.
    ///
    /// A catch-up request obliges this node to read and encode finalized history,
    /// so it is charged to the block budget rather than to a cheap class. A
    /// refusal ends the session; it does not queue or delay the request.
    fn charge_request(&self, peer: &PeerId, bytes: usize) -> Result<(), DaemonError> {
        let tick = self.tick();
        let mut admission = self
            .admission
            .lock()
            .map_err(|_| io_error("admission lock poisoned"))?;
        admission
            .charge_class(peer, MessageClass::Blocks, bytes, tick)
            .map_err(|reason| {
                self.metrics.add(NodeMetric::SessionLimitDrops, 1);
                io_error(reason)
            })
    }
    pub(super) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    fn directory(&self) -> io::Result<std::sync::MutexGuard<'_, PeerDirectory>> {
        self.directory
            .lock()
            .map_err(|_| io::Error::other("peer directory lock poisoned"))
    }
    fn frame(&self, payload: &[u8], maximum: usize) -> io::Result<Vec<u8>> {
        if !self.discovery {
            return Ok(payload.to_vec());
        }
        discovery::encode(
            self.genesis,
            &self.directory()?.advertisement(),
            payload,
            maximum,
        )
        .map_err(invalid)
    }
    fn unpack<'a>(
        &self,
        bytes: &'a [u8],
        maximum: usize,
    ) -> io::Result<(Vec<SocketAddr>, &'a [u8])> {
        if !self.discovery {
            return Ok((Vec::new(), bytes));
        }
        discovery::decode(bytes, self.genesis, maximum).map_err(invalid)
    }
    fn limit(&self, maximum: usize) -> usize {
        maximum
            + if self.discovery {
                discovery::MAX_OVERHEAD
            } else {
                0
            }
    }
    fn learn(&self, hints: &[SocketAddr]) -> io::Result<()> {
        let mut directory = self.directory()?;
        directory.learn(hints);
        self.metrics
            .set(NodeMetric::KnownPeers, directory.addresses().len() as u64);
        Ok(())
    }
    pub(super) fn spawn(&self) -> Result<Workers, DaemonError> {
        let (sender, receiver) = mpsc::sync_channel(4);
        let runtime = self.clone();
        let manager = std::thread::Builder::new()
            .name("peer-manager".into())
            .spawn(move || {
                if runtime.manage(&sender).is_err() {
                    runtime.metrics.add(NodeMetric::LocalFailures, 1);
                    runtime.failed.store(true, Ordering::Release);
                    runtime.stop();
                }
            })
            .map_err(io_error)?;
        Ok(Workers {
            receiver,
            handles: vec![manager],
        })
    }
    fn manage(&self, sender: &mpsc::SyncSender<PreparedExchange>) -> io::Result<()> {
        let mut handles: BTreeMap<SocketAddr, std::thread::JoinHandle<()>> = BTreeMap::new();
        let result = (|| {
            while !self.stop.load(Ordering::Acquire) {
                let finished: Vec<_> = handles
                    .iter()
                    .filter(|(_, handle)| handle.is_finished())
                    .map(|(address, _)| *address)
                    .collect();
                for address in finished {
                    if let Some(handle) = handles.remove(&address) {
                        let _ = handle.join();
                    }
                }
                for address in self.directory()?.addresses() {
                    if handles.len() >= discovery::MAX_PEERS {
                        break;
                    }
                    if handles.contains_key(&address) {
                        continue;
                    }
                    let runtime = self.clone();
                    let sender = sender.clone();
                    let handle = std::thread::Builder::new()
                        .name(format!("peer-{address}"))
                        .spawn(move || {
                            if runtime.poll(address, &sender).is_err() {
                                runtime.failed.store(true, Ordering::Release);
                                runtime.stop();
                            }
                        })?;
                    handles.insert(address, handle);
                }
                self.pause(Duration::from_millis(100));
            }
            Ok(())
        })();
        self.stop();
        for (_, handle) in handles {
            let _ = handle.join();
        }
        result
    }
    fn pause(&self, delay: Duration) {
        let end = Instant::now() + delay;
        while !self.stop.load(Ordering::Acquire) {
            let Some(remaining) = end.checked_duration_since(Instant::now()) else {
                break;
            };
            std::thread::sleep(remaining.min(Duration::from_millis(50)));
        }
    }
    fn poll(
        &self,
        address: SocketAddr,
        sender: &mpsc::SyncSender<PreparedExchange>,
    ) -> io::Result<()> {
        let mut session: Option<Session> = None;
        let mut backoff = 100_u64;
        let mut compact = self.compact_blocks;
        let mut next_height = None;
        while !self.stop.load(Ordering::Acquire) && self.directory()?.addresses().contains(&address)
        {
            if session.as_ref().is_some_and(|value| {
                value.count >= SESSION_MESSAGES || value.started.elapsed() >= SESSION_LIFETIME
            }) {
                session = None;
            }
            let result =
                self.exchange_with_fallback(address, &mut session, &mut compact, next_height);
            {
                let mut directory = self.directory()?;
                directory.result(address, result.is_ok());
                self.metrics
                    .set(NodeMetric::KnownPeers, directory.addresses().len() as u64);
            }
            if let Ok(exchange) = result {
                self.metrics.add(NodeMetric::Exchanges, 1);
                let finalized = exchange.finalized_height();
                if finalized.is_none() {
                    next_height = None;
                }
                match sender.try_send(exchange) {
                    Ok(()) => {
                        next_height = finalized.and_then(|height| height.checked_add(1));
                    }
                    Err(mpsc::TrySendError::Full(_)) => self.metrics.add(NodeMetric::QueueDrops, 1),
                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                }
                backoff = 100;
                self.pause(Duration::from_millis(50));
            } else {
                session = None;
                self.pause(Duration::from_millis(backoff));
                backoff = (backoff * 2).min(5000);
            }
        }
        Ok(())
    }
    fn exchange(
        &self,
        address: SocketAddr,
        session: &mut Option<Session>,
        compact: bool,
        next_height: Option<u64>,
    ) -> io::Result<PreparedExchange> {
        let remote = PeerId::new(&address.to_string());
        if session.is_none() {
            // A banned peer is not dialled. The caller treats this like any other
            // failed exchange, so the existing backoff bounds the retry rate.
            if self.banned(&remote) {
                return Err(io::Error::other("peer refused by local admission"));
            }
            let connect = || {
                self.transport
                    .connect(TcpStream::connect_timeout(&address, IO_TIMEOUT)?)
            };
            let stream =
                connect().inspect_err(|_| self.metrics.add(NodeMetric::ConnectionFailures, 1))?;
            self.metrics.add(NodeMetric::ConnectionsOpened, 1);
            self.metrics.add(NodeMetric::OutgoingSessions, 1);
            *session = Some(Session {
                stream,
                started: Instant::now(),
                count: 0,
                metrics: self.metrics.clone(),
            });
        }
        let (request, dictionary) = {
            let node = self
                .node
                .lock()
                .map_err(|_| io::Error::other("node lock poisoned"))?;
            let mut request = node.request();
            request.height = poll_height(request.height, next_height);
            (request, compact.then(|| node.compact_dictionary()))
        };
        let maximum = if compact {
            MAX_COMPACT_REQUEST_BYTES
        } else {
            48
        };
        let payload = dictionary.as_ref().map_or_else(
            || request.encode(),
            |known| CompactRequest::new(request, known).encode(),
        );
        let framed = self.frame(&payload, maximum)?;
        let session = session
            .as_mut()
            .ok_or_else(|| io::Error::other("missing peer session"))?;
        let mut exchange = || {
            write_packet(
                &mut session.stream,
                &framed,
                self.limit(maximum),
                IO_TIMEOUT,
            )?;
            let bytes = read_packet(
                &mut session.stream,
                self.limit(MAX_EXCHANGE_BYTES),
                IO_TIMEOUT,
            )?;
            let (hints, payload) = self.unpack(&bytes, MAX_EXCHANGE_BYTES)?;
            // Retain the complete decode for the node loop instead of decoding again
            // under its mutex. Message validation still runs against current node state.
            let prepared = match &dictionary {
                Some(known) => PreparedExchange::decode_compact(self.genesis, payload, known),
                None => PreparedExchange::decode(self.genesis, payload),
            }
            .map_err(invalid)?;
            self.learn(&hints)?;
            session.count += 1;
            Ok(prepared)
        };
        exchange().inspect_err(|error| {
            self.metrics.add(NodeMetric::ExchangeFailures, 1);
            self.score_io(&remote, error);
        })
    }
    fn exchange_with_fallback(
        &self,
        address: SocketAddr,
        session: &mut Option<Session>,
        compact: &mut bool,
        next_height: Option<u64>,
    ) -> io::Result<PreparedExchange> {
        let result = self.exchange(address, session, *compact, next_height);
        if result.is_err() && *compact && session.is_some() {
            // A legacy peer can reject the new request, or reconstruction can fail.
            // Start a fresh stream and keep the legacy preference for this polling
            // worker, including session rotations, to avoid repeated failed probes.
            *compact = false;
            *session = None;
            return self.exchange(address, session, false, next_height);
        }
        result
    }
    /// Serves one admitted inbound session.
    ///
    /// `peer` is the already-admitted endpoint whose slot the caller holds. Every
    /// request is charged against bounded admission before any history is read,
    /// and a malformed request or a foreign genesis namespace is scored against
    /// that endpoint's source address. Admission decides nothing about message
    /// validity: the ordinary genesis, committee and signature checks still run.
    pub(super) fn serve(
        &self,
        stream: TcpStream,
        storage_failed: &AtomicBool,
        peer: &PeerId,
    ) -> Result<(), DaemonError> {
        let mut stream = self.transport.accept(stream).map_err(io_error)?;
        let started = Instant::now();
        for _ in 0..SESSION_MESSAGES {
            if self.stop.load(Ordering::Acquire) || started.elapsed() >= SESSION_LIFETIME {
                break;
            }
            let timeout = IO_TIMEOUT.min(SESSION_LIFETIME.saturating_sub(started.elapsed()));
            if timeout.is_zero() {
                break;
            }
            let bytes = read_packet(&mut stream, self.limit(MAX_COMPACT_REQUEST_BYTES), timeout)
                .map_err(|error| {
                    self.score_io(peer, &error);
                    io_error(error)
                })?;
            self.charge_request(peer, bytes.len())?;
            // Discovery-enabled nodes also serve old fixed-profile peers without learning routes.
            let (hints, payload, wrapped) =
                if bytes.len() == 48 || bytes.starts_with(b"ALCQ\x01\0\0\0") {
                    (Vec::new(), bytes.as_slice(), false)
                } else {
                    let (hints, payload) =
                        self.unpack(&bytes, MAX_COMPACT_REQUEST_BYTES)
                            .map_err(|error| {
                                self.score_io(peer, &error);
                                io_error(error)
                            })?;
                    (hints, payload, true)
                };
            let compact = if payload.len() == 48 {
                None
            } else {
                Some(CompactRequest::decode(payload).map_err(|error| {
                    self.score(peer, Offence::InvalidFrame);
                    io_error(error)
                })?)
            };
            let request = compact.as_ref().map_or_else(
                || {
                    SyncRequest::decode(payload).map_err(|error| {
                        self.score(peer, Offence::InvalidFrame);
                        io_error(error)
                    })
                },
                |request| Ok(request.sync()),
            )?;
            let prepared = {
                let node = self
                    .node
                    .lock()
                    .map_err(|_| io_error("node lock poisoned"))?;
                node.prepare_response(request).map_err(|error| {
                    // `prepare_response` reports an input failure only for a peer
                    // whose trusted genesis namespace differs, which honest
                    // current input cannot do.
                    if let Some(offence) = error.offence() {
                        self.score(peer, offence);
                    }
                    self.response_error(storage_failed, error)
                })?
            };
            // The response owns its messages. Encoding no longer holds up node
            // ticks, received messages or RPC operations behind the node mutex.
            let response = match compact {
                Some(request) => prepared.encode_compact(request.known()),
                None => prepared.encode(),
            }
            .map_err(|error| self.response_error(storage_failed, error))?;
            self.learn(&hints).map_err(io_error)?;
            let response = if wrapped {
                self.frame(&response, MAX_EXCHANGE_BYTES)
                    .map_err(io_error)?
            } else {
                response
            };
            let timeout = IO_TIMEOUT.min(SESSION_LIFETIME.saturating_sub(started.elapsed()));
            if timeout.is_zero() {
                break;
            }
            write_packet(
                &mut stream,
                &response,
                self.limit(MAX_EXCHANGE_BYTES),
                timeout,
            )
            .map_err(io_error)?;
        }
        Ok(())
    }

    fn response_error(&self, storage_failed: &AtomicBool, error: NetworkNodeError) -> DaemonError {
        if matches!(error, NetworkNodeError::Local(_)) {
            storage_failed.store(true, Ordering::Release);
            self.metrics.add(NodeMetric::LocalFailures, 1);
            eprintln!("Finalized history read failed: {error}");
        }
        io_error(error)
    }
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn poll_height(committed_next: u64, speculative_next: Option<u64>) -> u64 {
    speculative_next
        .filter(|height| *height >= committed_next && *height <= committed_next.saturating_add(4))
        .unwrap_or(committed_next)
}
struct Session {
    stream: PeerStream,
    started: Instant,
    count: u32,
    metrics: Arc<NodeMetrics>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.metrics.subtract(NodeMetric::OutgoingSessions, 1);
    }
}

#[cfg(test)]
mod tests;
