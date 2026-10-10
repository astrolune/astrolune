// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Synchronous TCP transport for peer-to-peer frame exchange.
//!
//! Provides `TcpTransport` for outgoing connections and `TcpListener` for
//! incoming peers. Each connection reads and writes length-prefixed binary
//! frames using the existing `FrameEncoder` / `BoundedFrameDecoder`.
//!
//! Wire format matches the frame module: `[1 byte kind][4 bytes LE length][payload]`.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::admission::{AdmissionConfig, AdmissionController, Refusal};
use crate::error::NetworkError;
use crate::frame::{
    BoundedFrameDecoder, FRAME_HEADER_SIZE, FrameDecoder, FrameEncoder, MAX_FRAME_SIZE,
};
use crate::message::MessageKind;

/// Default connection timeout in milliseconds.
#[allow(dead_code)]
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Default read timeout for incoming frames in milliseconds.
const DEFAULT_READ_TIMEOUT_MS: u64 = 30000;

/// Maximum number of concurrent peer connections.
///
/// Identical to [`crate::admission::DEFAULT_MAX_TOTAL_CONNECTIONS`], which is the
/// value the admission controller actually enforces. The name is retained because
/// it is the historical name of the flat transport ceiling.
pub const MAX_PEERS: usize = crate::admission::DEFAULT_MAX_TOTAL_CONNECTIONS;

/// Identifies a remote peer on the network.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    /// TCP socket address of the peer.
    pub addr: String,
}

impl PeerId {
    /// Creates a new `PeerId` from a socket address string.
    #[must_use]
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_owned(),
        }
    }
}

/// A frame received from or ready to send to a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMessage {
    /// The sending or receiving peer.
    pub peer: PeerId,
    /// Decoded frame content.
    pub frame: OwnedFrame,
}

/// An owned version of `Frame` suitable for queuing and forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedFrame {
    /// Message kind discriminator.
    pub kind: MessageKind,
    /// Owned payload bytes.
    pub payload: Vec<u8>,
}

impl OwnedFrame {
    /// Creates a new `OwnedFrame` from a kind and payload.
    #[must_use]
    pub fn new(kind: MessageKind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }

    /// Encodes this frame into the wire format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        FrameEncoder::encode(self.kind, &self.payload)
    }
}

/// Errors specific to TCP transport operations.
#[derive(Debug)]
pub enum TransportError {
    /// Network-level I/O error.
    Io(std::io::Error),
    /// The peer sent an invalid frame.
    InvalidFrame(NetworkError),
    /// Connection attempt timed out.
    Timeout,
    /// Peer manager has reached capacity.
    PeerLimitReached,
    /// The peer is not connected.
    NotConnected,
    /// Bounded admission control refused this peer or this received message.
    Refused(Refusal),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::InvalidFrame(e) => write!(f, "invalid frame: {e}"),
            Self::Timeout => write!(f, "connection timed out"),
            Self::PeerLimitReached => write!(f, "peer limit reached"),
            Self::NotConnected => write!(f, "peer not connected"),
            Self::Refused(reason) => write!(f, "admission refused: {reason}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidFrame(e) => Some(e),
            Self::Refused(reason) => Some(reason),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

use std::fmt;

/// A managed connection to a single peer.
///
/// Wraps a `TcpStream` with frame-level reading and writing. The connection
/// is non-blocking in the sense that individual reads have timeouts, but
/// the public API is synchronous.
pub struct PeerConnection {
    /// Identity of the remote peer.
    pub peer_id: PeerId,
    /// Buffered reader for the TCP stream.
    reader: BufReader<TcpStream>,
    /// Raw TCP stream for writing (cloned from the original).
    writer: TcpStream,
    /// Frame decoder with the configured size limit.
    decoder: BoundedFrameDecoder,
}

impl PeerConnection {
    /// Connects to a remote peer at the given address.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on connection failure.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_millis(
            DEFAULT_READ_TIMEOUT_MS,
        )))?;
        stream.set_write_timeout(Some(std::time::Duration::from_millis(
            DEFAULT_READ_TIMEOUT_MS,
        )))?;

        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);

        Ok(Self {
            peer_id: PeerId::new(addr),
            reader,
            writer,
            decoder: BoundedFrameDecoder::new(MAX_FRAME_SIZE),
        })
    }

    /// Creates a `PeerConnection` from an already-accepted `TcpStream`.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if socket options cannot be set.
    pub fn from_stream(addr: &str, stream: TcpStream) -> Result<Self, TransportError> {
        stream.set_read_timeout(Some(std::time::Duration::from_millis(
            DEFAULT_READ_TIMEOUT_MS,
        )))?;
        stream.set_write_timeout(Some(std::time::Duration::from_millis(
            DEFAULT_READ_TIMEOUT_MS,
        )))?;

        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);

        Ok(Self {
            peer_id: PeerId::new(addr),
            reader,
            writer,
            decoder: BoundedFrameDecoder::new(MAX_FRAME_SIZE),
        })
    }

    /// Reads exactly one frame from the peer.
    ///
    /// Reads the 4-byte length prefix, then the payload, and decodes
    /// the frame header. Returns the decoded frame on success.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O or protocol errors.
    pub fn read_frame(&mut self) -> Result<OwnedFrame, TransportError> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        self.reader.read_exact(&mut header)?;

        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(TransportError::InvalidFrame(NetworkError::LimitExceeded));
        }

        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + len);
        buf.extend_from_slice(&header);
        buf.resize(FRAME_HEADER_SIZE + len, 0);
        self.reader.read_exact(&mut buf[FRAME_HEADER_SIZE..])?;

        let frame = self
            .decoder
            .decode(&buf)
            .map_err(TransportError::InvalidFrame)?;

        Ok(OwnedFrame {
            kind: frame.kind,
            payload: frame.payload.to_vec(),
        })
    }

    /// Writes a single frame to the peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O errors.
    pub fn write_frame(&mut self, frame: &OwnedFrame) -> Result<(), TransportError> {
        let encoded = frame.encode();
        self.writer.write_all(&encoded)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Sends a frame and reads the response in one call.
    ///
    /// Useful for request-response patterns during handshakes.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O or protocol errors.
    pub fn send_and_receive(&mut self, request: &OwnedFrame) -> Result<OwnedFrame, TransportError> {
        self.write_frame(request)?;
        self.read_frame()
    }

    /// Returns the peer's identity.
    #[must_use]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// Manages a set of connected peers with thread-safe access.
///
/// Peers are stored in a `BTreeMap` keyed by `PeerId` and protected by a
/// `Mutex` so that multiple threads can send and receive concurrently.
pub struct PeerManager {
    /// Active peer connections indexed by peer ID.
    peers: Arc<Mutex<std::collections::BTreeMap<PeerId, PeerConnection>>>,
    /// Maximum number of allowed peers.
    max_peers: usize,
    /// Bounded admission control shared by every caller of this manager.
    admission: Arc<Mutex<AdmissionController>>,
    /// Origin of the monotonic tick this transport supplies to admission.
    started: Instant,
}

impl PeerManager {
    /// Creates a new peer manager with the default peer limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(MAX_PEERS)
    }

    /// Creates a new peer manager with a custom peer limit.
    ///
    /// Every other admission bound keeps its documented default.
    #[must_use]
    pub fn with_limit(max_peers: usize) -> Self {
        Self::with_admission(AdmissionConfig::default().with_max_total_connections(max_peers))
    }

    /// Creates a new peer manager with explicit admission bounds.
    #[must_use]
    pub fn with_admission(config: AdmissionConfig) -> Self {
        Self {
            peers: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            max_peers: config.max_total_connections,
            admission: Arc::new(Mutex::new(AdmissionController::new(config))),
            started: Instant::now(),
        }
    }

    /// Returns the shared admission controller.
    ///
    /// A caller that observes an offence this transport cannot see, such as a
    /// failed signature check, records it against the same controller through
    /// this handle, supplying a tick from [`PeerManager::tick_ms`].
    #[must_use]
    pub fn admission(&self) -> Arc<Mutex<AdmissionController>> {
        self.admission.clone()
    }

    /// Milliseconds since this manager was created.
    ///
    /// The admission module never reads a clock. This transport reads one on its
    /// behalf and supplies a tick that cannot decrease within one process.
    #[must_use]
    pub fn tick_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Locks the shared controller, treating a poisoned lock as a dead manager.
    fn admission_locked(&self) -> Result<MutexGuard<'_, AdmissionController>, TransportError> {
        self.admission
            .lock()
            .map_err(|_| TransportError::NotConnected)
    }

    /// Returns an admitted slot, ignoring a poisoned lock that already failed closed.
    fn release(&self, peer_id: &PeerId) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.release_connection(peer_id);
        }
    }

    /// Inserts an admitted connection, releasing the slot of any it replaces.
    fn register(&self, conn: PeerConnection) -> Result<PeerId, TransportError> {
        let peer_id = conn.peer_id().clone();
        let Ok(mut peers) = self.peers.lock() else {
            self.release(&peer_id);
            return Err(TransportError::NotConnected);
        };
        let replaced = peers.insert(peer_id.clone(), conn).is_some();
        drop(peers);
        if replaced {
            self.release(&peer_id);
        }
        Ok(peer_id)
    }

    /// Connects to a remote peer and adds it to the managed set.
    ///
    /// Admission is consulted before a socket is created. The earlier order
    /// established the connection first and only then compared the peer count
    /// against the limit, so a caller already at capacity still completed a
    /// handshake and immediately discarded it; a refused dial now costs nothing.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if admission refuses the peer or the connection
    /// fails.
    pub fn connect(&self, addr: &str) -> Result<PeerId, TransportError> {
        let peer_id = PeerId::new(addr);
        let tick = self.tick_ms();
        self.admission_locked()?
            .admit_outbound(&peer_id, tick)
            .map_err(TransportError::Refused)?;
        match PeerConnection::connect(addr) {
            Ok(conn) => self.register(conn),
            Err(error) => {
                self.release(&peer_id);
                Err(error)
            }
        }
    }

    /// Registers an accepted incoming connection.
    ///
    /// Admission is consulted before the stream is wrapped, so a refused caller
    /// has its socket dropped here instead of being retained in the managed set.
    /// Refusal covers the total cap, the per-source connection cap, the
    /// per-source connection-attempt budget and an active ban.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if admission refuses the peer or socket options
    /// cannot be set.
    pub fn accept(&self, addr: &str, stream: TcpStream) -> Result<PeerId, TransportError> {
        let peer_id = PeerId::new(addr);
        let tick = self.tick_ms();
        self.admission_locked()?
            .admit_inbound(&peer_id, tick)
            .map_err(TransportError::Refused)?;
        match PeerConnection::from_stream(addr, stream) {
            Ok(conn) => self.register(conn),
            Err(error) => {
                self.release(&peer_id);
                Err(error)
            }
        }
    }

    /// Removes a peer from the managed set and returns its admitted slot.
    ///
    /// Returns `true` if the peer was found and removed, `false` otherwise.
    #[must_use]
    pub fn disconnect(&self, peer_id: &PeerId) -> bool {
        let removed = self
            .peers
            .lock()
            .is_ok_and(|mut peers| peers.remove(peer_id).is_some());
        if removed {
            self.release(peer_id);
        }
        removed
    }

    /// Sends a frame to a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the peer is not connected or the write fails.
    pub fn send(&self, peer_id: &PeerId, frame: &OwnedFrame) -> Result<(), TransportError> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| TransportError::NotConnected)?;
        let conn = peers.get_mut(peer_id).ok_or(TransportError::NotConnected)?;
        conn.write_frame(frame)
    }

    /// Reads a frame from a specific peer and charges it against admission.
    ///
    /// A banned peer is refused before the read. A malformed or oversized frame
    /// records the offence its [`NetworkError`] names. An accepted frame is
    /// charged to the message-count and byte-volume budgets of its
    /// [`crate::admission::MessageClass`] at the peer, source and process tiers;
    /// a refused charge is itself scored and the frame is dropped.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the peer is not connected, the read fails, or
    /// admission refuses the peer or the frame.
    pub fn receive(&self, peer_id: &PeerId) -> Result<OwnedFrame, TransportError> {
        if self.admission_locked()?.is_banned(peer_id, self.tick_ms()) {
            return Err(TransportError::Refused(Refusal::Banned));
        }
        let read = {
            let mut peers = self
                .peers
                .lock()
                .map_err(|_| TransportError::NotConnected)?;
            let conn = peers.get_mut(peer_id).ok_or(TransportError::NotConnected)?;
            conn.read_frame()
        };
        let tick = self.tick_ms();
        let frame = match read {
            Ok(frame) => frame,
            Err(TransportError::InvalidFrame(error)) => {
                self.admission_locked()?
                    .record_network_error(peer_id, error, tick);
                return Err(TransportError::InvalidFrame(error));
            }
            Err(error) => return Err(error),
        };
        self.admission_locked()?
            .charge_message(peer_id, frame.kind, frame.payload.len(), tick)
            .map_err(TransportError::Refused)?;
        Ok(frame)
    }

    /// Broadcasts a frame to all connected peers.
    ///
    /// Sends to each peer sequentially. If a send fails, the error for
    /// that peer is recorded but transmission continues to remaining peers.
    ///
    /// Returns a list of `(PeerId, Result<(), TransportError>)` for each peer.
    #[must_use]
    pub fn broadcast(&self, frame: &OwnedFrame) -> Vec<(PeerId, Result<(), TransportError>)> {
        let Ok(peers) = self.peers.lock() else {
            return Vec::new();
        };

        let ids: Vec<PeerId> = peers.keys().cloned().collect();
        drop(peers);

        ids.iter()
            .map(|id| {
                let result = self.send(id, frame);
                (id.clone(), result)
            })
            .collect()
    }

    /// Maximum concurrent peers this manager admits.
    #[must_use]
    pub const fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Returns the number of currently connected peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.lock().map_or(0, |peers| peers.len())
    }

    /// Returns the list of connected peer IDs.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .lock()
            .map(|peers| peers.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronous TCP listener that accepts incoming peer connections.
///
/// Runs a blocking accept loop. Each accepted connection is handed to the
/// provided callback for registration with the `PeerManager`.
pub struct TcpPeerListener {
    /// Bound TCP listener socket.
    listener: std::net::TcpListener,
    /// Shared peer manager for registering accepted connections.
    peer_manager: Arc<PeerManager>,
}

impl TcpPeerListener {
    /// Binds a new listener on the given address and registers peers
    /// with the provided `PeerManager`.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the address cannot be bound.
    pub fn bind(addr: &str, peer_manager: Arc<PeerManager>) -> Result<Self, std::io::Error> {
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self {
            listener,
            peer_manager,
        })
    }

    /// Runs the accept loop, blocking until the process terminates.
    ///
    /// Each accepted connection is registered with the peer manager.
    /// Errors during acceptance or registration are printed to stderr
    /// but do not terminate the loop.
    pub fn run(&self) -> std::io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let addr = stream
                        .peer_addr()
                        .map_or_else(|_| "unknown".into(), |a| a.to_string());

                    match self.peer_manager.accept(&addr, stream) {
                        Ok(peer_id) => {
                            println!("accepted peer: {peer_id:?}");
                        }
                        Err(e) => {
                            eprintln!("failed to register peer {addr}: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("accept error: {e}");
                }
            }
        }
        Ok(())
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::Offence;
    use crate::message::MessageKind;

    /// Binds a loopback listener and returns one accepted server side of a pair.
    ///
    /// The client half is returned too so the caller keeps the socket open for as
    /// long as the assertion needs it.
    fn accepted_pair() -> (std::net::TcpListener, TcpStream, TcpStream, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, peer) = listener.accept().unwrap();
        (listener, client, server, peer.to_string())
    }

    #[test]
    fn owned_frame_encode_roundtrip() {
        let frame = OwnedFrame::new(MessageKind::Hello, b"ping".to_vec());
        let encoded = frame.encode();
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Hello);
        assert_eq!(frame.payload, b"ping");
    }

    #[test]
    fn peer_manager_new_default() {
        let mgr = PeerManager::new();
        assert_eq!(mgr.peer_count(), 0);
        assert_eq!(mgr.connected_peers().len(), 0);
    }

    #[test]
    fn peer_manager_with_limit() {
        let mgr = PeerManager::with_limit(5);
        assert_eq!(mgr.max_peers(), 5);
        assert_eq!(
            mgr.admission()
                .lock()
                .unwrap()
                .config()
                .max_total_connections,
            5,
            "the peer limit must be the admission total cap"
        );
    }

    #[test]
    fn connect_is_refused_before_a_socket_is_created_when_the_total_cap_is_full() {
        let mgr = PeerManager::with_limit(0);
        // 127.0.0.1:9 is the discard port and is not listening in this test, so a
        // dial would fail slowly; admission must refuse before reaching it.
        match mgr.connect("127.0.0.1:9") {
            Err(TransportError::Refused(Refusal::TotalConnections)) => {}
            other => panic!("expected a total-cap refusal, got {other:?}"),
        }
        assert_eq!(mgr.peer_count(), 0);
    }

    #[test]
    fn connect_is_refused_without_dialling_an_unparsable_endpoint() {
        let mgr = PeerManager::new();
        match mgr.connect("not-an-address") {
            Err(TransportError::Refused(Refusal::UnknownSource)) => {}
            other => panic!("expected an unknown-source refusal, got {other:?}"),
        }
    }

    #[test]
    fn accept_refuses_a_connection_past_the_per_source_cap_and_retains_nothing() {
        let config = AdmissionConfig {
            max_connections_per_source: 1,
            ..AdmissionConfig::default()
        };
        let mgr = PeerManager::with_admission(config);
        let (listener, _first_client, first, first_peer) = accepted_pair();
        let address = listener.local_addr().unwrap();
        let _second_client = TcpStream::connect(address).unwrap();
        let (second, second_peer) = listener.accept().unwrap();

        mgr.accept(&first_peer, first).unwrap();
        assert_eq!(mgr.peer_count(), 1);
        match mgr.accept(&second_peer.to_string(), second) {
            Err(TransportError::Refused(Refusal::SourceConnections)) => {}
            other => panic!("expected a per-source refusal, got {other:?}"),
        }
        assert_eq!(
            mgr.peer_count(),
            1,
            "a refused connection must not be retained in the managed set"
        );
    }

    #[test]
    fn disconnect_returns_the_admitted_slot_so_the_source_can_reconnect() {
        let config = AdmissionConfig {
            max_connections_per_source: 1,
            ..AdmissionConfig::default()
        };
        let mgr = PeerManager::with_admission(config);
        let (listener, _client, server, peer) = accepted_pair();
        let id = mgr.accept(&peer, server).unwrap();
        assert_eq!(mgr.admission().lock().unwrap().total_connections(), 1);
        assert!(mgr.disconnect(&id));
        assert_eq!(
            mgr.admission().lock().unwrap().total_connections(),
            0,
            "disconnect must return the admitted slot"
        );

        let address = listener.local_addr().unwrap();
        let _again = TcpStream::connect(address).unwrap();
        let (server, peer) = listener.accept().unwrap();
        mgr.accept(&peer.to_string(), server)
            .expect("a released slot must be reusable by the same source");
    }

    #[test]
    fn accept_refuses_a_banned_source_recorded_through_the_shared_controller() {
        let mgr = PeerManager::new();
        let (_listener, _client, server, peer) = accepted_pair();
        let controller = mgr.admission();
        {
            let mut admission = controller.lock().unwrap();
            let tick = mgr.tick_ms();
            for round in 0..3 {
                admission.record_offence(&PeerId::new(&peer), Offence::OversizedPayload, tick);
                assert!(
                    round < 2 || admission.is_banned(&PeerId::new(&peer), tick),
                    "round={round}: three oversized payloads must reach the default threshold"
                );
            }
        }
        match mgr.accept(&peer, server) {
            Err(TransportError::Refused(Refusal::Banned)) => {}
            other => panic!("expected a ban refusal, got {other:?}"),
        }
        assert_eq!(mgr.peer_count(), 0);
    }

    #[test]
    fn disconnect_nonexistent_peer() {
        let mgr = PeerManager::new();
        assert!(!mgr.disconnect(&PeerId::new("127.0.0.1:8080")));
    }

    #[test]
    fn peer_id_equality() {
        let a = PeerId::new("127.0.0.1:9000");
        let b = PeerId::new("127.0.0.1:9000");
        assert_eq!(a, b);
    }

    #[test]
    fn transport_error_display() {
        let err = TransportError::Timeout;
        assert_eq!(format!("{err}"), "connection timed out");

        let err = TransportError::PeerLimitReached;
        assert_eq!(format!("{err}"), "peer limit reached");

        let err = TransportError::Refused(Refusal::Banned);
        assert_eq!(format!("{err}"), "admission refused: source is banned");
        let source = std::error::Error::source(&err).map(ToString::to_string);
        assert_eq!(source, Some("source is banned".to_owned()));
    }

    #[test]
    fn listen_and_connect() {
        let mgr = Arc::new(PeerManager::with_limit(2));
        let listener = TcpPeerListener::bind("127.0.0.1:0", mgr.clone()).unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the accept loop so it registers incoming connections
        std::thread::spawn(move || {
            listener.run().ok();
        });

        // Connect a client — the accept loop registers it automatically
        let _client = PeerConnection::connect(&addr.to_string()).unwrap();

        // Give the accept loop a moment to register the peer
        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(mgr.peer_count(), 1);
        let peers = mgr.connected_peers();
        let peer_id = peers.first().unwrap().clone();

        let _ = mgr.disconnect(&peer_id);
        assert_eq!(mgr.peer_count(), 0);
    }
}
