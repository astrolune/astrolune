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
use std::sync::{Arc, Mutex};

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
const MAX_PEERS: usize = 128;

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
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::InvalidFrame(e) => write!(f, "invalid frame: {e}"),
            Self::Timeout => write!(f, "connection timed out"),
            Self::PeerLimitReached => write!(f, "peer limit reached"),
            Self::NotConnected => write!(f, "peer not connected"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidFrame(e) => Some(e),
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
}

impl PeerManager {
    /// Creates a new peer manager with the default peer limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            max_peers: MAX_PEERS,
        }
    }

    /// Creates a new peer manager with a custom peer limit.
    #[must_use]
    pub fn with_limit(max_peers: usize) -> Self {
        Self {
            peers: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            max_peers,
        }
    }

    /// Connects to a remote peer and adds it to the managed set.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the connection fails or the peer limit
    /// has been reached.
    pub fn connect(&self, addr: &str) -> Result<PeerId, TransportError> {
        let conn = PeerConnection::connect(addr)?;
        let peer_id = conn.peer_id().clone();

        let mut peers = self
            .peers
            .lock()
            .map_err(|_| TransportError::NotConnected)?;
        if peers.len() >= self.max_peers {
            return Err(TransportError::PeerLimitReached);
        }
        peers.insert(peer_id.clone(), conn);

        Ok(peer_id)
    }

    /// Registers an accepted incoming connection.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the peer limit has been reached.
    pub fn accept(&self, addr: &str, stream: TcpStream) -> Result<PeerId, TransportError> {
        let conn = PeerConnection::from_stream(addr, stream)?;
        let peer_id = conn.peer_id().clone();

        let mut peers = self
            .peers
            .lock()
            .map_err(|_| TransportError::NotConnected)?;
        if peers.len() >= self.max_peers {
            return Err(TransportError::PeerLimitReached);
        }
        peers.insert(peer_id.clone(), conn);

        Ok(peer_id)
    }

    /// Removes a peer from the managed set.
    ///
    /// Returns `true` if the peer was found and removed, `false` otherwise.
    #[must_use]
    pub fn disconnect(&self, peer_id: &PeerId) -> bool {
        self.peers
            .lock()
            .is_ok_and(|mut peers| peers.remove(peer_id).is_some())
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

    /// Reads a frame from a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the peer is not connected or the read fails.
    pub fn receive(&self, peer_id: &PeerId) -> Result<OwnedFrame, TransportError> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| TransportError::NotConnected)?;
        let conn = peers.get_mut(peer_id).ok_or(TransportError::NotConnected)?;
        conn.read_frame()
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
    use crate::message::MessageKind;

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
        assert_eq!(mgr.max_peers, 5);
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
