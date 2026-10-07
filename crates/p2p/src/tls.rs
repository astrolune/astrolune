// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! TLS 1.3 with mandatory mutual authentication under an explicit network CA.
//! Transport admission is separate from consensus voting authority.

use crate::exchange::{PacketIo, remaining};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

/// Network service identity in certificates; IP addresses are routing hints only.
pub const PEER_DNS_NAME: &str = "astrolune-peer";
/// Application protocol negotiated before accepting any network messages.
pub const PEER_ALPN: &[u8] = b"astrolune/p2p/1";
const MAX_IDENTITY_BYTES: usize = 64 * 1024;

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

/// Shared client and server configurations. Contains private key material; never logged.
#[derive(Clone)]
pub struct PeerTlsConfig {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
}

impl PeerTlsConfig {
    /// Loads one DER CA, one DER leaf certificate, and a DER PKCS#8 private key.
    /// Input files are bounded and validated even when the caller only checks configuration.
    pub fn from_directory(directory: &Path) -> io::Result<Self> {
        Self::from_der(
            read_bounded(&directory.join("ca.der"))?,
            read_bounded(&directory.join("cert.der"))?,
            read_bounded(&directory.join("key.der"))?,
        )
    }

    /// Builds mutual TLS using only the supplied network trust root.
    /// Checks the local certificate's chain, validity, service name, usages, and key match.
    pub fn from_der(ca: Vec<u8>, certificate: Vec<u8>, key: Vec<u8>) -> io::Result<Self> {
        let key = zeroize::Zeroizing::new(key);
        if [&ca, &certificate, &key]
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES)
        {
            return Err(invalid("empty or oversized TLS identity"));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca)).map_err(invalid)?;
        let roots = Arc::new(roots);
        let certificate = CertificateDer::from(certificate);
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .map_err(invalid)?;
        client_verifier
            .verify_client_cert(&certificate, &[], UnixTime::now())
            .map_err(invalid)?;
        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .map_err(invalid)?;
        server_verifier
            .verify_server_cert(
                &certificate,
                &[],
                &ServerName::try_from(PEER_DNS_NAME).map_err(invalid)?,
                &[],
                UnixTime::now(),
            )
            .map_err(invalid)?;
        let private_key = PrivatePkcs8KeyDer::from(key.to_vec());
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(invalid)?
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![certificate.clone()], private_key.clone_key().into())
            .map_err(invalid)?;
        client.alpn_protocols = vec![PEER_ALPN.to_vec()];
        client.resumption = rustls::client::Resumption::disabled();
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(invalid)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![certificate], private_key.into())
            .map_err(invalid)?;
        server.alpn_protocols = vec![PEER_ALPN.to_vec()];
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        Ok(Self {
            client: Arc::new(client),
            server: Arc::new(server),
        })
    }

    /// Authenticates an outgoing connection under a single handshake deadline.
    pub fn connect(&self, stream: TcpStream, timeout: Duration) -> io::Result<PeerStream> {
        let connection = ClientConnection::new(
            self.client.clone(),
            ServerName::try_from(PEER_DNS_NAME).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let mut stream = StreamOwned::new(connection, DeadlineSocket::new(stream, timeout)?);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        check_protocol(&stream.conn)?;
        Ok(PeerStream(StreamKind::Client(Box::new(stream))))
    }

    /// Authenticates an incoming connection before exposing application bytes.
    pub fn accept(&self, stream: TcpStream, timeout: Duration) -> io::Result<PeerStream> {
        let connection = ServerConnection::new(self.server.clone()).map_err(invalid)?;
        let mut stream = StreamOwned::new(connection, DeadlineSocket::new(stream, timeout)?);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        check_protocol(&stream.conn)?;
        Ok(PeerStream(StreamKind::Server(Box::new(stream))))
    }
}

fn check_protocol(connection: &rustls::CommonState) -> io::Result<()> {
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.alpn_protocol() != Some(PEER_ALPN)
        || connection.peer_certificates().is_none_or(<[_]>::is_empty)
    {
        return Err(invalid(
            "TLS peer authentication or application protocol missing",
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    File::open(path)?
        .take(MAX_IDENTITY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
        return Err(invalid("empty or oversized TLS identity file"));
    }
    Ok(std::mem::take(&mut *bytes))
}

struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineSocket {
    fn new(stream: TcpStream, timeout: Duration) -> io::Result<Self> {
        // Windows accepts can inherit a nonblocking listener's mode. Worker I/O is
        // blocking under socket deadlines, including every TLS handshake record.
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + timeout,
        })
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        remaining(self.deadline)?;
        self.stream.flush()
    }
}

enum StreamKind {
    Plain(DeadlineSocket),
    Client(Box<StreamOwned<ClientConnection, DeadlineSocket>>),
    Server(Box<StreamOwned<ServerConnection, DeadlineSocket>>),
}

/// A bounded packet stream. Plaintext construction is explicit and restricted to loopback.
pub struct PeerStream(StreamKind);

impl PeerStream {
    /// Opens an explicitly insecure local development connection.
    pub fn plaintext_local(stream: TcpStream, timeout: Duration) -> io::Result<Self> {
        if !stream.local_addr()?.ip().is_loopback() || !stream.peer_addr()?.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "plaintext peers must use loopback",
            ));
        }
        Ok(Self(StreamKind::Plain(DeadlineSocket::new(
            stream, timeout,
        )?)))
    }
}

impl PacketIo for PeerStream {
    fn set_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        remaining(deadline)?;
        match &mut self.0 {
            StreamKind::Plain(stream) => stream.deadline = deadline,
            StreamKind::Client(stream) => stream.sock.deadline = deadline,
            StreamKind::Server(stream) => stream.sock.deadline = deadline,
        }
        Ok(())
    }
}

impl Read for PeerStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &mut self.0 {
            StreamKind::Plain(stream) => stream.read(bytes),
            StreamKind::Client(stream) => stream.read(bytes),
            StreamKind::Server(stream) => stream.read(bytes),
        }
    }
}

impl Write for PeerStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            StreamKind::Plain(stream) => stream.write(bytes),
            StreamKind::Client(stream) => stream.write(bytes),
            StreamKind::Server(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            StreamKind::Plain(stream) => stream.flush(),
            StreamKind::Client(stream) => stream.flush(),
            StreamKind::Server(stream) => stream.flush(),
        }
    }
}

#[cfg(test)]
mod tests;
