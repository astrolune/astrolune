// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

use super::*;
use crate::{
    exchange::{read_packet, write_packet},
    provisioning::TransportAuthority,
};
use std::{net::TcpListener, thread};

const TIMEOUT: Duration = Duration::from_secs(3);

fn config(authority: &TransportAuthority, label: &str) -> PeerTlsConfig {
    let identity = authority.issue(label).unwrap();
    PeerTlsConfig::from_der(
        identity.ca_der,
        identity.certificate_der,
        identity.private_key_der.to_vec(),
    )
    .unwrap()
}

fn exchange(
    client: &PeerTlsConfig,
    server: PeerTlsConfig,
) -> (io::Result<Vec<u8>>, io::Result<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || -> io::Result<()> {
        let (socket, _) = listener.accept()?;
        // Emulate sockets accepted by the daemon's nonblocking listener on Windows.
        socket.set_nonblocking(true)?;
        let mut stream = server.accept(socket, TIMEOUT)?;
        let packet = read_packet(&mut stream, 100_000, TIMEOUT)?;
        write_packet(&mut stream, &packet, 100_000, TIMEOUT)
    });
    let result = (|| {
        let socket = TcpStream::connect(address)?;
        let mut stream = client.connect(socket, TIMEOUT)?;
        write_packet(&mut stream, &vec![0x5a; 70_000], 100_000, TIMEOUT)?;
        read_packet(&mut stream, 100_000, TIMEOUT)
    })();
    (result, worker.join().unwrap())
}

#[test]
fn mutual_tls_exchanges_packets_across_multiple_records() {
    let authority = TransportAuthority::generate().unwrap();
    let (client, server) = exchange(&config(&authority, "client"), config(&authority, "server"));
    assert_eq!(client.unwrap(), vec![0x5a; 70_000]);
    server.unwrap();
}

#[test]
fn unrelated_network_ca_is_rejected() {
    let first = TransportAuthority::generate().unwrap();
    let second = TransportAuthority::generate().unwrap();
    let (client, server) = exchange(&config(&first, "client"), config(&second, "server"));
    assert!(client.is_err());
    assert!(server.is_err());
}

#[test]
fn missing_and_untrusted_client_certificates_are_rejected() {
    let authority = TransportAuthority::generate().unwrap();
    let alien = TransportAuthority::generate()
        .unwrap()
        .issue("alien")
        .unwrap();
    for untrusted in [false, true] {
        let mut client = config(&authority, "client");
        let identity = authority.issue("trusted").unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(identity.ca_der)).unwrap();
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots);
        let mut client_config = if untrusted {
            builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(alien.certificate_der.clone())],
                    PrivatePkcs8KeyDer::from(alien.private_key_der.to_vec()).into(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        client_config.alpn_protocols = vec![PEER_ALPN.to_vec()];
        client.client = Arc::new(client_config);
        let (client, server) = exchange(&client, config(&authority, "server"));
        assert!(client.is_err());
        assert!(server.is_err());
    }
}

#[test]
fn absent_or_wrong_application_protocol_is_rejected() {
    let authority = TransportAuthority::generate().unwrap();
    for protocols in [Vec::new(), vec![b"unrelated/protocol".to_vec()]] {
        let mut client = config(&authority, "client");
        Arc::make_mut(&mut client.client).alpn_protocols = protocols;
        let (client, server) = exchange(&client, config(&authority, "server"));
        assert!(client.is_err());
        assert!(server.is_err());
    }
}

#[test]
fn startup_rejects_mismatched_key_root_and_malformed_inputs() {
    let authority = TransportAuthority::generate().unwrap();
    let first = authority.issue("first").unwrap();
    let second = authority.issue("second").unwrap();
    let alien = TransportAuthority::generate()
        .unwrap()
        .issue("alien")
        .unwrap();
    for (ca, cert, key) in [
        (
            first.ca_der.clone(),
            first.certificate_der.clone(),
            second.private_key_der.to_vec(),
        ),
        (
            alien.ca_der,
            first.certificate_der.clone(),
            first.private_key_der.to_vec(),
        ),
        (
            first.ca_der.clone(),
            vec![0; 1024],
            first.private_key_der.to_vec(),
        ),
        (
            first.ca_der.clone(),
            first.certificate_der.clone(),
            vec![0; 64],
        ),
        (
            first.ca_der,
            vec![0; MAX_IDENTITY_BYTES + 1],
            first.private_key_der.to_vec(),
        ),
        (Vec::new(), Vec::new(), Vec::new()),
    ] {
        assert!(PeerTlsConfig::from_der(ca, cert, key).is_err());
    }
}

#[test]
fn startup_rejects_expired_wrong_name_and_missing_usages() {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let authority = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    for defect in 0..4 {
        let mut params = CertificateParams::new(vec![
            if defect == 1 {
                "wrong-name"
            } else {
                PEER_DNS_NAME
            }
            .into(),
        ])
        .unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        if defect == 0 {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        } else if defect == 2 {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        } else if defect == 3 {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &authority).unwrap();
        assert!(
            PeerTlsConfig::from_der(
                authority.der().to_vec(),
                cert.der().to_vec(),
                key.serialize_der()
            )
            .is_err(),
            "defect {defect}"
        );
    }
}

#[test]
fn plaintext_and_stalled_handshakes_are_rejected_within_deadline() {
    let authority = TransportAuthority::generate().unwrap();
    for plaintext in [false, true] {
        let server = config(&authority, "server");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        if plaintext {
            write_packet(&mut client, b"plaintext is not TLS", 100, TIMEOUT).unwrap();
        }
        let start = Instant::now();
        assert!(server.accept(socket, Duration::from_millis(150)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[test]
fn trickled_tls_records_cannot_extend_packet_deadline() {
    let authority = TransportAuthority::generate().unwrap();
    let server = config(&authority, "server");
    let client = config(&authority, "client");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, received) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut stream = server.accept(socket, TIMEOUT).unwrap();
        ready.send(()).unwrap();
        read_packet(&mut stream, 100, Duration::from_millis(150))
    });
    let mut stream = client
        .connect(TcpStream::connect(address).unwrap(), TIMEOUT)
        .unwrap();
    received.recv_timeout(TIMEOUT).unwrap();
    for byte in [1, 0, 0, 0, 0x42] {
        if stream
            .write_all(&[byte])
            .and_then(|()| stream.flush())
            .is_err()
        {
            break;
        }
        thread::sleep(Duration::from_millis(60));
    }
    assert!(worker.join().unwrap().is_err());
}
