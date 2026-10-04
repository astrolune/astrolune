// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Framing, typed decoding, hostile responses, and absolute deadline coverage.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rpc::{ClientError, TcpRpcClient};
use types::{AccountState, Address, Hash256};

#[path = "../../consensus/tests/support/potb.rs"]
mod support;

#[test]
fn historical_proofs_distinguish_unavailability_and_reject_a_wrong_height() {
    use std::fmt::Write as _;
    let (profile, keys) = support::fixture();
    let state = profile.materialize(&keys).unwrap();
    let key = genesis::genesis_key();
    let proof = rpc::CertifiedStateProof::create(&state, &key, None).unwrap();
    let mut encoded = String::new();
    for byte in proof.to_bytes().unwrap() {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    for height in [0, 1, u64::MAX] {
        let (address, worker) = peer(response(&format!("\"{encoded}\"")));
        let result = client(address).state_proof_at(&key, height);
        if height == 0 {
            assert_eq!(result.unwrap(), Some(proof.clone()));
        } else {
            assert!(matches!(
                result,
                Err(ClientError::Protocol("state proof height mismatch"))
            ));
        }
        let request = worker.join().unwrap();
        assert!(request.contains(r#""method":"state_proof_at""#));
        assert!(request.contains(&format!(r#""height":"{height}""#)));
    }
    let (address, worker) = peer(response("null"));
    assert!(client(address).state_proof_at(&key, 5).unwrap().is_none());
    worker.join().unwrap();
    let (address, worker) = peer(response("null"));
    assert!(client(address).state_proof(&key).is_err());
    worker.join().unwrap();
}

fn peer(reply: Vec<u8>) -> (SocketAddr, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(&reply).unwrap();
        request
    });
    (address, handle)
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_le_bytes(prefix) as usize;
    assert!(length < 256 * 1024);
    let mut request = vec![0; length];
    stream.read_exact(&mut request).unwrap();
    String::from_utf8(request).unwrap()
}

fn frame(text: &str) -> Vec<u8> {
    let mut bytes = u32::try_from(text.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

fn response(result: &str) -> Vec<u8> {
    frame(&format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#))
}

fn client(address: SocketAddr) -> TcpRpcClient {
    TcpRpcClient::new(address, Duration::from_secs(3)).unwrap()
}

#[test]
fn decodes_real_wire_types_and_sends_expected_methods() {
    let (address, peer) = peer(response(&format!(
        r#"{{"chain_id":42,"finalized_height":9,"finalized_block":"{}"}}"#,
        "ab".repeat(32)
    )));
    let status = client(address).chain_status().unwrap();
    assert_eq!(status.chain_id, 42);
    assert_eq!(status.finalized_height, 9);
    assert_eq!(status.finalized_block, Hash256([0xab; 32]));
    assert!(peer.join().unwrap().contains(r#""method":"chain_status""#));

    let (address, peer) = self::peer(response(r#""0700000000000000ffffffffffffffff""#));
    assert_eq!(
        client(address).account(Address([1; 32])).unwrap(),
        Some(AccountState {
            nonce: 7,
            balance: u64::MAX
        })
    );
    assert!(peer.join().unwrap().contains(&Address([1; 32]).to_string()));

    let (address, peer) = self::peer(response("null"));
    assert_eq!(client(address).account(Address::ZERO).unwrap(), None);
    peer.join().unwrap();

    let (address, peer) = self::peer(response(&format!(r#""{}""#, "cd".repeat(32))));
    assert_eq!(
        client(address).submit_transaction(&[0xab, 0xcd]).unwrap(),
        Hash256([0xcd; 32])
    );
    assert!(peer.join().unwrap().contains(r#""data":"abcd""#));
}

#[test]
fn rejects_ambiguous_or_malformed_envelopes_and_typed_results() {
    for response in [
        r#"{"jsonrpc":"2.0","id":2,"result":null}"#.to_owned(),
        r#"{"jsonrpc":"1.0","id":1,"result":null}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"result":null,"error":null}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"result":null,"result":"bad"}"#.into(),
        r#"{"jsonrpc":"2.0","id":1}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"oops"}}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"chain_id":-1,"finalized_height":0,"finalized_block":"00"}}"#.into(),
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, "[".repeat(200)),
    ] {
        let (address, peer) = peer(frame(&response));
        assert!(matches!(client(address).chain_status(), Err(ClientError::Protocol(_))), "{response}");
        peer.join().unwrap();
    }
}

#[test]
fn rejects_oversized_empty_truncated_and_non_utf8_frames() {
    for bytes in [
        4097_u32.to_le_bytes().to_vec(),
        0_u32.to_le_bytes().to_vec(),
        vec![1, 0],
        vec![2, 0, 0, 0, b'{'],
        vec![1, 0, 0, 0, 0xff],
    ] {
        let (address, peer) = peer(bytes);
        assert!(client(address).chain_status().is_err());
        peer.join().unwrap();
    }
}

#[test]
fn malformed_hashes_and_accounts_are_not_success() {
    for result in [
        r#""""#,
        r#""0""#,
        r#""zz""#,
        r#""１２""#,
        "false",
        "7",
        "[]",
    ] {
        let (address, peer) = peer(response(result));
        assert!(client(address).account(Address::ZERO).is_err());
        peer.join().unwrap();
        let (address, peer) = self::peer(response(result));
        assert!(client(address).submit_transaction(&[1]).is_err());
        peer.join().unwrap();
    }
}

#[test]
fn remote_rejection_is_distinct_and_terminal_controls_are_escaped() {
    let (address, peer) = peer(frame(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad\n\u001b[31m"}}"#,
    ));
    let error = client(address).submit_transaction(&[1]).unwrap_err();
    assert!(matches!(error, ClientError::Remote { code: -32600, .. }));
    assert!(!error.to_string().contains('\x1b'));
    assert!(!error.to_string().contains('\n'));
    peer.join().unwrap();
}

#[test]
fn deadline_covers_the_entire_dripped_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        for byte in response("null") {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let started = Instant::now();
    assert!(client_with_timeout(address).chain_status().is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    peer.join().unwrap();
}

fn client_with_timeout(address: SocketAddr) -> TcpRpcClient {
    TcpRpcClient::new(address, Duration::from_millis(100)).unwrap()
}

#[test]
fn invalid_limits_fail_before_connecting() {
    let address = "127.0.0.1:0".parse().unwrap();
    assert!(TcpRpcClient::new(address, Duration::ZERO).is_err());
    assert!(TcpRpcClient::new(address, Duration::from_secs(61)).is_err());
    assert!(matches!(
        client(address).submit_transaction(&[]),
        Err(ClientError::LimitExceeded)
    ));
    assert!(matches!(
        client(address).submit_transaction(&vec![0; 65537]),
        Err(ClientError::LimitExceeded)
    ));
}

#[test]
fn receipt_wait_preserves_transport_failures_and_bounds_a_silent_peer() {
    let (address, task) = peer(vec![]);
    assert!(matches!(
        client(address).wait_receipt(Hash256::ZERO, Duration::from_secs(2)),
        Err(ClientError::Io(_))
    ));
    assert!(task.join().unwrap().contains("receipt"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        thread::sleep(Duration::from_millis(300));
        request
    });
    let start = Instant::now();
    assert_eq!(
        client(address)
            .wait_receipt(Hash256::ZERO, Duration::from_millis(100))
            .unwrap(),
        None
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(task.join().unwrap().contains("receipt"));
}
