// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Streaming RPC trust transfer, hostile peers and bounded resumable progress.

#[path = "../../consensus/tests/support/rotation.rs"]
mod support;

use consensus::rotation::{CommitteeHandoff, HandoffVerifier};
use rpc::{ClientError, TcpRpcClient};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn result(handoff: &CommitteeHandoff) -> String {
    use std::fmt::Write as _;
    let bytes = handoff.to_bytes().unwrap();
    let mut hex = String::new();
    for byte in bytes {
        write!(hex, "{byte:02x}").unwrap();
    }
    format!("\"{hex}\"")
}

fn peer(replies: Vec<(u64, String)>) -> (TcpRpcClient, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = TcpRpcClient::new(listener.local_addr().unwrap(), Duration::from_secs(3)).unwrap();
    let task = thread::spawn(move || {
        for (height, result) in replies {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "expected request did not arrive");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).unwrap();
            let length = u32::from_le_bytes(prefix) as usize;
            assert!(length < 1024);
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            let request = rpc::json::parse_json(std::str::from_utf8(&request).unwrap()).unwrap();
            assert_eq!(
                request.get("method").unwrap().as_str(),
                Some("committee_handoff")
            );
            assert_eq!(
                request
                    .get("params")
                    .unwrap()
                    .get("height")
                    .unwrap()
                    .as_str(),
                Some(height.to_string().as_str())
            );
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_le_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (client, task)
}

#[test]
fn streams_from_genesis_and_resumes_only_the_verified_prefix() {
    let (genesis, keys) = support::fixture();
    let initial = HandoffVerifier::new(&genesis, &keys).unwrap();
    let first = support::handoff(&genesis, &initial);
    let mut middle = initial.clone();
    middle.apply(&first).unwrap();
    let second = support::handoff(&genesis, &middle);
    let mut expected = middle.clone();
    expected.apply(&second).unwrap();
    let (client, task) = peer(vec![(1, result(&first)), (2, "null".into())]);
    let mut trusted = initial;
    assert!(
        client
            .advance_handoffs(&mut trusted, 3, 2, Duration::from_secs(3))
            .is_err()
    );
    task.join().unwrap();
    assert_eq!(trusted, middle);
    let (client, task) = peer(vec![(2, result(&second))]);
    client
        .advance_handoffs(&mut trusted, 3, 1, Duration::from_secs(3))
        .unwrap();
    task.join().unwrap();
    assert_eq!(trusted, expected);
}

#[test]
fn malformed_forked_incomplete_or_wrong_height_handoffs_never_advance_authority() {
    let (genesis, keys) = support::fixture();
    let initial = HandoffVerifier::new(&genesis, &keys).unwrap();
    let valid = support::handoff(&genesis, &initial);
    let mut replies = vec!["null".into(), "7".into(), "\"00\"".into(), "\"zz\"".into()];
    replies.push(format!(
        "\"{}\"",
        "ab".repeat(CommitteeHandoff::MAX_BYTES + 1)
    ));
    for mutation in 0..5 {
        let mut changed = valid.clone();
        match mutation {
            0 => changed.header.height += 1,
            1 => changed.header.parent.0[0] ^= 1,
            2 => changed.certificate.signatures[0].signature[0] ^= 1,
            3 => {
                changed.contributions = consensus::rotation::VrfBatch::new(
                    changed.contributions.entries()[..3].to_vec(),
                )
                .unwrap();
            }
            _ => changed.header.state_root.0[0] ^= 1,
        }
        replies.push(result(&changed));
    }
    let mut foreign = genesis.clone();
    foreign.chain_id += 1;
    replies.push(result(&support::handoff(
        &foreign,
        &HandoffVerifier::new(&foreign, &keys).unwrap(),
    )));
    for reply in replies {
        let (client, task) = peer(vec![(1, reply)]);
        let mut trusted = initial.clone();
        assert!(
            client
                .advance_handoffs(&mut trusted, 2, 1, Duration::from_secs(3))
                .is_err()
        );
        task.join().unwrap();
        assert_eq!(trusted, initial);
    }
}

#[test]
fn invalid_limits_fail_before_connecting_and_complete_positions_need_no_peer() {
    let (genesis, keys) = support::fixture();
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let initial = trusted.clone();
    let client =
        TcpRpcClient::new("127.0.0.1:1".parse().unwrap(), Duration::from_millis(10)).unwrap();
    assert!(matches!(
        client.advance_handoffs(&mut trusted, 100, 3, Duration::from_secs(1)),
        Err(ClientError::LimitExceeded)
    ));
    for (target, timeout) in [
        (0, Duration::from_secs(1)),
        (2, Duration::ZERO),
        (2, Duration::from_secs(3601)),
    ] {
        assert!(matches!(
            client.advance_handoffs(&mut trusted, target, 3, timeout),
            Err(ClientError::Protocol(_))
        ));
    }
    client
        .advance_handoffs(&mut trusted, 1, 0, Duration::from_secs(1))
        .unwrap();
    assert_eq!(trusted, initial);
}
