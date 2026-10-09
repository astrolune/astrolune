// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Streaming RPC trust transfer, hostile peers and bounded resumable progress.

#[path = "../../consensus/tests/support/potb.rs"]
mod support;

use consensus::potb_transition::{PotbBatch, PotbHandoff, PotbVerifier};
use rpc::{ClientError, TcpRpcClient};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn result(handoff: &PotbHandoff) -> String {
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
            // Windows accepts inherit the nonblocking listener's mode, which the
            // timeouts below do not clear. Reads and writes here are blocking.
            stream.set_nonblocking(false).unwrap();
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
                Some("potb_handoff")
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
fn authenticates_only_a_complete_prefix_and_commits_after_the_consumer() {
    let (profile, keys) = support::fixture();
    let initial = PotbVerifier::new(&profile, &keys).unwrap();
    let first = support::handoff(&initial, support::batch(initial.current()));
    let mut middle = initial.clone();
    middle.apply(&first).unwrap();
    let second = support::handoff(&middle, support::batch(middle.current()));
    let (client, worker) = peer(vec![(1, result(&first)), (2, "null".into())]);
    let mut trusted = initial.clone();
    assert!(
        client
            .advance_potb_handoffs(&mut trusted, 3, 2, Duration::from_secs(5))
            .is_err()
    );
    worker.join().unwrap();
    assert_eq!(trusted, middle);
    let (client, worker) = peer(vec![(2, result(&second))]);
    assert!(
        client
            .advance_potb_handoffs_with(&mut trusted, 3, 1, Duration::from_secs(5), |_| Err(
                ClientError::Protocol("consumer rejected")
            ))
            .is_err()
    );
    worker.join().unwrap();
    assert_eq!(trusted, middle);
    let (client, worker) = peer(vec![(2, result(&second))]);
    client
        .advance_potb_handoffs(&mut trusted, 3, 1, Duration::from_secs(5))
        .unwrap();
    worker.join().unwrap();
    middle.apply(&second).unwrap();
    assert_eq!(trusted, middle);
}

#[test]
fn rejects_wrong_height_parent_quorum_roster_and_frontier_without_advancing() {
    let (profile, keys) = support::fixture();
    let initial = PotbVerifier::new(&profile, &keys).unwrap();
    let valid = support::handoff(&initial, support::batch(initial.current()));
    let mut replies = vec![
        "null".into(),
        "\"zz\"".into(),
        format!("\"{}\"", "ab".repeat(PotbHandoff::MAX_BYTES + 1)),
    ];
    for mutation in 0..6 {
        let mut changed = valid.clone();
        match mutation {
            0 => changed.header.height += 1,
            1 => changed.header.parent.0[0] ^= 1,
            2 => changed.certificate.signatures[0].signature[0] ^= 1,
            3 => {
                changed.batch = PotbBatch::new(
                    consensus::rotation::VrfBatch::new(
                        changed.batch.contributions().entries()[..3].to_vec(),
                    )
                    .unwrap(),
                    vec![],
                    vec![],
                )
                .unwrap();
            }
            4 => changed.header.state_root.0[0] ^= 1,
            _ => {
                changed.next_state = state::StateValueProof::create(
                    profile
                        .materialize(&keys)
                        .unwrap()
                        .snapshot()
                        .unwrap()
                        .as_ref(),
                    &consensus::potb_transition::potb_state_key(),
                )
                .unwrap();
            }
        }
        replies.push(result(&changed));
    }
    for reply in replies {
        let (client, worker) = peer(vec![(1, reply)]);
        let mut trusted = initial.clone();
        assert!(
            client
                .advance_potb_handoffs(&mut trusted, 2, 1, Duration::from_secs(5))
                .is_err()
        );
        worker.join().unwrap();
        assert_eq!(trusted, initial);
    }
}

#[test]
fn limits_fail_without_connecting_and_genesis_proofs_require_the_separate_namespace() {
    let (profile, keys) = support::fixture();
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let initial = trusted.clone();
    let client =
        TcpRpcClient::new("127.0.0.1:1".parse().unwrap(), Duration::from_millis(10)).unwrap();
    assert!(matches!(
        client.advance_potb_handoffs(&mut trusted, 100, 3, Duration::from_secs(1)),
        Err(ClientError::LimitExceeded)
    ));
    for (target, timeout) in [
        (0, Duration::from_secs(1)),
        (2, Duration::ZERO),
        (2, Duration::from_secs(3601)),
    ] {
        assert!(matches!(
            client.advance_potb_handoffs(&mut trusted, target, 3, timeout),
            Err(ClientError::Protocol(_))
        ));
    }
    client
        .advance_potb_handoffs(&mut trusted, 1, 0, Duration::from_secs(1))
        .unwrap();
    assert_eq!(trusted, initial);
    let database = profile.materialize(&keys).unwrap();
    let key = types::StateKey(b"missing".to_vec());
    let proof = rpc::CertifiedStateProof::create(database.snapshot().unwrap().as_ref(), &key, None)
        .unwrap();
    assert_eq!(
        proof.verify_potb_genesis(&profile, &keys, &key).unwrap(),
        None
    );
    assert!(proof.verify_with_potb(&initial, &key, 0).is_err());
    assert!(proof.verify(profile.genesis(), &keys, &key, 0).is_err());
    let mut policy = profile.policy();
    policy.epoch_blocks += 1;
    let other =
        consensus::potb_transition::PotbConfiguration::new(profile.genesis().clone(), policy)
            .unwrap();
    assert!(proof.verify_potb_genesis(&other, &keys, &key).is_err());
}

use state::StateDatabase;
