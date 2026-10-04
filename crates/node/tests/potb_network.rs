// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Live admission, exclusion, standby participation, observer sync and durable authority.
#![allow(clippy::too_many_lines)]

#[path = "../../consensus/tests/support/potb.rs"]
mod support;
use consensus::potb_transition::PotbVerifier;
use keystore::{DurableSigner, SigningContext};
use node::{
    network::{NetworkNode, StaticNetwork},
    network_wire::{NetworkMessage, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
fn open(directory: &Directory, network: &StaticNetwork, seed: u8) -> NetworkNode {
    let path = directory.0.join(seed.to_string());
    let signer = DurableSigner::open(
        path.join("signing.journal"),
        SigningContext {
            chain_id: network.chain_id(),
            genesis: network.genesis_hash(),
        },
        [seed; 32],
    )
    .unwrap();
    NetworkNode::open(network.clone(), &path, signer, Duration::from_millis(100)).unwrap()
}
fn advance(nodes: &mut [NetworkNode], height: u64) {
    let now = Instant::now();
    for step in 0..400 {
        for index in 0..nodes.len() {
            if nodes[index].request().height >= height {
                continue;
            }
            let request = nodes[index].request();
            let responses: Vec<_> = nodes
                .iter()
                .map(|node| node.respond(request).unwrap())
                .collect();
            for response in responses {
                nodes[index].receive(&response).unwrap();
            }
            if nodes[index].request().height < height {
                nodes[index]
                    .tick(now + Duration::from_millis(step * 20))
                    .unwrap();
            }
        }
        if nodes.iter().all(|node| node.request().height == height) {
            return;
        }
    }
    panic!(
        "PoTB network stalled: {:?}",
        nodes
            .iter()
            .map(|node| (
                node.request().height,
                node.round(),
                node.missing_contributions()
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn gossip_includes_quorum_admission_and_evidence_then_recovers_every_role() {
    let (profile, keys) = support::fixture();
    let network = StaticNetwork::decode(&profile.to_bytes(), keys.clone()).unwrap();
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let initial = trusted.current().committee().clone();
    let directory = Directory(
        std::env::temp_dir().join(format!("astrolune-potb-network-{}", std::process::id())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    for seed in [1, 2, 3, 4, 99] {
        let path = directory.0.join(seed.to_string());
        std::fs::create_dir(&path).unwrap();
        drop(
            DurableSigner::create_protected(
                path.join("signing.journal"),
                SigningContext {
                    chain_id: network.chain_id(),
                    genesis: network.genesis_hash(),
                },
                [seed; 32],
            )
            .unwrap(),
        );
    }
    let admission = support::admission(trusted.current(), trusted.parent(), 99);
    let mut first = open(&directory, &network, 1);
    assert_eq!(
        first.submit_potb_admission(admission.clone()).unwrap(),
        admission.request().id()
    );
    drop(first);
    let mut nodes: Vec<_> = [1, 2, 3, 4, 99]
        .iter()
        .map(|seed| open(&directory, &network, *seed))
        .collect();
    assert!(nodes[4].is_standby());
    assert!(
        decode_exchange(
            network.genesis_hash(),
            &nodes[0].respond(nodes[0].request()).unwrap()
        )
        .unwrap()
        .iter()
        .any(|message| matches!(message, NetworkMessage::PotbAdmission(_)))
    );
    // All registered VRF contributors are necessary, even with an incumbent voting quorum.
    let now = Instant::now();
    for _ in 0..5 {
        for index in 0..3 {
            let responses: Vec<_> = nodes[..3]
                .iter()
                .map(|node| node.respond(nodes[index].request()).unwrap())
                .collect();
            for response in responses {
                nodes[index].receive(&response).unwrap();
            }
            nodes[index].tick(now).unwrap();
        }
    }
    assert!(nodes.iter().all(|node| node.request().height == 1));
    advance(&mut nodes, 2);
    let first = node::handoff::read_potb_handoff(nodes[0].storage(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(first.batch.admissions(), std::slice::from_ref(&admission));
    assert!(
        node::handoff::read_handoff(nodes[0].storage(), 1)
            .unwrap()
            .is_none()
    );
    trusted.apply(&first).unwrap();
    assert!(
        trusted
            .current()
            .records()
            .any(|(id, _)| id == support::identity(99))
    );
    assert!(nodes[0].submit_potb_admission(admission.clone()).is_err());
    let evidence = support::evidence(
        trusted.current(),
        &initial,
        &[initial.context().unwrap().root()],
        1,
    );
    assert_eq!(
        nodes[1].submit_potb_evidence(evidence.clone()).unwrap(),
        evidence.evidence().offence_id()
    );
    let wire = encode_exchange(
        network.genesis_hash(),
        &[
            NetworkMessage::PotbEvidence(evidence.clone()),
            NetworkMessage::PotbAdmission(admission),
        ],
    )
    .unwrap();
    assert_eq!(nodes[2].receive(&wire).unwrap(), 1); // stale admission only
    advance(&mut nodes, 3);
    let second = node::handoff::read_potb_handoff(nodes[0].storage(), 2)
        .unwrap()
        .unwrap();
    assert_eq!(second.batch.evidence(), std::slice::from_ref(&evidence));
    trusted.apply(&second).unwrap();
    assert!(nodes[0].is_standby());
    assert!(nodes[0].submit_potb_evidence(evidence).is_err());
    advance(&mut nodes, 8);
    let checkpoint = *nodes[0].storage().checkpoint().unwrap();
    assert!(
        nodes
            .iter()
            .all(|node| node.storage().checkpoint() == Some(&checkpoint))
    );
    let mut observer = ObserverNode::open(network.clone(), &directory.0.join("observer")).unwrap();
    while observer.request().height < 8 {
        assert_eq!(
            observer
                .receive(&nodes[0].respond(observer.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    drop(observer);
    let observer = ObserverNode::open(network.clone(), &directory.0.join("observer")).unwrap();
    network.verify_storage(observer.storage()).unwrap();
    for height in 3..8 {
        trusted
            .apply(
                &node::handoff::read_potb_handoff(observer.storage(), height)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(trusted.parent(), checkpoint.block);
    drop(observer);
    drop(nodes);
    let mut recovered: Vec<_> = [1, 2, 3, 4, 99]
        .iter()
        .map(|seed| open(&directory, &network, *seed))
        .collect();
    assert!(recovered[0].is_standby());
    advance(&mut recovered, 10);
    assert!(
        recovered
            .iter()
            .all(|node| node.storage().checkpoint().unwrap().height == 9)
    );
}

#[test]
fn restored_pending_admission_refreshes_an_already_complete_single_member_batch() {
    let (profile, mut keys) = support::fixture();
    keys.truncate(1);
    let mut genesis = profile.genesis().clone();
    genesis
        .validators
        .retain(|member| member.id == support::identity(1));
    genesis.committee_size = 1;
    let profile =
        consensus::potb_transition::PotbConfiguration::new(genesis, profile.policy()).unwrap();
    let network = StaticNetwork::with_potb(profile.clone(), keys.clone()).unwrap();
    let directory = Directory(
        std::env::temp_dir().join(format!("astrolune-potb-single-{}", std::process::id())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    std::fs::create_dir(directory.0.join("1")).unwrap();
    drop(
        DurableSigner::create_protected(
            directory.0.join("1/signing.journal"),
            SigningContext {
                chain_id: network.chain_id(),
                genesis: network.genesis_hash(),
            },
            [1; 32],
        )
        .unwrap(),
    );
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let admission = support::admission(trusted.current(), trusted.parent(), 99);
    let mut node = open(&directory, &network, 1);
    node.submit_potb_admission(admission.clone()).unwrap();
    drop(node);
    let mut nodes = vec![open(&directory, &network, 1)];
    advance(&mut nodes, 2);
    let first = node::handoff::read_potb_handoff(nodes[0].storage(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(first.batch.admissions(), &[admission]);
}
