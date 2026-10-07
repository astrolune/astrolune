// Copyright (c) 2026 Ankerin
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
fn retained_checkpoints_require_independent_pins_and_resume_all_profiles() {
    use node::network::RecoveryCheckpoint;
    use storage::ChainStorage;
    for profile_kind in 0..4 {
        let (base, keys) = support::fixture();
        let network = match profile_kind {
            0 => {
                let mut genesis = base.genesis().clone();
                genesis.version = 1;
                genesis.committee_size = genesis.validators.len();
                StaticNetwork::new(genesis, keys).unwrap()
            }
            1 => StaticNetwork::new(base.genesis().clone(), keys).unwrap(),
            2 => StaticNetwork::with_potb(base, keys).unwrap(),
            _ => StaticNetwork::with_potb(support::governed(base), keys).unwrap(),
        };
        let directory = Directory(std::env::temp_dir().join(format!(
            "astrolune-retained-{profile_kind}-{}",
            std::process::id()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        for seed in 1..=4 {
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
        let mut nodes: Vec<_> = (1..=4)
            .map(|seed| open(&directory, &network, seed))
            .collect();
        if profile_kind == 3 {
            let (base, keys) = support::fixture();
            let trusted = PotbVerifier::new(&support::governed(base), &keys).unwrap();
            nodes[0]
                .submit_governance(support::parameters(trusted.current(), trusted.parent()))
                .unwrap();
        }
        advance(&mut nodes, 5);
        let original = *nodes[0].storage().checkpoint().unwrap();
        let destination = directory.0.join("retained");
        let point = network
            .export_retained(nodes[0].storage(), 3, &destination)
            .unwrap();
        assert_eq!(point.checkpoint().height, 1);
        assert!(
            network
                .export_retained(nodes[0].storage(), 3, &destination)
                .is_err()
        );
        let bytes = point.to_bytes();
        assert!(RecoveryCheckpoint::from_bytes(&bytes, types::Hash256([9; 32])).is_err());
        let mut altered = bytes.clone();
        altered[40] ^= 1;
        assert!(RecoveryCheckpoint::from_bytes(&altered, point.id()).is_err());
        let decoded = RecoveryCheckpoint::from_bytes(&bytes, point.id()).unwrap();
        assert_eq!(decoded, point);
        let pinned = network.clone().with_checkpoint(decoded).unwrap();
        {
            let store = ChainStorage::open(destination.join("chain.bin")).unwrap();
            assert_eq!(store.block_count(), 3);
            assert!(store.read_finalized(1).unwrap().is_none());
            assert_eq!(pinned.verify_storage(&store).unwrap(), original);
            assert!(network.verify_storage(&store).is_err());
            let second = directory.0.join("retained-again");
            let later = pinned.export_retained(&store, 1, &second).unwrap();
            assert_eq!(later.checkpoint().height, 3);
            let later_network = network.clone().with_checkpoint(later).unwrap();
            let store = ChainStorage::open(second.join("chain.bin")).unwrap();
            assert_eq!(later_network.verify_storage(&store).unwrap(), original);
            assert!(pinned.verify_storage(&store).is_err());
        }
        assert!(ObserverNode::open(network.clone(), &destination).is_err());
        let mut observer = ObserverNode::open(pinned.clone(), &destination).unwrap();
        assert_eq!(observer.request().height, 5);
        advance(&mut nodes, 7);
        while observer.request().height < 7 {
            observer
                .receive(&nodes[0].respond(observer.request()).unwrap())
                .unwrap();
        }
        assert_eq!(
            observer.storage().checkpoint(),
            nodes[0].storage().checkpoint()
        );
        drop(observer);
        assert_eq!(
            ObserverNode::open(pinned, &destination)
                .unwrap()
                .request()
                .height,
            7
        );
        let zero = directory.0.join("checkpoint-only");
        let latest = network
            .export_retained(nodes[0].storage(), 0, &zero)
            .unwrap();
        let latest_network = network.clone().with_checkpoint(latest).unwrap();
        assert_eq!(
            ChainStorage::open(zero.join("chain.bin"))
                .unwrap()
                .block_count(),
            0
        );
        // A separately provisioned test signer can recover and bind the current committee.
        let signer = DurableSigner::create_protected(
            zero.join("signing.journal"),
            SigningContext {
                chain_id: network.chain_id(),
                genesis: network.genesis_hash(),
            },
            [1; 32],
        )
        .unwrap();
        let recovered =
            NetworkNode::open(latest_network, &zero, signer, Duration::from_millis(100)).unwrap();
        assert_eq!(recovered.request().height, 7);
        assert_eq!(
            recovered.storage().checkpoint(),
            nodes[0].storage().checkpoint()
        );
    }
}

#[test]
fn governance_gossip_survives_restart_activates_at_epoch_and_observer_authenticates_it() {
    let (base, keys) = support::fixture();
    let profile = support::governed(base);
    let network = StaticNetwork::decode(&profile.to_bytes(), keys.clone()).unwrap();
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let certificate = support::parameters(trusted.current(), trusted.parent());
    let directory = Directory(std::env::temp_dir().join(format!(
        "astrolune-governance-network-{}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    for seed in 1..=4 {
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
    let message = NetworkMessage::Governance(certificate.clone());
    let bytes = encode_exchange(network.genesis_hash(), std::slice::from_ref(&message)).unwrap();
    assert_eq!(
        decode_exchange(network.genesis_hash(), &bytes).unwrap(),
        vec![message]
    );
    let mut first = open(&directory, &network, 1);
    assert_eq!(
        first.submit_governance(certificate.clone()).unwrap(),
        certificate.request().id()
    );
    drop(first);
    let mut nodes: Vec<_> = (1..=4)
        .map(|seed| open(&directory, &network, seed))
        .collect();
    advance(&mut nodes, 3);
    for height in 1..=2 {
        trusted
            .apply(
                &node::handoff::read_potb_handoff(nodes[0].storage(), height)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(
        trusted.current().governance().unwrap().active().prices,
        certificate.request().prices
    );
    assert_eq!(
        trusted.current().committee().capacity(),
        certificate.request().capacity
    );
    assert!(nodes[0].submit_governance(certificate).is_err());
    advance(&mut nodes, 5);
    let observer_path = directory.0.join("observer");
    std::fs::create_dir(&observer_path).unwrap();
    let mut observer = ObserverNode::open(network.clone(), &observer_path).unwrap();
    for _ in 0..4 {
        observer
            .receive(&nodes[0].respond(observer.request()).unwrap())
            .unwrap();
    }
    assert_eq!(observer.request().height, 5);
    drop(observer);
    assert_eq!(
        ObserverNode::open(network.clone(), &observer_path)
            .unwrap()
            .request()
            .height,
        5
    );
    drop(nodes);
    for seed in 1..=4 {
        assert_eq!(open(&directory, &network, seed).request().height, 5);
    }
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
