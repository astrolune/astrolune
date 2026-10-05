// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Frozen cross-release bytes plus authenticated replay, independent of the fixture writer.

#[path = "support/compatibility.rs"]
mod compatibility;

use codec::{CanonicalDecode, CanonicalEncode};
use consensus::{
    DoubleVoteEvidence, FinalityCertificate, Vote,
    rotation::{CommitteeHandoff, HandoffVerifier},
};
use node::{
    BlockProducer, ProducerConfig,
    network::StaticNetwork,
    network_wire::{NetworkMessage, decode_exchange, encode_exchange},
};
use rpc::{CertifiedReceiptProof, CertifiedStateProof};
use state::StateDatabase;
use std::{collections::BTreeSet, path::PathBuf};
use types::{Address, Hash256, Transaction};

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/protocol-v1")
}

fn read(version: u16, name: &str) -> Vec<u8> {
    std::fs::read(directory().join(format!("genesis-v{version}/{name}.bin"))).unwrap()
}

#[test]
fn current_implementation_reproduces_the_frozen_protocol_corpus() {
    let expected = compatibility::build();
    let manifest = std::fs::read_to_string(directory().join("MANIFEST.blake2s")).unwrap();

    let mut seen = BTreeSet::new();

    for line in manifest.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);

        let [hash, length, name] = fields.as_slice() else {
            unreachable!()
        };
        assert!(seen.insert(*name));

        let bytes = std::fs::read(directory().join(name)).unwrap();
        assert_eq!(bytes.len(), length.parse::<usize>().unwrap(), "{name}");
        assert_eq!(crypto::blake2s_hash(&bytes).to_string(), *hash, "{name}");
        assert_eq!(
            &bytes,
            expected.get(*name).unwrap(),
            "protocol compatibility changed: {name}"
        );
    }

    assert_eq!(seen.len(), expected.len());
    assert_eq!(seen.len(), 50);
}

#[test]
fn frozen_history_authenticates_and_reexecutes_in_both_profiles() {
    for version in [1, 2] {
        replay(version);
    }
}

fn replay(version: u16) {
    let genesis = genesis::Genesis::decode(&read(version, "genesis")).unwrap();
    assert_eq!(genesis.version, version);

    let keys: Vec<[u8; 32]> = read(version, "public-keys").as_chunks::<32>().0.to_vec();
    let network = StaticNetwork::new(genesis.clone(), keys.clone()).unwrap();
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut state = genesis.materialize().unwrap();

    let mut checkpoint = storage::Checkpoint {
        height: 0,
        block: genesis.commitment().unwrap(),
        state_root: state.root(),
    };

    for height in 1..=2 {
        let tag = format!("height-{height}");

        let bytes = read(version, &format!("{tag}-network"));
        let messages = decode_exchange(genesis.commitment().unwrap(), &bytes).unwrap();
        assert_eq!(
            encode_exchange(genesis.commitment().unwrap(), &messages).unwrap(),
            bytes
        );

        let [NetworkMessage::Finalized { block, certificate }] = messages.as_slice() else {
            panic!("one finalized block required")
        };
        assert_eq!(block.header.height, height);
        assert_eq!(block.header.parent, checkpoint.block);
        assert_eq!(
            block.header.to_bytes(),
            read(version, &format!("{tag}-header"))
        );
        assert_eq!(
            certificate.encode().unwrap(),
            read(version, &format!("{tag}-certificate"))
        );

        let context = if version == 2 {
            trusted.current().context().unwrap()
        } else {
            network.committee(height).unwrap()
        };
        context
            .verify_certificate(certificate, &block.header)
            .unwrap();

        let vote = Vote::decode(&read(version, &format!("{tag}-vote"))).unwrap();
        context.verify_vote(&vote).unwrap();

        DoubleVoteEvidence::decode(&read(version, &format!("{tag}-evidence")))
            .unwrap()
            .verify(&context)
            .unwrap();

        let mut producer = BlockProducer::from_checkpoint(
            ProducerConfig {
                chain_id: genesis.chain_id,
                block_capacity: genesis.capacity,
                ..ProducerConfig::default()
            },
            Some(checkpoint),
            state.clone(),
        )
        .unwrap();
        if version == 2 {
            producer = producer.with_rotation(&trusted).unwrap();
        }

        // Exercise the uncached reference path against literal old bytes.
        let proposal = producer.execute_received_block(block.clone()).unwrap();
        let diffs: Vec<_> = proposal
            .outputs
            .iter()
            .map(|output| output.diff.clone())
            .collect();
        state.commit(state.root(), &diffs).unwrap();
        assert_eq!(state.root(), block.header.state_root);

        verify_proofs(version, height, &tag, &genesis, &keys, &trusted);

        if version == 2 {
            let handoff =
                CommitteeHandoff::from_bytes(&read(version, &format!("{tag}-handoff"))).unwrap();
            assert_eq!(
                trusted.current().to_bytes().unwrap(),
                read(version, &format!("{tag}-committee"))
            );
            assert_eq!(
                handoff.contributions.to_bytes().unwrap(),
                read(version, &format!("{tag}-contributions"))
            );
            trusted.apply(&handoff).unwrap();
        }

        checkpoint = storage::Checkpoint {
            height,
            block: block.header.compute_hash(),
            state_root: state.root(),
        };
    }

    assert_eq!(
        types::AccountState::decode(state.get(&state::account_key(Address([77; 32]))).unwrap())
            .unwrap()
            .balance,
        246
    );
}

fn verify_proofs(
    version: u16,
    height: u64,
    tag: &str,
    genesis: &genesis::Genesis,
    keys: &[[u8; 32]],
    trusted: &HandoffVerifier,
) {
    let tx = Transaction::decode(&read(version, &format!("{tag}-transaction"))).unwrap();
    let id = transaction::compute_tx_id(&tx);

    let receipts =
        CertifiedReceiptProof::from_bytes(&read(version, &format!("{tag}-receipts"))).unwrap();
    assert_eq!(
        receipts.0.effects.to_bytes().unwrap(),
        read(version, &format!("{tag}-effects"))
    );

    let receipt = if version == 2 {
        assert!(receipts.verify(genesis, keys, id, height).is_err());
        receipts.verify_with_handoffs(trusted, id, height).unwrap()
    } else {
        receipts.verify(genesis, keys, id, height).unwrap()
    };
    assert!(receipt.succeeded);

    for (kind, key, present) in [
        ("present", state::account_key(Address([77; 32])), true),
        ("absent", state::account_key(Address([78; 32])), false),
    ] {
        let proof = CertifiedStateProof::from_bytes(&read(version, &format!("{tag}-state-{kind}")))
            .unwrap();

        let value = if version == 2 {
            proof.verify_with_handoffs(trusted, &key, height).unwrap()
        } else {
            proof.verify(genesis, keys, &key, height).unwrap()
        };
        assert_eq!(value.is_some(), present);

        if let Some(value) = value {
            assert_eq!(
                types::AccountState::decode(value).unwrap().balance,
                123 * height
            );
        }
    }
}

#[test]
fn frozen_envelopes_reject_truncation_trailing_bytes_and_cross_network_authority() {
    for version in [1, 2] {
        let genesis = genesis::Genesis::decode(&read(version, "genesis")).unwrap();
        let bytes = read(version, "height-1-network");

        assert!(decode_exchange(Hash256([42; 32]), &bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode_exchange(genesis.commitment().unwrap(), &bytes[..end]).is_err());
        }

        for name in ["height-1-certificate", "height-2-certificate"] {
            exact_only(&read(version, name), |bytes| {
                FinalityCertificate::decode(bytes).is_ok()
            });
        }

        for name in ["height-1-evidence", "height-2-evidence"] {
            exact_only(&read(version, name), |bytes| {
                DoubleVoteEvidence::decode(bytes).is_ok()
            });
        }

        if version == 2 {
            for name in ["height-1-handoff", "height-2-handoff"] {
                exact_only(&read(version, name), |bytes| {
                    CommitteeHandoff::from_bytes(bytes).is_ok()
                });
            }
        }
    }
}

fn exact_only(bytes: &[u8], accepts: impl Fn(&[u8]) -> bool) {
    assert!(accepts(bytes));

    for end in 0..bytes.len() {
        assert!(!accepts(&bytes[..end]), "truncation at {end}");
    }

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(!accepts(&trailing));
}