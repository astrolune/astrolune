// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Genesis binding, authenticated quorum and hostile state-proof framing.

use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, FinalityCertificate,
    PotbWeight, Vote, VotePhase,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use genesis::{Genesis, GenesisValidator};
use rpc::CertifiedStateProof;
use state::{StateDatabase, StateDiff};
use types::{BlockHeader, Hash256, Resources, StateKey, ValidatorId};

fn fixture() -> (Genesis, Vec<[u8; 32]>) {
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    let mut validators: Vec<_> = keys
        .iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(key).0),
            weight: 1,
        })
        .collect();
    validators.sort_by_key(|validator| validator.id);
    (
        Genesis {
            version: 1,
            chain_id: 7,
            committee_size: 4,
            rotation_count: 1,
            runtime_version: 1,
            capacity: Resources {
                compute: 1_000_000,
                memory: 1_000_000,
                io: 1_000_000,
                bandwidth: 1_000_000,
            },
            validators,
            allocations: vec![],
        },
        keys,
    )
}

fn finalized(genesis: &Genesis, keys: &[[u8; 32]], root: Hash256) -> (BlockHeader, Vec<u8>) {
    finalized_receipts(genesis, keys, root, Hash256([2; 32]))
}

fn finalized_receipts(
    genesis: &Genesis,
    keys: &[[u8; 32]],
    root: Hash256,
    receipts_root: Hash256,
) -> (BlockHeader, Vec<u8>) {
    let committee = Committee {
        height: 9,
        members: genesis
            .validators
            .iter()
            .map(|member| CommitteeMember {
                id: member.id,
                power: PotbWeight(member.weight),
            })
            .collect(),
    };
    let context = AuthenticatedCommittee::new(genesis.chain_id, &committee, keys).unwrap();
    let header = BlockHeader {
        height: 9,
        parent: genesis.commitment().unwrap(),
        transactions_root: Hash256([1; 32]),
        state_root: root,
        receipts_root,
        committee_root: context.root(),
        capacity: genesis.capacity,
    };
    let mut signatures: Vec<_> = (1..=3)
        .map(|seed| {
            let mut vote = Vote {
                chain_id: genesis.chain_id,
                committee_root: context.root(),
                height: header.height,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(header.compute_hash()),
                voter: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0),
                signature: [0; 64],
            };
            vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
            CertificateSignature {
                voter: vote.voter,
                signature: vote.signature,
            }
        })
        .collect();
    signatures.sort_by_key(|signature| signature.voter);
    let certificate = FinalityCertificate {
        chain_id: genesis.chain_id,
        height: header.height,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    };
    (header, certificate.encode().unwrap())
}

#[test]
fn certified_state_authenticates_membership_absence_genesis_and_minimum_height() {
    let (genesis, keys) = fixture();
    let mut db = genesis.materialize().unwrap();
    let key = StateKey(b"hello".to_vec());
    let mut diff = StateDiff::new();
    diff.put(key.clone(), b"world".to_vec());
    db.commit(db.root(), &[diff]).unwrap();
    let snapshot = db.snapshot().unwrap();
    for query in [&key, &StateKey(b"missing".to_vec())] {
        let proof = CertifiedStateProof::create(
            snapshot.as_ref(),
            query,
            Some(finalized(&genesis, &keys, db.root())),
        )
        .unwrap();
        assert_eq!(
            proof.verify(&genesis, &keys, query, 9).unwrap(),
            db.get(query)
        );
        assert!(proof.verify(&genesis, &keys, query, 10).is_err());
        assert!(proof.verify(&genesis, &keys[..2], query, 0).is_err());
        let mut other = genesis.clone();
        other.rotation_count = 2;
        assert!(proof.verify(&other, &keys, query, 0).is_err());
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(CertifiedStateProof::from_bytes(&bytes).unwrap(), proof);
        for len in 0..bytes.len() {
            assert!(CertifiedStateProof::from_bytes(&bytes[..len]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CertifiedStateProof::from_bytes(&trailing).is_err());
        for attack in 0..6 {
            let mut altered = proof.clone();
            match attack {
                0 => altered.root.0[0] ^= 1,
                1 => altered.header.as_mut().unwrap().receipts_root.0[0] ^= 1,
                2 => altered.certificate[100] ^= 1,
                3 => altered.certificate.clear(),
                4 => altered.genesis = altered.value.clone(),
                _ => altered.header = None,
            }
            assert!(altered.verify(&genesis, &keys, query, 0).is_err());
        }
    }
    let proof = CertifiedStateProof::create(
        snapshot.as_ref(),
        &key,
        Some(finalized(&genesis, &keys, db.root())),
    )
    .unwrap();
    assert!(
        proof
            .verify(&genesis, &keys, &StateKey(b"elsewhere".to_vec()), 0)
            .is_err()
    );
    let mut invalid = proof.to_bytes().unwrap();
    invalid[40] = 2;
    assert!(CertifiedStateProof::from_bytes(&invalid).is_err());
    let mut mismatched = finalized(&genesis, &keys, db.root());
    mismatched.0.state_root = Hash256::ZERO;
    assert!(CertifiedStateProof::create(snapshot.as_ref(), &key, Some(mismatched)).is_err());
}

#[test]
fn genesis_proof_requires_exact_trusted_materialized_state() {
    let (genesis, keys) = fixture();
    let db = genesis.materialize().unwrap();
    let snapshot = db.snapshot().unwrap();
    let key = genesis::genesis_key();
    let proof = CertifiedStateProof::create(snapshot.as_ref(), &key, None).unwrap();
    assert_eq!(
        proof.verify(&genesis, &keys, &key, 0).unwrap(),
        Some(genesis.commitment().unwrap().as_bytes().as_slice())
    );
    assert!(proof.verify(&genesis, &keys, &key, 1).is_err());
    let mut extra_certificate = proof;
    extra_certificate.certificate.push(0);
    assert!(extra_certificate.verify(&genesis, &keys, &key, 0).is_err());
}

#[test]
fn certified_receipts_bind_execution_output_order_genesis_and_quorum() {
    let (genesis, keys) = fixture();
    let db = genesis.materialize().unwrap();
    let snapshot = db.snapshot().unwrap();
    let receipts: Vec<_> = (1..=2)
        .map(|id| types::ExecutionReceipt {
            transaction: Hash256([id; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256([id + 1; 32]),
        })
        .collect();
    let root = crypto::compute_receipts_root(
        &receipts
            .iter()
            .map(types::ExecutionReceipt::commitment)
            .collect::<Vec<_>>(),
    );
    let (header, certificate) = finalized_receipts(&genesis, &keys, db.root(), root);
    let proof = rpc::CertifiedReceiptProof(storage::StoredReceipts {
        header,
        certificate,
        effects: storage::BlockEffects {
            committee: None,
            potb: None,
            receipts,
            genesis: state::StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key())
                .unwrap(),
        },
    });
    let id = Hash256([1; 32]);
    assert_eq!(
        proof.verify(&genesis, &keys, id, 9).unwrap(),
        &proof.0.effects.receipts[0]
    );
    assert!(proof.verify(&genesis, &keys, id, 10).is_err());
    assert!(proof.verify(&genesis, &keys, Hash256([99; 32]), 0).is_err());
    let encoded = proof.to_bytes().unwrap();
    assert_eq!(
        rpc::CertifiedReceiptProof::from_bytes(&encoded).unwrap(),
        proof
    );
    for size in 0..encoded.len() {
        assert!(rpc::CertifiedReceiptProof::from_bytes(&encoded[..size]).is_err());
    }
    assert!(rpc::CertifiedReceiptProof::from_bytes(&[encoded.as_slice(), &[0]].concat()).is_err());
    for mutation in 0..5 {
        let mut changed = proof.clone();
        match mutation {
            0 => changed.0.effects.receipts[0].output_root.0[0] ^= 1,
            1 => changed.0.effects.receipts.reverse(),
            2 => changed.0.header.parent = Hash256::ZERO,
            3 => {
                changed.0.effects.receipts.pop();
            }
            _ => {
                let mut certificate = FinalityCertificate::decode(&changed.0.certificate).unwrap();
                certificate.signatures.pop();
                changed.0.certificate = certificate.encode().unwrap();
            }
        }
        assert!(changed.verify(&genesis, &keys, id, 0).is_err());
    }
    let mut foreign = genesis;
    foreign.rotation_count = 2;
    assert!(proof.verify(&foreign, &keys, id, 0).is_err());
}
