// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Full-roster availability, certified trust transfer and sequential recovery.

use consensus::rotation::{
    CommitteeHandoff, CommitteeState, HandoffVerifier, VrfBatch, VrfContribution,
    committee_state_key,
};
use consensus::{CertificateSignature, FinalityCertificate, Vote, VotePhase};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use crypto::{VrfRole, prove_vrf};
use genesis::{Genesis, GenesisValidator};
use state::{StateDatabase, StateDiff, StateValueProof};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

pub fn fixture() -> (Genesis, Vec<[u8; 32]>) {
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    let mut validators: Vec<_> = keys
        .iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(key).0),
            weight: 10,
        })
        .collect();
    validators.sort_by_key(|v| v.id);
    (
        Genesis {
            version: 1,
            chain_id: 7,
            committee_size: 3,
            rotation_count: 1,
            runtime_version: 1,
            capacity: Resources {
                compute: 100_000,
                memory: 100_000,
                io: 100_000,
                bandwidth: 100_000,
            },
            validators,
            allocations: vec![],
        },
        keys,
    )
}

pub fn batch(current: &CommitteeState) -> VrfBatch {
    VrfBatch::new(
        (1..=4)
            .map(|seed| VrfContribution {
                validator: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0),
                committee: prove_vrf(&[seed; 32], current.input(VrfRole::Committee).unwrap())
                    .unwrap(),
                producer: prove_vrf(&[seed; 32], current.input(VrfRole::Producer).unwrap())
                    .unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

pub fn sign(current: &CommitteeState, header: &BlockHeader) -> FinalityCertificate {
    let context = current.context().unwrap();
    let mut signatures: Vec<_> = (1..=4)
        .filter_map(|seed| {
            let id = ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0);
            context.voting_power(id)?;
            let vote = Vote {
                chain_id: current.chain_id(),
                committee_root: context.root(),
                height: current.height(),
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(header.compute_hash()),
                voter: id,
                signature: [0; 64],
            };
            Some(CertificateSignature {
                voter: id,
                signature: ed25519_sign(&[seed; 32], &vote.signing_hash().0),
            })
        })
        .collect();
    signatures.sort_by_key(|v| v.voter);
    if signatures.len() == 4 {
        signatures.pop();
    }
    FinalityCertificate {
        chain_id: current.chain_id(),
        height: current.height(),
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}

pub fn handoff(genesis: &Genesis, verifier: &HandoffVerifier) -> CommitteeHandoff {
    let current = verifier.current();
    let contributions = batch(current);
    let next = current.transition(&contributions).unwrap();
    let mut db = genesis.materialize().unwrap();
    let mut diff = StateDiff::new();
    diff.put(committee_state_key(), next.to_bytes().unwrap());
    db.commit(db.root(), &[diff]).unwrap();
    let header = BlockHeader {
        height: current.height(),
        parent: verifier.parent(),
        transactions_root: Hash256([4; 32]),
        state_root: db.root(),
        receipts_root: Hash256::ZERO,
        committee_root: current.context().unwrap().root(),
        capacity: genesis.capacity,
    };
    CommitteeHandoff {
        certificate: sign(current, &header),
        header,
        contributions,
        next_state: StateValueProof::create(
            db.snapshot().unwrap().as_ref(),
            &committee_state_key(),
        )
        .unwrap(),
    }
}
