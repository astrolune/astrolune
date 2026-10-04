// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic public test keys and complete `PoTB` transitions.

#![allow(dead_code)]

use consensus::{
    CertificateSignature, DoubleVoteEvidence, FinalityCertificate, Vote, VotePhase,
    admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest},
    history::HistoricalEvidence,
    potb::PotbPolicy,
    potb_transition::{
        PotbBatch, PotbConfiguration, PotbHandoff, PotbState, PotbVerifier, potb_state_key,
    },
    rotation::{CommitteeState, VrfBatch, VrfContribution},
};
use crypto::{
    VrfRole,
    blake2s::{ed25519_public_key, ed25519_sign},
};
use genesis::{Genesis, GenesisValidator};
use state::{InMemoryState, StateDatabase, StateDiff, StateValueProof};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

pub fn identity(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0)
}

pub fn governed(profile: PotbConfiguration) -> PotbConfiguration {
    profile
        .with_governance(consensus::governance::GovernancePolicy {
            epoch_blocks: 2,
            minimum_capacity: Resources {
                compute: 500_000,
                memory: 131_072,
                io: 16_384,
                bandwidth: 65_536,
            },
            maximum_capacity: Resources {
                compute: 2_000_000,
                memory: 2_000_000,
                io: 2_000_000,
                bandwidth: 2_000_000,
            },
            maximum_prices: Resources {
                compute: 10,
                memory: 10,
                io: 10,
                bandwidth: 10,
            },
        })
        .unwrap()
}

pub fn parameter_approvals(
    request: &consensus::governance::GovernanceIntent,
    ids: impl Iterator<Item = ValidatorId>,
) -> Vec<consensus::governance::GovernanceApproval> {
    ids.map(|id| {
        let mut bytes = b"ALGVAP01".to_vec();
        bytes.extend_from_slice(&request.id().0);
        bytes.extend_from_slice(&id.0);
        bytes.extend_from_slice(&ed25519_sign(&[seed(id); 32], &request.approval_hash(id).0));
        consensus::governance::GovernanceApproval::from_bytes(&bytes).unwrap()
    })
    .collect()
}

pub fn parameters(
    state: &PotbState,
    parent: Hash256,
) -> consensus::governance::GovernanceCertificate {
    let policy = state.governance().unwrap();
    let parameters = consensus::governance::NetworkParameters {
        capacity: Resources {
            compute: 600_000,
            memory: 200_000,
            io: 20_000,
            bandwidth: 70_000,
        },
        prices: Resources {
            compute: 2,
            memory: 1,
            io: 2,
            bandwidth: 1,
        },
    };
    let current = state.committee();
    let request = policy.request(current, parent, parameters).unwrap();
    let approvals = parameter_approvals(&request, current.context().unwrap().members());
    consensus::governance::GovernanceCertificate::assemble(
        request, approvals, current, parent, policy,
    )
    .unwrap()
}

pub fn seed(id: ValidatorId) -> u8 {
    (1..=99).find(|s| identity(*s) == id).unwrap()
}

pub fn fixture() -> (PotbConfiguration, Vec<[u8; 32]>) {
    let keys: Vec<_> = (1..=4).map(|s| ed25519_public_key(&[s; 32])).collect();
    let mut validators: Vec<_> = keys
        .iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(key).0),
            weight: 10,
        })
        .collect();
    validators.sort_by_key(|v| v.id);
    (
        PotbConfiguration::new(
            Genesis {
                version: 2,
                chain_id: 71,
                committee_size: 3,
                rotation_count: 1,
                runtime_version: 2,
                capacity: Resources {
                    compute: 1_000_000,
                    memory: 1_000_000,
                    io: 1_000_000,
                    bandwidth: 1_000_000,
                },
                validators,
                allocations: vec![],
            },
            PotbPolicy {
                epoch_blocks: 2,
                initial_weight: 10,
                age_increment: 3,
                maximum_weight: 20,
            },
        )
        .unwrap(),
        keys,
    )
}

pub fn contributions(state: &PotbState) -> VrfBatch {
    let current = state.committee();
    VrfBatch::new(
        current
            .roster()
            .iter()
            .map(|v| {
                let id = ValidatorId(crypto::blake2s_hash(&v.public_key).0);
                let seed = [seed(id); 32];
                VrfContribution {
                    validator: id,
                    committee: crypto::prove_vrf(&seed, current.input(VrfRole::Committee).unwrap())
                        .unwrap(),
                    producer: crypto::prove_vrf(&seed, current.input(VrfRole::Producer).unwrap())
                        .unwrap(),
                }
            })
            .collect(),
    )
    .unwrap()
}

pub fn batch(state: &PotbState) -> PotbBatch {
    PotbBatch::new(contributions(state), vec![], vec![]).unwrap()
}

pub fn admission(state: &PotbState, parent: Hash256, candidate: u8) -> AdmissionCertificate {
    let current = state.committee();
    let request = AdmissionRequest::sign(current, parent, &[candidate; 32]).unwrap();
    // Public fixture keys only; production operator approvals use DurableSigner.
    let approvals = current
        .context()
        .unwrap()
        .members()
        .map(|id| {
            let signature = ed25519_sign(
                &[seed(id); 32],
                &request.intent().approval_hash(request.consent(), id).0,
            );
            let mut bytes = b"ALADAP01".to_vec();
            bytes.extend_from_slice(&request.id().0);
            bytes.extend_from_slice(&id.0);
            bytes.extend_from_slice(&signature);
            AdmissionApproval::from_bytes(&bytes).unwrap()
        })
        .collect();
    AdmissionCertificate::assemble(request, approvals, current, parent).unwrap()
}

pub fn certificate(current: &CommitteeState, header: &BlockHeader) -> FinalityCertificate {
    let context = current.context().unwrap();
    let mut signatures: Vec<_> = context
        .members()
        .map(|id| {
            let vote = Vote {
                chain_id: current.chain_id(),
                height: current.height(),
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(header.compute_hash()),
                committee_root: context.root(),
                voter: id,
                signature: [0; 64],
            };
            CertificateSignature {
                voter: id,
                signature: ed25519_sign(&[seed(id); 32], &vote.signing_hash().0),
            }
        })
        .collect();
    signatures.sort_by_key(|s| s.voter);
    FinalityCertificate {
        chain_id: current.chain_id(),
        height: current.height(),
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}

pub fn handoff(trusted: &PotbVerifier, batch: PotbBatch) -> PotbHandoff {
    let next = trusted.current().stage(trusted.parent(), &batch).unwrap();
    handoff_with_state(trusted, batch, &next)
}

pub fn handoff_with_state(
    trusted: &PotbVerifier,
    batch: PotbBatch,
    next: &PotbState,
) -> PotbHandoff {
    let mut database = InMemoryState::default();
    let mut diff = StateDiff::new();
    diff.put(potb_state_key(), next.to_bytes().unwrap());
    database.commit(database.root(), &[diff]).unwrap();
    let current = trusted.current().committee();
    let header = BlockHeader {
        height: current.height(),
        parent: trusted.parent(),
        state_root: database.root(),
        transactions_root: Hash256::ZERO,
        receipts_root: Hash256::ZERO,
        committee_root: current.context().unwrap().root(),
        capacity: current.capacity(),
    };
    PotbHandoff {
        certificate: certificate(current, &header),
        header,
        batch,
        next_state: StateValueProof::create(
            database.snapshot().unwrap().as_ref(),
            &potb_state_key(),
        )
        .unwrap(),
    }
}

pub fn evidence(
    state: &PotbState,
    past: &CommitteeState,
    roots: &[Hash256],
    accused: u8,
) -> HistoricalEvidence {
    let context = past.context().unwrap();
    let vote = |block| {
        let mut vote = Vote {
            chain_id: past.chain_id(),
            committee_root: context.root(),
            height: past.height(),
            round: 1,
            phase: VotePhase::Prevote,
            block,
            voter: identity(accused),
            signature: [0; 64],
        };
        vote.signature = ed25519_sign(&[accused; 32], &vote.signing_hash().0);
        vote
    };
    let evidence =
        DoubleVoteEvidence::from_votes(&context, vote(None), vote(Some(Hash256([99; 32]))))
            .unwrap();
    let proof = state
        .history()
        .prove(past.height(), roots.len() as u64, |height| {
            Ok(roots[usize::try_from(height).unwrap() - 1])
        })
        .unwrap();
    let keys: Vec<_> = context
        .members()
        .map(|id| ed25519_public_key(&[seed(id); 32]))
        .collect();
    HistoricalEvidence::new(state.history(), &past.committee(), &keys, proof, evidence).unwrap()
}
