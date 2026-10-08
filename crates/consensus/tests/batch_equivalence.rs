// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Routing certificate authentication through bounded parallel strict
//! verification changes neither the accept/reject decision nor the exact
//! `ConsensusError` variant. Each case fixes a rejection whose variant depends
//! on which check the serial loop reached first, and asserts that hoisting the
//! cheap checks ahead of one batched signature decision reports the same
//! variant. Signatures beyond the quorum threshold are still authenticated.

#[path = "support/potb.rs"]
mod support;

use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, ConsensusError,
    FinalityCertificate, PotbWeight, PrevoteCertificate, Vote, VotePhase,
    admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest},
    governance::{
        GovernanceApproval, GovernanceCertificate, GovernancePolicy, GovernanceState,
        NetworkParameters,
    },
    rotation::CommitteeState,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use genesis::{Genesis, GenesisValidator};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

/// Enough equally weighted signers that the batch path uses several workers and
/// that three signatures sit beyond the quorum threshold of nine.
const SIGNERS: u8 = 12;

fn id(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0)
}

fn committee() -> Committee {
    Committee {
        height: 9,
        members: (1..=SIGNERS)
            .map(|seed| CommitteeMember {
                id: id(seed),
                power: PotbWeight(1),
            })
            .collect(),
    }
}

fn context() -> AuthenticatedCommittee {
    let keys: Vec<_> = (1..=SIGNERS)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    AuthenticatedCommittee::new(7, &committee(), &keys).unwrap()
}

fn header(context: &AuthenticatedCommittee) -> BlockHeader {
    BlockHeader {
        height: context.height(),
        parent: Hash256([1; 32]),
        transactions_root: Hash256([2; 32]),
        state_root: Hash256([3; 32]),
        receipts_root: Hash256([4; 32]),
        committee_root: context.root(),
        capacity: Resources::ZERO,
    }
}

fn vote(
    context: &AuthenticatedCommittee,
    seed: u8,
    round: u32,
    phase: VotePhase,
    block: Option<Hash256>,
) -> Vote {
    let mut vote = Vote {
        chain_id: context.chain_id(),
        committee_root: context.root(),
        height: context.height(),
        round,
        phase,
        block,
        voter: id(seed),
        signature: [0; 64],
    };
    vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
    vote
}

fn certificate(context: &AuthenticatedCommittee, header: &BlockHeader) -> FinalityCertificate {
    let mut signatures: Vec<_> = (1..=SIGNERS)
        .map(|seed| {
            let vote = vote(
                context,
                seed,
                0,
                VotePhase::Precommit,
                Some(header.compute_hash()),
            );
            CertificateSignature {
                voter: vote.voter,
                signature: vote.signature,
            }
        })
        .collect();
    signatures.sort_by_key(|entry| entry.voter);
    FinalityCertificate {
        chain_id: context.chain_id(),
        height: context.height(),
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}

fn prevotes(context: &AuthenticatedCommittee, block: Hash256) -> Vec<Vote> {
    let mut votes: Vec<_> = (1..=SIGNERS)
        .map(|seed| vote(context, seed, 3, VotePhase::Prevote, Some(block)))
        .collect();
    votes.sort_by_key(|vote| vote.voter);
    votes
}

fn genesis_fixture() -> (Genesis, Vec<[u8; 32]>) {
    let keys: Vec<_> = (1..=SIGNERS)
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
            version: 2,
            chain_id: 7,
            committee_size: usize::from(SIGNERS),
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
        keys,
    )
}

fn admission_approvals(
    request: &AdmissionRequest,
    context: &AuthenticatedCommittee,
) -> Vec<AdmissionApproval> {
    context
        .members()
        .map(|voter| {
            let mut bytes = b"ALADAP01".to_vec();
            bytes.extend_from_slice(&request.id().0);
            bytes.extend_from_slice(&voter.0);
            bytes.extend_from_slice(&ed25519_sign(
                &[support::seed(voter); 32],
                &request.intent().approval_hash(request.consent(), voter).0,
            ));
            AdmissionApproval::from_bytes(&bytes).unwrap()
        })
        .collect()
}

/// Flips one scalar bit, leaving a well-framed approval with an invalid signature.
fn corrupt_admission(approval: &AdmissionApproval) -> AdmissionApproval {
    let mut bytes = approval.to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    AdmissionApproval::from_bytes(&bytes).unwrap()
}

/// Flips one scalar bit, leaving a well-framed approval with an invalid signature.
fn corrupt_governance(approval: &GovernanceApproval) -> GovernanceApproval {
    let mut bytes = approval.to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    GovernanceApproval::from_bytes(&bytes).unwrap()
}

#[test]
fn finality_quorum_rejects_every_corrupted_signature_position_with_invalid_proof() {
    let context = context();
    let header = header(&context);
    let original = certificate(&context, &header);
    assert_eq!(context.quorum(), 9);
    context.verify_certificate(&original, &header).unwrap();
    for position in 0..original.signatures.len() {
        let mut broken = original.clone();
        broken.signatures[position].signature[0] ^= 1;
        assert_eq!(
            context.verify_certificate(&broken, &header),
            Err(ConsensusError::InvalidProof),
            "position {position}"
        );
    }
}

#[test]
fn finality_quorum_reports_the_check_the_serial_order_reached_first() {
    let context = context();
    let header = header(&context);
    let original = certificate(&context, &header);
    // A voter outside the committee below a corrupted signature. The cheap
    // membership check sits at the lower position, so it decides the variant.
    let mut membership_first = original.clone();
    membership_first.signatures[0].voter = ValidatorId::ZERO;
    membership_first.signatures[7].signature[0] ^= 1;
    assert_eq!(
        context.verify_certificate(&membership_first, &header),
        Err(ConsensusError::UnknownVoter)
    );
    // The same two faults with their positions exchanged.
    let mut signature_first = original.clone();
    signature_first.signatures[4].signature[0] ^= 1;
    signature_first.signatures[11].voter = ValidatorId([0xFF; 32]);
    assert_eq!(
        context.verify_certificate(&signature_first, &header),
        Err(ConsensusError::InvalidProof)
    );
    // An unknown voter above every valid signature is still reached.
    let mut membership_last = original;
    membership_last.signatures[11].voter = ValidatorId([0xFF; 32]);
    assert_eq!(
        context.verify_certificate(&membership_last, &header),
        Err(ConsensusError::UnknownVoter)
    );
}

#[test]
fn prevote_quorum_rejects_every_corrupted_signature_position_with_invalid_proof() {
    let context = context();
    let votes = prevotes(&context, Hash256([0xBB; 32]));
    PrevoteCertificate::from_votes(&context, votes.clone()).unwrap();
    for position in 0..votes.len() {
        let mut broken = votes.clone();
        broken[position].signature[0] ^= 1;
        assert_eq!(
            PrevoteCertificate::from_votes(&context, broken),
            Err(ConsensusError::InvalidProof),
            "position {position}"
        );
    }
}

#[test]
fn prevote_quorum_reports_the_hoisted_phase_round_and_block_checks_in_order() {
    let context = context();
    let votes = prevotes(&context, Hash256([0xBB; 32]));
    // A phase mismatch below a corrupted signature keeps its own variant, even
    // though the mismatch also invalidates its own signature.
    let mut phase_first = votes.clone();
    phase_first[2].phase = VotePhase::Precommit;
    phase_first[9].signature[0] ^= 1;
    assert_eq!(
        PrevoteCertificate::from_votes(&context, phase_first),
        Err(ConsensusError::InvalidCertificate)
    );
    // A round mismatch above a corrupted signature does not.
    let mut signature_first = votes.clone();
    signature_first[2].signature[0] ^= 1;
    signature_first[9].round += 1;
    assert_eq!(
        PrevoteCertificate::from_votes(&context, signature_first),
        Err(ConsensusError::InvalidProof)
    );
    // The same for a block mismatch, which is checked against the first vote.
    let mut block_mismatch = votes.clone();
    block_mismatch[9].block = Some(Hash256([0xCC; 32]));
    assert_eq!(
        PrevoteCertificate::from_votes(&context, block_mismatch),
        Err(ConsensusError::InvalidCertificate)
    );
    // An unknown voter above every valid signature is still reached.
    let mut unknown = votes;
    unknown[11].voter = ValidatorId([0xFF; 32]);
    assert_eq!(
        PrevoteCertificate::from_votes(&context, unknown),
        Err(ConsensusError::UnknownVoter)
    );
}

#[test]
fn admission_quorum_authenticates_every_approval_including_those_after_quorum() {
    let (genesis, keys) = genesis_fixture();
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    let parent = current.genesis();
    let context = current.context().unwrap();
    let request = AdmissionRequest::sign(&current, parent, &[99; 32]).unwrap();
    let approvals = admission_approvals(&request, &context);
    assert_eq!(approvals.len(), usize::from(SIGNERS));
    assert_eq!(context.quorum(), 9);
    AdmissionCertificate::assemble(request.clone(), approvals.clone(), &current, parent).unwrap();
    for position in 0..approvals.len() {
        let mut corrupted = approvals.clone();
        corrupted[position] = corrupt_admission(&approvals[position]);
        assert_eq!(
            AdmissionCertificate::assemble(request.clone(), corrupted, &current, parent),
            Err(ConsensusError::InvalidProof),
            "position {position}"
        );
    }
    // The quorum prefix is sufficient and one approval short of it is not.
    AdmissionCertificate::assemble(request.clone(), approvals[..9].to_vec(), &current, parent)
        .unwrap();
    assert_eq!(
        AdmissionCertificate::assemble(request, approvals[..8].to_vec(), &current, parent),
        Err(ConsensusError::InvalidCertificate)
    );
}

#[test]
fn admission_quorum_reports_an_outsider_before_a_higher_invalid_signature() {
    let (genesis, keys) = genesis_fixture();
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    let parent = current.genesis();
    let context = current.context().unwrap();
    let request = AdmissionRequest::sign(&current, parent, &[99; 32]).unwrap();
    let approvals = admission_approvals(&request, &context);
    // The maximum identity is above every derived member identity, so canonical
    // order puts this unregistered approver after all twelve valid signatures.
    let mut bytes = b"ALADAP01".to_vec();
    bytes.extend_from_slice(&request.id().0);
    bytes.extend_from_slice(&[0xFF; 32]);
    bytes.extend_from_slice(&[0x11; 64]);
    let mut mixed = approvals.clone();
    mixed.push(AdmissionApproval::from_bytes(&bytes).unwrap());
    assert_eq!(
        AdmissionCertificate::assemble(request.clone(), mixed.clone(), &current, parent),
        Err(ConsensusError::UnknownVoter)
    );
    // Corrupting a lower signature moves the first rejection below the outsider.
    mixed[3] = corrupt_admission(&approvals[3]);
    assert_eq!(
        AdmissionCertificate::assemble(request, mixed, &current, parent),
        Err(ConsensusError::InvalidProof)
    );
}

#[test]
fn governance_quorum_authenticates_every_approval_including_those_after_quorum() {
    let (genesis, keys) = genesis_fixture();
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    let parent = current.genesis();
    let context = current.context().unwrap();
    let policy = GovernanceState::new(
        GovernancePolicy {
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
        },
        NetworkParameters {
            capacity: genesis.capacity,
            prices: Resources::ZERO,
        },
    )
    .unwrap();
    let value = NetworkParameters {
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
    let request = policy.request(&current, parent, value).unwrap();
    let approvals = support::parameter_approvals(&request, context.members());
    assert_eq!(approvals.len(), usize::from(SIGNERS));
    let assemble =
        |approvals| GovernanceCertificate::assemble(request, approvals, &current, parent, &policy);
    assemble(approvals.clone()).unwrap();
    for position in 0..approvals.len() {
        let mut corrupted = approvals.clone();
        corrupted[position] = corrupt_governance(&approvals[position]);
        assert_eq!(
            assemble(corrupted).unwrap_err(),
            ConsensusError::InvalidProof,
            "position {position}"
        );
    }
    assemble(approvals[..9].to_vec()).unwrap();
    assert_eq!(
        assemble(approvals[..8].to_vec()).unwrap_err(),
        ConsensusError::InvalidCertificate
    );
}
