// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Verified sampling, trusted weights, rotation, and finality interoperability.

use consensus::{
    AuthenticatedCommittee, Candidate, Committee, CommitteeMember, ConsensusError, PotbWeight,
    VerifiedVrfSampler, VrfValidator,
};
use crypto::blake2s::ed25519_public_key;
use crypto::{VrfInput, VrfRole, prove_vrf};
use types::{Hash256, ValidatorId};

fn input(role: VrfRole) -> VrfInput {
    VrfInput {
        chain_id: 7,
        genesis: Hash256([1; 32]),
        epoch: 1,
        height: 8,
        parent_randomness: Hash256([3; 32]),
        round: 0,
        role,
    }
}

fn fixtures(input: VrfInput) -> (Vec<VrfValidator>, Vec<Candidate>) {
    let roster: Vec<_> = (1..=4)
        .map(|seed| VrfValidator {
            public_key: ed25519_public_key(&[seed; 32]),
            weight: PotbWeight(u128::from(seed) * 10),
        })
        .collect();
    let candidates = (1..=4)
        .zip(&roster)
        .map(|(seed, v)| Candidate {
            id: ValidatorId(crypto::blake2s_hash(&v.public_key).0),
            weight: v.weight,
            vrf: prove_vrf(&[seed; 32], input).unwrap(),
        })
        .collect();
    (roster, candidates)
}

#[test]
fn selection_is_order_independent_and_accepted_by_finality_context() {
    let input = input(VrfRole::Committee);
    let (mut roster, mut candidates) = fixtures(input);
    let sampler = VerifiedVrfSampler::new(input, &roster, &candidates).unwrap();
    let committee = sampler.select(3).unwrap();
    assert_eq!(committee.height, input.height);
    assert_eq!(committee.members.len(), 3);
    let keys: Vec<_> = roster
        .iter()
        .filter(|v| {
            committee
                .members
                .iter()
                .any(|m| m.id.0 == crypto::blake2s_hash(&v.public_key).0)
        })
        .map(|v| v.public_key)
        .collect();
    let context = AuthenticatedCommittee::new(input.chain_id, &committee, &keys).unwrap();
    assert_eq!(
        context.root(),
        committee.commitment(input.chain_id).unwrap()
    );
    let transcript = sampler.randomness();
    for _ in 0..4 {
        candidates.rotate_left(1);
        roster.reverse();
        let sampler = VerifiedVrfSampler::new(input, &roster, &candidates).unwrap();
        assert_eq!(sampler.randomness(), transcript);
        assert_eq!(sampler.select(3).unwrap(), committee);
    }
    assert!(sampler.select(0).is_err());
    assert!(sampler.select(5).is_err());
}

#[test]
fn every_proof_and_trusted_weight_is_required() {
    let input = input(VrfRole::Committee);
    let (roster, candidates) = fixtures(input);
    assert!(VerifiedVrfSampler::new(input, &roster, &candidates[..3]).is_err());
    assert!(VerifiedVrfSampler::new(input, &[], &[]).is_err());
    for index in 0..4 {
        let mut altered = candidates.clone();
        altered[index].vrf.proof[0] ^= 1;
        assert!(matches!(
            VerifiedVrfSampler::new(input, &roster, &altered),
            Err(ConsensusError::InvalidProof)
        ));
        let mut altered = candidates.clone();
        altered[index].weight.0 += 1;
        assert!(VerifiedVrfSampler::new(input, &roster, &altered).is_err());
    }
    let mut duplicate = candidates.clone();
    duplicate[0] = duplicate[1].clone();
    assert!(VerifiedVrfSampler::new(input, &roster, &duplicate).is_err());
    let mut invalid = roster.clone();
    invalid[0].weight = PotbWeight(0);
    assert!(VerifiedVrfSampler::new(input, &invalid, &candidates).is_err());
    invalid[0].weight = PotbWeight(u128::MAX);
    assert!(VerifiedVrfSampler::new(input, &invalid, &candidates).is_err());
    invalid = roster.clone();
    invalid[0] = invalid[1];
    assert!(VerifiedVrfSampler::new(input, &invalid, &candidates).is_err());
    let mut unknown = candidates.clone();
    unknown[0].id = ValidatorId::ZERO;
    assert!(VerifiedVrfSampler::new(input, &roster, &unknown).is_err());
    assert!(
        VerifiedVrfSampler::new(VrfInput { height: 9, ..input }, &roster, &candidates).is_err()
    );
}

#[test]
fn rotation_replaces_requested_seats_updates_retained_weights_and_checks_height() {
    let input = input(VrfRole::Committee);
    let (roster, candidates) = fixtures(input);
    let sampler = VerifiedVrfSampler::new(input, &roster, &candidates).unwrap();
    let current = Committee {
        height: 7,
        members: candidates[..3]
            .iter()
            .map(|c| CommitteeMember {
                id: c.id,
                power: PotbWeight(1),
            })
            .collect(),
    };
    let next = sampler.rotate(&current, 1).unwrap();
    assert_eq!(next.members.len(), 3);
    assert_eq!(next.members[0].id, candidates[1].id);
    assert_eq!(next.members[0].power, candidates[1].weight);
    assert_eq!(next.members[1].id, candidates[2].id);
    next.total_power().unwrap();
    let unchanged = sampler.rotate(&current, 0).unwrap();
    assert_eq!(
        unchanged.members.iter().map(|m| m.id).collect::<Vec<_>>(),
        current.members.iter().map(|m| m.id).collect::<Vec<_>>()
    );
    assert!(sampler.rotate(&current, 4).is_err());
    let mut invalid = current.clone();
    invalid.height = u64::MAX;
    assert!(sampler.rotate(&invalid, 1).is_err());
    invalid = current.clone();
    invalid.members[2].id = ValidatorId::ZERO;
    assert!(sampler.rotate(&invalid, 1).is_err());
    invalid = current;
    invalid.members[1] = invalid.members[0];
    assert!(sampler.rotate(&invalid, 1).is_err());
}

#[test]
fn producer_requires_exact_committee_role_height_and_weights() {
    let input = input(VrfRole::Producer);
    let (roster, candidates) = fixtures(input);
    let sampler = VerifiedVrfSampler::new(input, &roster, &candidates).unwrap();
    let mut committee = Committee {
        height: 8,
        members: candidates
            .iter()
            .map(|c| CommitteeMember {
                id: c.id,
                power: c.weight,
            })
            .collect(),
    };
    let producer = sampler.producer(&committee).unwrap();
    assert!(committee.members.iter().any(|m| m.id == producer));
    committee.members.reverse();
    assert_eq!(sampler.producer(&committee).unwrap(), producer);
    assert!(sampler.select(2).is_err());
    committee.members[0].power.0 += 1;
    assert!(sampler.producer(&committee).is_err());
    committee.members[0].power.0 -= 1;
    committee.height += 1;
    assert!(sampler.producer(&committee).is_err());
}
