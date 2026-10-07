// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticated voting, canonical envelopes, and weighted quorum regressions.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, CertificateSignature, Committee, CommitteeMember,
    ConsensusError, FinalityCertificate, FinalityEngine, MAX_COMMITTEE_MEMBERS, PotbWeight, Vote,
    VotePhase,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

fn id(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0)
}

fn committee(weights: &[u128]) -> Committee {
    Committee {
        height: 9,
        members: weights
            .iter()
            .enumerate()
            .map(|(index, weight)| CommitteeMember {
                id: id(u8::try_from(index + 1).unwrap()),
                power: PotbWeight(*weight),
            })
            .collect(),
    }
}

fn context(weights: &[u128]) -> AuthenticatedCommittee {
    let keys: Vec<_> = (1..=weights.len())
        .map(|seed| ed25519_public_key(&[u8::try_from(seed).unwrap(); 32]))
        .collect();
    AuthenticatedCommittee::new(7, &committee(weights), &keys).unwrap()
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

fn certificate(
    context: &AuthenticatedCommittee,
    header: &BlockHeader,
    seeds: &[u8],
) -> FinalityCertificate {
    let mut signatures: Vec<_> = seeds
        .iter()
        .map(|seed| {
            let vote = vote(
                context,
                *seed,
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

#[test]
fn invalid_membership_and_key_bindings_fail_closed() {
    for weights in [&[][..], &[0][..], &[u128::MAX, 1][..]] {
        assert_eq!(
            committee(weights).total_power(),
            Err(ConsensusError::InvalidCommittee)
        );
    }
    let mut duplicate = committee(&[1, 1]);
    duplicate.members[1].id = duplicate.members[0].id;
    assert_eq!(
        duplicate.commitment(7),
        Err(ConsensusError::InvalidCommittee)
    );
    let mut oversized = committee(&[1]);
    oversized.members = vec![oversized.members[0]; MAX_COMMITTEE_MEMBERS + 1];
    assert!(oversized.total_power().is_err());
    let keys = [ed25519_public_key(&[1; 32]), ed25519_public_key(&[2; 32])];
    for invalid in [
        vec![],
        vec![keys[0]],
        vec![keys[0], keys[0]],
        vec![keys[0], ed25519_public_key(&[3; 32])],
        vec![[0; 32], keys[1]],
        vec![keys[0], keys[1], keys[1]],
    ] {
        assert!(AuthenticatedCommittee::new(7, &committee(&[1, 1]), &invalid).is_err());
    }
    assert!(AuthenticatedCommittee::new(7, &committee(&[1, 1]), &[keys[1], keys[0]]).is_ok());
    assert_eq!(
        context(&[u128::MAX]).quorum(),
        consensus::quorum_power(u128::MAX)
    );
}

#[test]
fn committee_commitment_binds_chain_height_seat_order_and_full_weights() {
    let original = committee(&[1, 2]);
    let root = original.commitment(7).unwrap();
    assert_ne!(root, original.commitment(8).unwrap());
    for field in 0..4 {
        let mut altered = original.clone();
        match field {
            0 => altered.height += 1,
            1 => altered.members.swap(0, 1),
            2 => altered.members[0].power.0 += 1 << 100,
            _ => altered.members[0].id = id(3),
        }
        assert_ne!(root, altered.commitment(7).unwrap());
    }
}

#[test]
fn every_signed_vote_field_is_authenticated_without_consuming_the_slot() {
    let mut engine = BftFinalityEngine::new(context(&[1]));
    let original = vote(
        engine.committee(),
        1,
        0,
        VotePhase::Precommit,
        Some(Hash256([9; 32])),
    );
    for field in 0..9 {
        let mut altered = original.clone();
        match field {
            0 => altered.chain_id += 1,
            1 => altered.height += 1,
            2 => altered.round += 1,
            3 => altered.committee_root.0[0] ^= 1,
            4 => altered.voter = id(2),
            5 => altered.phase = VotePhase::Prevote,
            6 => altered.block = None,
            7 => altered.block = Some(Hash256([8; 32])),
            _ => altered.signature[0] ^= 1,
        }
        assert!(engine.receive_vote(altered).is_err());
        assert_eq!(engine.finalized_block(), None);
    }
    engine.receive_vote(original).unwrap();
    assert_eq!(engine.finalized_block(), Some(Hash256([9; 32])));
}

#[test]
fn nil_replays_and_authenticated_conflicts_never_add_power() {
    let mut engine = BftFinalityEngine::new(context(&[1, 1, 1, 1]));
    let nil = vote(engine.committee(), 1, 0, VotePhase::Precommit, None);
    engine.receive_vote(nil.clone()).unwrap();
    for _ in 0..5 {
        assert_eq!(
            engine.receive_vote(nil.clone()),
            Err(ConsensusError::DuplicateVote)
        );
    }
    let conflicting = vote(
        engine.committee(),
        1,
        0,
        VotePhase::Precommit,
        Some(Hash256::ZERO),
    );
    let mut forged = conflicting.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        engine.receive_vote(forged),
        Err(ConsensusError::InvalidProof)
    );
    assert_eq!(
        engine.receive_vote(conflicting),
        Err(ConsensusError::Equivocation)
    );
    for seed in [2, 3] {
        engine
            .receive_vote(vote(
                engine.committee(),
                seed,
                0,
                VotePhase::Precommit,
                Some(Hash256::ZERO),
            ))
            .unwrap();
    }
    assert_eq!(engine.finalized_block(), None);
    engine
        .receive_vote(vote(
            engine.committee(),
            4,
            0,
            VotePhase::Precommit,
            Some(Hash256::ZERO),
        ))
        .unwrap();
    assert_eq!(engine.finalized_block(), Some(Hash256::ZERO));
    assert_eq!(
        engine.advance_round(),
        Err(ConsensusError::InvalidTransition)
    );
}

#[test]
fn rounds_phases_blocks_and_nil_have_separate_power() {
    let mut engine = BftFinalityEngine::new(context(&[1, 1, 1, 1]));
    let block = Hash256([1; 32]);
    for seed in [1, 2] {
        engine
            .receive_vote(vote(
                engine.committee(),
                seed,
                0,
                VotePhase::Precommit,
                Some(block),
            ))
            .unwrap();
    }
    let old = vote(engine.committee(), 3, 0, VotePhase::Precommit, Some(block));
    let future = vote(engine.committee(), 3, 1, VotePhase::Precommit, Some(block));
    assert_eq!(
        engine.receive_vote(future.clone()),
        Err(ConsensusError::InvalidTransition)
    );
    engine.advance_round().unwrap();
    assert_eq!(engine.round(), 1);
    assert_eq!(
        engine.receive_vote(old),
        Err(ConsensusError::InvalidTransition)
    );
    engine.receive_vote(future).unwrap();
    for seed in 1..=4 {
        engine
            .receive_vote(vote(
                engine.committee(),
                seed,
                1,
                VotePhase::Prevote,
                Some(block),
            ))
            .unwrap();
    }
    engine
        .receive_vote(vote(engine.committee(), 1, 1, VotePhase::Precommit, None))
        .unwrap();
    engine
        .receive_vote(vote(
            engine.committee(),
            2,
            1,
            VotePhase::Precommit,
            Some(Hash256([2; 32])),
        ))
        .unwrap();
    engine
        .receive_vote(vote(
            engine.committee(),
            4,
            1,
            VotePhase::Precommit,
            Some(block),
        ))
        .unwrap();
    assert_eq!(engine.finalized_block(), None);
}

#[test]
fn all_weighted_subsets_agree_with_reference_threshold_in_both_orders() {
    for weights in [[1, 1, 1, 1], [1, 2, 3, 4], [1, 1, 1, u128::MAX - 3]] {
        for mask in 0u8..16 {
            for reverse in [false, true] {
                let mut engine = BftFinalityEngine::new(context(&weights));
                let header = header(engine.committee());
                let expected: u128 = (0..4)
                    .filter(|index| mask & (1 << index) != 0)
                    .map(|index| weights[index])
                    .sum();
                let mut seeds: Vec<u8> = (1..=4)
                    .filter(|seed| mask & (1 << (seed - 1)) != 0)
                    .collect();
                if reverse {
                    seeds.reverse();
                }
                for seed in seeds {
                    if engine.finalized_block().is_some() {
                        break;
                    }
                    engine
                        .receive_vote(vote(
                            engine.committee(),
                            seed,
                            0,
                            VotePhase::Precommit,
                            Some(header.compute_hash()),
                        ))
                        .unwrap();
                }
                assert_eq!(
                    engine.finalized_block().is_some(),
                    expected >= engine.committee().quorum()
                );
                if let Some(certificate) = engine.certificate() {
                    engine
                        .committee()
                        .verify_certificate(certificate, &header)
                        .unwrap();
                    assert_eq!(
                        FinalityCertificate::decode(&certificate.encode().unwrap()).unwrap(),
                        *certificate
                    );
                }
            }
        }
    }
}

#[test]
fn certificates_reject_replay_insufficient_power_and_every_invalid_signature() {
    let context = context(&[1, 1, 1, 1]);
    let header = header(&context);
    let original = certificate(&context, &header, &[1, 2, 3, 4]);
    context.verify_certificate(&original, &header).unwrap();
    for field in 0..8 {
        let mut altered = original.clone();
        match field {
            0 => altered.chain_id += 1,
            1 => altered.height += 1,
            2 => altered.round += 1,
            3 => altered.committee_root.0[0] ^= 1,
            4 => altered.block.0[0] ^= 1,
            5 => altered.signatures.truncate(2),
            6 => altered.signatures[0].voter = id(9),
            _ => altered.signatures.clear(),
        }
        assert!(context.verify_certificate(&altered, &header).is_err());
    }
    for index in 0..4 {
        let mut altered = original.clone();
        altered.signatures[index].signature[0] ^= 1;
        assert!(context.verify_certificate(&altered, &header).is_err());
    }
    let mut altered_header = header;
    altered_header.state_root.0[0] ^= 1;
    assert!(
        context
            .verify_certificate(&original, &altered_header)
            .is_err()
    );
    let prevote = vote(
        &context,
        1,
        0,
        VotePhase::Prevote,
        Some(header.compute_hash()),
    );
    let mut altered = original;
    altered
        .signatures
        .iter_mut()
        .find(|entry| entry.voter == id(1))
        .unwrap()
        .signature = prevote.signature;
    assert!(context.verify_certificate(&altered, &header).is_err());
}

#[test]
fn strict_wire_decoders_reject_truncation_tags_order_duplicates_and_trailing_bytes() {
    let context = context(&[1, 1, 1]);
    let header = header(&context);
    let original = certificate(&context, &header, &[1, 2, 3]);
    let bytes = original.encode().unwrap();
    for len in 0..bytes.len() {
        assert!(FinalityCertificate::decode(&bytes[..len]).is_err());
    }
    for offset in [0, 4, 88, 89, 90, 91] {
        let mut altered = bytes.clone();
        altered[offset] ^= 0xff;
        assert!(FinalityCertificate::decode(&altered).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(FinalityCertificate::decode(&trailing).is_err());
    for duplicate in [false, true] {
        let mut altered = original.clone();
        if duplicate {
            altered.signatures[1] = altered.signatures[0].clone();
        } else {
            altered.signatures.swap(0, 1);
        }
        assert!(altered.encode().is_err());
        let mut wire = bytes.clone();
        if duplicate {
            wire[188..284].copy_from_slice(&bytes[92..188]);
        } else {
            wire[188..284].copy_from_slice(&bytes[92..188]);
            wire[92..188].copy_from_slice(&bytes[188..284]);
        }
        assert!(FinalityCertificate::decode(&wire).is_err());
    }
    for block in [None, Some(Hash256::ZERO), Some(Hash256([9; 32]))] {
        let bytes = vote(&context, 1, 0, VotePhase::Precommit, block).encode();
        assert_eq!(Vote::decode(&bytes).unwrap().encode(), bytes);
        for len in 0..bytes.len() {
            assert!(Vote::decode(&bytes[..len]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Vote::decode(&trailing).is_err());
        for tag in 2..=255 {
            let mut altered = bytes;
            altered[24] = tag;
            assert!(Vote::decode(&altered).is_err());
            altered = bytes;
            altered[25] = tag;
            assert!(Vote::decode(&altered).is_err());
        }
    }
    let mut nil = vote(&context, 1, 0, VotePhase::Prevote, None).encode();
    nil[26] = 1;
    assert!(Vote::decode(&nil).is_err());
}

#[test]
fn accepted_mutations_always_reencode_exactly() {
    let context = context(&[1]);
    let vote_bytes = vote(&context, 1, 0, VotePhase::Precommit, Some(Hash256([9; 32]))).encode();
    let cert_bytes = certificate(&context, &header(&context), &[1])
        .encode()
        .unwrap();
    for (bytes, is_vote) in [(vote_bytes.to_vec(), true), (cert_bytes, false)] {
        for offset in 0..bytes.len() {
            for delta in [1, 128, 255] {
                let mut altered = bytes.clone();
                altered[offset] ^= delta;
                if is_vote {
                    if let Ok(value) = Vote::decode(&altered) {
                        assert_eq!(value.encode().as_slice(), altered);
                    }
                } else if let Ok(value) = FinalityCertificate::decode(&altered) {
                    assert_eq!(value.encode().unwrap(), altered);
                }
            }
        }
    }
}

#[test]
fn golden_commitments_match_independent_python_blake2s_vectors() {
    let vote = Vote {
        chain_id: 7,
        height: 9,
        round: 2,
        phase: VotePhase::Precommit,
        block: Some(Hash256([3; 32])),
        committee_root: Hash256([4; 32]),
        voter: ValidatorId([5; 32]),
        signature: [6; 64],
    };
    assert_eq!(
        vote.signing_hash().to_string(),
        "1c4e23c50d88d4b1c3fc57d84e6aa2a9788630a1094771d71deec16b947f7761"
    );
    assert_eq!(
        &vote.encode()[..26],
        &[
            65, 76, 86, 84, 1, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 1
        ]
    );
    let committee = Committee {
        height: 9,
        members: vec![
            CommitteeMember {
                id: ValidatorId([1; 32]),
                power: PotbWeight(10),
            },
            CommitteeMember {
                id: ValidatorId([2; 32]),
                power: PotbWeight(20),
            },
        ],
    };
    assert_eq!(
        committee.commitment(7).unwrap().to_string(),
        "48bece9bfac292ce064eca6a6aa03b55b4a8cfa5989423e19f63842152b94a00"
    );
    let certificate = FinalityCertificate {
        chain_id: 7,
        height: 9,
        round: 2,
        committee_root: vote.committee_root,
        block: vote.block.unwrap(),
        signatures: vec![CertificateSignature {
            voter: vote.voter,
            signature: vote.signature,
        }],
    };
    assert_eq!(
        certificate.commitment().unwrap().to_string(),
        "7e682da8a7c76f77a685054a9bf9c7ab10e56070da8e6e9b6cfedd82895100d4"
    );
}

#[test]
fn nil_quorums_never_finalize_and_first_certificate_is_frozen() {
    let mut engine = BftFinalityEngine::new(context(&[1, 1, 1, 1]));
    for phase in [VotePhase::Prevote, VotePhase::Precommit] {
        for seed in 1..=4 {
            engine
                .receive_vote(vote(engine.committee(), seed, 0, phase, None))
                .unwrap();
        }
    }
    assert_eq!(engine.finalized_block(), None);
    engine.advance_round().unwrap();
    let block = Hash256([9; 32]);
    for seed in 1..=3 {
        engine
            .receive_vote(vote(
                engine.committee(),
                seed,
                1,
                VotePhase::Precommit,
                Some(block),
            ))
            .unwrap();
    }
    let certificate = engine.certificate().unwrap().clone();
    for target in [Some(block), Some(Hash256::ZERO), None] {
        assert_eq!(
            engine.receive_vote(vote(engine.committee(), 4, 1, VotePhase::Precommit, target)),
            Err(ConsensusError::InvalidTransition)
        );
        assert_eq!(engine.certificate(), Some(&certificate));
    }
}

#[test]
fn certificate_size_bound_accepts_exact_limit_and_rejects_excess() {
    let context = context(&[1]);
    let mut certificate = certificate(&context, &header(&context), &[1]);
    certificate.signatures = (0..MAX_COMMITTEE_MEMBERS)
        .map(|index| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&u32::try_from(index).unwrap().to_be_bytes());
            CertificateSignature {
                voter: ValidatorId(id),
                signature: [1; 64],
            }
        })
        .collect();
    let bytes = certificate.encode().unwrap();
    assert_eq!(bytes.len(), 393_308);
    assert_eq!(FinalityCertificate::decode(&bytes).unwrap(), certificate);
    certificate.signatures.push(CertificateSignature {
        voter: ValidatorId([255; 32]),
        signature: [1; 64],
    });
    assert!(certificate.encode().is_err());
    let mut excess = bytes;
    excess.push(0);
    assert!(FinalityCertificate::decode(&excess).is_err());
}
