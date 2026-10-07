// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Cryptographic evidence, bounded retention and conservative policy invariants.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, CertificateSignature, Committee, CommitteeMember,
    ConsensusError, DoubleVoteEvidence, FinalityCertificate, FinalityEngine, PotbWeight, Vote,
    VotePhase,
    potb::{PotbPolicy, PotbTracker},
};
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

fn id(seed: u8) -> ValidatorId {
    ValidatorId(blake2s(&ed25519_public_key(&[seed; 32])).0)
}
fn context(height: u64) -> AuthenticatedCommittee {
    let members = (1..=4)
        .map(|seed| CommitteeMember {
            id: id(seed),
            power: PotbWeight(1),
        })
        .collect();
    let keys: Vec<_> = (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect();
    AuthenticatedCommittee::new(42, &Committee { height, members }, &keys).unwrap()
}
fn vote(context: &AuthenticatedCommittee, seed: u8, round: u32, block: Option<Hash256>) -> Vote {
    let mut vote = Vote {
        chain_id: 42,
        committee_root: context.root(),
        height: context.height(),
        round,
        phase: VotePhase::Precommit,
        block,
        voter: id(seed),
        signature: [0; 64],
    };
    vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
    vote
}
fn header(height: u64, parent: Hash256) -> BlockHeader {
    BlockHeader {
        height,
        parent,
        transactions_root: Hash256([1; 32]),
        state_root: Hash256([2; 32]),
        receipts_root: Hash256([3; 32]),
        committee_root: context(height).root(),
        capacity: Resources::ZERO,
    }
}
fn certificate(header: &BlockHeader, seeds: &[u8]) -> FinalityCertificate {
    let context = context(header.height);
    let mut signatures: Vec<_> = seeds
        .iter()
        .map(|seed| {
            let vote = vote(&context, *seed, 0, Some(header.compute_hash()));
            CertificateSignature {
                voter: vote.voter,
                signature: vote.signature,
            }
        })
        .collect();
    signatures.sort_by_key(|entry| entry.voter);
    FinalityCertificate {
        chain_id: 42,
        height: header.height,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}
fn policy() -> PotbPolicy {
    PotbPolicy {
        epoch_blocks: 2,
        initial_weight: 1000,
        age_increment: 100,
        maximum_weight: 1200,
    }
}
fn tracker() -> PotbTracker {
    PotbTracker::new(
        42,
        0,
        Hash256([99; 32]),
        policy(),
        &(1..=4).map(id).collect::<Vec<_>>(),
    )
    .unwrap()
}
fn proof(height: u64, seed: u8) -> DoubleVoteEvidence {
    let context = context(height);
    DoubleVoteEvidence::from_votes(
        &context,
        vote(&context, seed, 0, None),
        vote(&context, seed, 0, Some(Hash256([1; 32]))),
    )
    .unwrap()
}

#[test]
fn evidence_canonicalizes_order_and_deduplicates_the_offence_slot() {
    let context = context(1);
    let a = vote(&context, 1, 0, None);
    let b = vote(&context, 1, 0, Some(Hash256([1; 32])));
    let c = vote(&context, 1, 0, Some(Hash256([2; 32])));
    let ab = DoubleVoteEvidence::from_votes(&context, a.clone(), b.clone()).unwrap();
    let ba = DoubleVoteEvidence::from_votes(&context, b.clone(), a).unwrap();
    let bc = DoubleVoteEvidence::from_votes(&context, b, c).unwrap();
    assert_eq!(ab, ba);
    assert_eq!(ab.id(), ba.id());
    assert_eq!(ab.offence_id(), bc.offence_id());
    assert_ne!(ab.id(), bc.id());
    assert_eq!(DoubleVoteEvidence::decode(&ab.encode()).unwrap(), ab);
    assert!(ab.verify(&self::context(2)).is_err());
}

#[test]
fn duplicates_forged_signatures_and_different_slots_are_not_evidence() {
    let context = context(1);
    let a = vote(&context, 1, 0, None);
    assert!(DoubleVoteEvidence::from_votes(&context, a.clone(), a.clone()).is_err());
    let b = vote(&context, 1, 0, Some(Hash256([1; 32])));
    for field in 0..7 {
        let mut bad = b.clone();
        match field {
            0 => bad.signature[0] ^= 1,
            1 => bad.chain_id += 1,
            2 => bad.height += 1,
            3 => bad.round += 1,
            4 => bad.phase = VotePhase::Prevote,
            5 => bad.voter = id(2),
            _ => bad.committee_root.0[0] ^= 1,
        }
        assert!(DoubleVoteEvidence::from_votes(&context, a.clone(), bad).is_err());
    }
}

#[test]
fn all_truncations_and_single_byte_changes_fail_decode_or_authentication() {
    let original = proof(1, 1).encode();
    let context = context(1);
    for size in 0..original.len() {
        assert!(DoubleVoteEvidence::decode(&original[..size]).is_err());
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert!(DoubleVoteEvidence::decode(&trailing).is_err());
    for index in 0..original.len() {
        let mut bytes = original;
        bytes[index] ^= 1;
        if let Ok(decoded) = DoubleVoteEvidence::decode(&bytes) {
            assert!(decoded.verify(&context).is_err(), "mutation {index}");
        }
    }
    let mut reversed = original;
    reversed[8..194].copy_from_slice(&original[194..]);
    reversed[194..].copy_from_slice(&original[8..194]);
    assert!(DoubleVoteEvidence::decode(&reversed).is_err());
}

#[test]
fn collector_retains_one_proof_per_member_across_rounds_without_counting_conflicts() {
    let context = context(1);
    let mut collector = BftFinalityEngine::new(self::context(1));
    let a = vote(&context, 1, 0, None);
    collector.receive_vote(a.clone()).unwrap();
    let mut forged = vote(&context, 1, 0, Some(Hash256([1; 32])));
    forged.signature[0] ^= 1;
    assert_eq!(
        collector.receive_vote(forged),
        Err(ConsensusError::InvalidProof)
    );
    assert_eq!(collector.evidence().count(), 0);
    for byte in 1..=20 {
        assert_eq!(
            collector.receive_vote(vote(&context, 1, 0, Some(Hash256([byte; 32])))),
            Err(ConsensusError::Equivocation)
        );
    }
    assert_eq!(collector.evidence().count(), 1);
    assert_eq!(collector.finalized_block(), None);
    collector.advance_round().unwrap();
    assert_eq!(collector.evidence().count(), 1);
    collector
        .evidence()
        .next()
        .unwrap()
        .verify(&context)
        .unwrap();
    assert!(collector.receive_vote(a).is_err());
}

#[test]
fn finalized_replay_grows_capped_age_without_treating_certificate_omission_as_downtime() {
    let mut tracker = tracker();
    for height in 1..=10 {
        let header = header(height, tracker.head().1);
        let cert = certificate(&header, &[1, 2, 3]);
        tracker
            .observe_finalized(&context(height), &header, &cert)
            .unwrap();
        let expected = 1000 + u128::from((height / 2).min(2)) * 100;
        for seed in 1..=4 {
            assert_eq!(
                tracker.candidate_weight(id(seed)).unwrap(),
                PotbWeight(expected)
            );
        }
    }
    let records: std::collections::BTreeMap<_, _> = tracker.records().collect();
    assert_eq!(records[&id(4)].certificate_mentions, 0);
    assert_eq!(records[&id(4)].eligible_blocks, 10);
    assert_eq!(records[&id(1)].certificate_mentions, 10);
    let before = tracker.clone();
    let future = proof(11, 1);
    assert!(tracker.observe_evidence(&context(11), &future).is_err());
    assert_eq!(tracker, before);
    assert!(tracker.observe_evidence(&context(2), &proof(2, 1)).unwrap());
    assert_eq!(tracker.candidate_weight(id(1)).unwrap(), PotbWeight(0));
    assert!(!tracker.observe_evidence(&context(2), &proof(2, 1)).unwrap());
    assert_eq!(tracker.candidate_weight(id(4)).unwrap(), PotbWeight(1200));
}

#[test]
fn rejected_histories_never_publish_partial_counters_or_head() {
    let mut tracker = tracker();
    let good = header(1, tracker.head().1);
    let cert = certificate(&good, &[1, 2, 3]);
    let original = tracker.clone();
    let mut forged = cert.clone();
    forged.signatures[1].signature[5] ^= 1;
    assert!(
        tracker
            .observe_finalized(&context(1), &good, &forged)
            .is_err()
    );
    assert_eq!(tracker, original);
    assert!(
        tracker
            .observe_finalized(&context(1), &good, &certificate(&good, &[1, 2]))
            .is_err()
    );
    assert_eq!(tracker, original);
    let gap = header(2, tracker.head().1);
    assert!(
        tracker
            .observe_finalized(&context(2), &gap, &certificate(&gap, &[1, 2, 3]))
            .is_err()
    );
    assert_eq!(tracker, original);
    tracker
        .observe_finalized(&context(1), &good, &cert)
        .unwrap();
    let advanced = tracker.clone();
    assert!(
        tracker
            .observe_finalized(&context(1), &good, &cert)
            .is_err()
    );
    assert_eq!(tracker, advanced);
}

#[test]
fn score_matches_small_reference_and_never_overflows_at_full_width() {
    for base in 1..20_u128 {
        for increment in 0..20 {
            let policy = PotbPolicy {
                epoch_blocks: 3,
                initial_weight: base,
                age_increment: increment,
                maximum_weight: base + 50,
            };
            for blocks in 0..200 {
                assert_eq!(
                    policy.score(blocks, false).unwrap().0,
                    (base + u128::from(blocks / 3) * increment).min(base + 50)
                );
            }
        }
    }
    for initial in [1, u128::MAX / 2, u128::MAX] {
        let policy = PotbPolicy {
            epoch_blocks: 1,
            initial_weight: initial,
            age_increment: u128::MAX,
            maximum_weight: u128::MAX,
        };
        assert_eq!(
            policy.score(u64::MAX, false).unwrap(),
            PotbWeight(u128::MAX)
        );
        assert_eq!(policy.score(u64::MAX, true).unwrap(), PotbWeight(0));
    }
    assert!(
        PotbPolicy {
            epoch_blocks: 0,
            ..policy()
        }
        .validate()
        .is_err()
    );
    assert!(
        PotbPolicy {
            initial_weight: 0,
            ..policy()
        }
        .validate()
        .is_err()
    );
    assert!(
        PotbPolicy {
            maximum_weight: 1,
            ..policy()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn evidence_order_and_duplicates_do_not_stack_penalties() {
    let mut a = tracker();
    for height in 1..=2 {
        let block = header(height, a.head().1);
        a.observe_finalized(&context(height), &block, &certificate(&block, &[1, 2, 3]))
            .unwrap();
    }
    let mut b = a.clone();
    for height in [1, 2, 1, 2] {
        a.observe_evidence(&context(height), &proof(height, 1))
            .unwrap();
    }
    for height in [2, 1, 2, 1] {
        b.observe_evidence(&context(height), &proof(height, 1))
            .unwrap();
    }
    assert_eq!(a, b);
    assert_eq!(a.records().count(), 4);
    assert!(PotbTracker::new(42, 0, Hash256([1; 32]), policy(), &[id(1), id(1)]).is_err());
    assert!(PotbTracker::new(42, 0, Hash256([1; 32]), policy(), &[ValidatorId::ZERO]).is_err());
}
