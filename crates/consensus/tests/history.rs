// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Streaming history commitments, shortest proofs and full-width boundary checks.

use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, ConsensusError, PotbWeight,
    history::{CommitteeHistory, CommitteeHistoryProof},
};
use types::{Hash256, ValidatorId, hash::domain_hash};

fn context(chain: u32, height: u64, seed: u8) -> AuthenticatedCommittee {
    let key = crypto::blake2s::ed25519_public_key(&[seed; 32]);
    AuthenticatedCommittee::new(
        chain,
        &Committee {
            height,
            members: vec![CommitteeMember {
                id: ValidatorId(crypto::blake2s_hash(&key).0),
                power: PotbWeight(10),
            }],
        },
        &[key],
    )
    .unwrap()
}
fn raw_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = 1usize << (leaves.len() - 1).ilog2();
    domain_hash(
        b"astrolune.committee.history.node.v1",
        &[raw_root(&leaves[..split]).0, raw_root(&leaves[split..]).0].concat(),
    )
}
fn reference_commitment(contexts: &[AuthenticatedCommittee]) -> Hash256 {
    let namespace = [7u32.to_le_bytes().as_slice(), &[9; 32]].concat();
    let leaves: Vec<_> = contexts
        .iter()
        .map(|c| {
            domain_hash(
                b"astrolune.committee.history.leaf.v1",
                &[namespace.as_slice(), &c.height().to_le_bytes(), &c.root().0].concat(),
            )
        })
        .collect();
    domain_hash(
        b"astrolune.committee.history.root.v1",
        &[
            namespace,
            (contexts.len() as u64).to_le_bytes().to_vec(),
            raw_root(&leaves).0.to_vec(),
        ]
        .concat(),
    )
}

#[test]
fn frontiers_and_every_leaf_match_the_reference_across_unbalanced_tree_shapes() {
    let contexts: Vec<_> = (1..=257).map(|h| context(7, h, 1)).collect();
    let mut history = CommitteeHistory::new(7, Hash256([9; 32])).unwrap();
    for (at, context) in contexts.iter().enumerate() {
        history.append(context).unwrap();
        let count = at + 1;
        assert_eq!(
            history.commitment(),
            reference_commitment(&contexts[..count])
        );
        assert_eq!(
            CommitteeHistory::from_bytes(&history.to_bytes()).unwrap(),
            history
        );
        if ![
            1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
            257,
        ]
        .contains(&count)
        {
            continue;
        }
        for height in 1..=count {
            let mut expected = 1;
            let proof = history
                .prove(height as u64, 257, |requested| {
                    assert_eq!(requested, expected);
                    expected += 1;
                    Ok(contexts[usize::try_from(requested).unwrap() - 1].root())
                })
                .unwrap();
            assert_eq!(expected, count as u64 + 1);
            assert_eq!(proof.height(), height as u64);
            proof.verify(&history, &contexts[height - 1]).unwrap();
            let bytes = proof.to_bytes().unwrap();
            assert!(bytes.len() <= CommitteeHistoryProof::MAX_BYTES);
            assert_eq!(CommitteeHistoryProof::from_bytes(&bytes).unwrap(), proof);
        }
    }
}

#[test]
fn failed_updates_and_proof_generation_preserve_history_and_authority() {
    let contexts: Vec<_> = (1..=5).map(|h| context(7, h, 1)).collect();
    let mut history = CommitteeHistory::new(7, Hash256([9; 32])).unwrap();
    assert!(
        history
            .prove(1, 1, |_| panic!("empty history has no lookup"))
            .is_err()
    );
    for context in &contexts {
        history.append(context).unwrap();
    }
    let before = history.clone();
    assert!(history.append(&contexts[4]).is_err());
    assert!(history.append(&context(7, 7, 1)).is_err());
    assert!(history.append(&context(8, 6, 1)).is_err());
    for (height, limit) in [(0, 5), (6, 5), (1, 4)] {
        assert!(
            history
                .prove(height, limit, |_| panic!(
                    "invalid bounds must precede reads"
                ))
                .is_err()
        );
    }
    assert!(
        history
            .prove(3, 5, |_| Err(ConsensusError::InvalidProof))
            .is_err()
    );
    assert!(history.prove(3, 5, |_| Ok(Hash256([3; 32]))).is_err());
    let proof = history
        .prove(3, 5, |h| {
            Ok(contexts[usize::try_from(h).unwrap() - 1].root())
        })
        .unwrap();
    assert!(proof.verify(&history, &context(7, 3, 2)).is_err());
    assert!(proof.verify(&history, &contexts[1]).is_err());
    let mut foreign = CommitteeHistory::new(7, Hash256([10; 32])).unwrap();
    for context in &contexts {
        foreign.append(context).unwrap();
    }
    assert!(proof.verify(&foreign, &contexts[2]).is_err());
    assert_eq!(history, before);
    history.append(&context(7, 6, 1)).unwrap();
    assert!(
        proof.verify(&history, &contexts[2]).is_err(),
        "a proof cannot select a stale history size"
    );
}

#[test]
fn codecs_enforce_minimal_paths_and_mutations_cannot_gain_authority() {
    let contexts: Vec<_> = (1..=5).map(|h| context(7, h, 1)).collect();
    let mut history = CommitteeHistory::new(7, Hash256([9; 32])).unwrap();
    for context in &contexts {
        history.append(context).unwrap();
    }
    let proof = history
        .prove(3, 5, |h| {
            Ok(contexts[usize::try_from(h).unwrap() - 1].root())
        })
        .unwrap();
    let bytes = proof.to_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(CommitteeHistoryProof::from_bytes(&bytes[..end]).is_err());
    }
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(decoded) = CommitteeHistoryProof::from_bytes(&changed) {
            assert_eq!(decoded.to_bytes().unwrap(), changed);
            assert!(decoded.verify(&history, &contexts[2]).is_err());
        }
    }
    let mut padding = bytes;
    padding[56] += 1;
    padding.extend_from_slice(&[0; 32]);
    assert!(CommitteeHistoryProof::from_bytes(&padding).is_err());
    let frontier = history.to_bytes();
    for end in 0..frontier.len() {
        assert!(CommitteeHistory::from_bytes(&frontier[..end]).is_err());
    }
    for at in 0..frontier.len() {
        let mut changed = frontier.clone();
        changed[at] ^= 1;
        if let Ok(decoded) = CommitteeHistory::from_bytes(&changed) {
            assert_eq!(decoded.to_bytes(), changed);
            assert_ne!(decoded.commitment(), history.commitment());
            assert!(proof.verify(&decoded, &contexts[2]).is_err());
        }
    }
    let mut trailing = frontier;
    trailing.push(0);
    assert!(CommitteeHistory::from_bytes(&trailing).is_err());
}

#[test]
fn full_width_counts_have_bounded_paths_and_overflow_is_atomic() {
    let mut bytes = b"ALCHST01".to_vec();
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&[9; 32]);
    bytes.extend_from_slice(&(u64::MAX - 1).to_le_bytes());
    for level in 1..=63 {
        bytes.extend_from_slice(&[level; 32]);
    }
    let mut history = CommitteeHistory::from_bytes(&bytes).unwrap();
    let last = context(7, u64::MAX, 1);
    history.append(&last).unwrap();
    assert_eq!(history.entries(), u64::MAX);
    assert_eq!(history.to_bytes().len(), CommitteeHistory::MAX_BYTES);
    let before = history.clone();
    assert!(history.append(&last).is_err());
    assert_eq!(history, before);
    let mut proof = b"ALCHPF01".to_vec();
    proof.extend_from_slice(&u64::MAX.to_le_bytes());
    proof.extend_from_slice(&u64::MAX.to_le_bytes());
    proof.extend_from_slice(&last.root().0);
    proof.push(63);
    proof.extend_from_slice(&bytes[52..]);
    CommitteeHistoryProof::from_bytes(&proof)
        .unwrap()
        .verify(&history, &last)
        .unwrap();
}
