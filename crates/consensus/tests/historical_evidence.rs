// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Historical offences authenticate old seats without accepting peer-selected authority.
#[path = "support/rotation.rs"]
mod support;
use consensus::{
    DoubleVoteEvidence, Vote, VotePhase,
    history::{CommitteeHistory, HistoricalEvidence},
    rotation::HandoffVerifier,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use types::{Hash256, ValidatorId};

fn fixture() -> (CommitteeHistory, HistoricalEvidence) {
    let (genesis, keys) = support::fixture();
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let current = trusted.current();
    let old = current.committee();
    let old_context = current.context().unwrap();
    let mut history =
        CommitteeHistory::new(genesis.chain_id, genesis.commitment().unwrap()).unwrap();
    let mut roots = Vec::new();
    for _ in 0..5 {
        let context = trusted.current().context().unwrap();
        history.append(&context).unwrap();
        roots.push(context.root());
        trusted
            .apply(&support::handoff(&genesis, &trusted))
            .unwrap();
    }
    assert_eq!(trusted.history(), &history);
    let current = trusted.current();
    let voter = (1..=4)
        .find(|seed| {
            let id = ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[*seed; 32])).0);
            current.context().unwrap().voting_power(id).is_none()
        })
        .unwrap();
    let make_vote = |block| {
        let mut vote = Vote {
            chain_id: 7,
            height: 1,
            round: 0,
            phase: VotePhase::Precommit,
            committee_root: old_context.root(),
            block,
            voter: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[voter; 32])).0),
            signature: [0; 64],
        };
        vote.signature = ed25519_sign(&[voter; 32], &vote.signing_hash().0);
        vote
    };
    let evidence = DoubleVoteEvidence::from_votes(
        &old_context,
        make_vote(None),
        make_vote(Some(Hash256([7; 32]))),
    )
    .unwrap();
    assert!(evidence.verify(&current.context().unwrap()).is_err());
    let proof = history
        .prove(1, 5, |h| Ok(roots[usize::try_from(h).unwrap() - 1]))
        .unwrap();
    let bundle =
        HistoricalEvidence::new(&history, &old, &keys, proof.clone(), evidence.clone()).unwrap();
    let mut changed = old.clone();
    changed.members[0].power.0 += 1;
    assert!(
        HistoricalEvidence::new(&history, &changed, &keys, proof.clone(), evidence.clone())
            .is_err()
    );
    changed = old;
    changed.members.swap(0, 1);
    assert!(HistoricalEvidence::new(&history, &changed, &keys, proof, evidence).is_err());
    (history, bundle)
}
#[test]
fn past_offence_is_authenticated_after_the_validator_leaves_the_committee() {
    let (history, bundle) = fixture();
    bundle.verify(&history).unwrap();
    let bytes = bundle.to_bytes().unwrap();
    assert!(bytes.len() <= HistoricalEvidence::MAX_BYTES);
    let decoded = HistoricalEvidence::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.evidence().height(), 1);
    decoded.verify(&history).unwrap();
    let other = CommitteeHistory::new(7, Hash256([7; 32])).unwrap();
    assert!(decoded.verify(&other).is_err());
}
#[test]
fn every_truncation_mutation_and_padding_fails_to_authenticate() {
    let (history, bundle) = fixture();
    let bytes = bundle.to_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(HistoricalEvidence::from_bytes(&bytes[..end]).is_err());
    }
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(decoded) = HistoricalEvidence::from_bytes(&changed) {
            assert_eq!(decoded.to_bytes().unwrap(), changed);
            assert!(decoded.verify(&history).is_err(), "mutation at byte {at}");
        }
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(HistoricalEvidence::from_bytes(&extra).is_err());
    assert!(HistoricalEvidence::from_bytes(&vec![0; HistoricalEvidence::MAX_BYTES + 1]).is_err());
}
