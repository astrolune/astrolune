// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Full-roster availability, certified trust transfer and sequential recovery.

#[path = "support/rotation.rs"]
mod support;
use consensus::rotation::{
    CommitteeHandoff, CommitteeState, ContributionPool, HandoffVerifier, VrfBatch, VrfContribution,
    committee_state_key,
};
use state::{StateDatabase, StateDiff, StateValueProof};
use support::{batch, fixture, handoff, sign};
use types::StateKey;
#[test]
fn complete_collection_is_order_independent_idempotent_and_fail_closed() {
    let (genesis, keys) = fixture();
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    let contributions = batch(&current);
    let mut pool = ContributionPool::new(current.clone());
    assert_eq!(pool.missing().len(), 4);
    for (index, entry) in contributions.entries().iter().rev().enumerate() {
        assert!(pool.complete().is_err());
        assert!(pool.insert(entry.clone()).unwrap());
        assert!(!pool.insert(entry.clone()).unwrap());
        let mut corrupt = entry.clone();
        corrupt.producer.randomness.0[0] ^= 1;
        assert!(pool.insert(corrupt).is_err());
        assert_eq!(pool.missing().len(), 3 - index);
    }
    assert_eq!(pool.complete().unwrap(), contributions);
    let next = current.transition(&contributions).unwrap();
    assert_eq!(next.committee().members.len(), 3);
    for entry in contributions.entries() {
        assert!(entry.verify(&next).is_err());
    }
    let partial = VrfBatch::new(contributions.entries()[..3].to_vec()).unwrap();
    assert!(current.transition(&partial).is_err());
    let mut altered = contributions.entries().to_vec();
    // Even an unselected producer-role contributor must verify.
    let unselected = altered
        .iter_mut()
        .find(|entry| {
            !next
                .committee()
                .members
                .iter()
                .any(|v| v.id == entry.validator)
        })
        .unwrap();
    unselected.producer.randomness.0[0] ^= 1;
    assert!(
        current
            .transition(&VrfBatch::new(altered).unwrap())
            .is_err()
    );
    let selected = next.committee();
    let following = next.transition(&batch(&next)).unwrap();
    assert_eq!(&following.committee().members[..2], &selected.members[1..]);
    let proposers: std::collections::BTreeSet<_> =
        (0..3).map(|round| next.proposer(round)).collect();
    assert_eq!(proposers.len(), 3);
    assert_eq!(next.proposer(0), next.proposer(3));
}

#[test]
fn handoffs_recover_from_genesis_and_reject_replay_without_changing_trust() {
    let (genesis, keys) = fixture();
    let mut live = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut bytes = Vec::new();
    for _ in 0..8 {
        let proof = handoff(&genesis, &live);
        bytes.push(proof.to_bytes().unwrap());
        live.apply(&proof).unwrap();
        let before = live.clone();
        assert!(live.apply(&proof).is_err());
        assert_eq!(live, before);
    }
    let mut recovered = HandoffVerifier::new(&genesis, &keys).unwrap();
    for encoded in &bytes {
        let proof = CommitteeHandoff::from_bytes(encoded).unwrap();
        assert_eq!(proof.to_bytes().unwrap(), *encoded);
        recovered.apply(&proof).unwrap();
    }
    assert_eq!(recovered, live);
    assert_eq!(live.current().height(), 9);
    let mut fresh = HandoffVerifier::new(&genesis, &keys).unwrap();
    assert!(
        fresh
            .apply(&CommitteeHandoff::from_bytes(&bytes[1]).unwrap())
            .is_err()
    );
    assert_eq!(fresh.current().height(), 1);
}

#[test]
fn every_anchor_is_checked_and_failed_handoffs_preserve_authority() {
    let (genesis, keys) = fixture();
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let good = handoff(&genesis, &trusted);
    for attack in 0..13 {
        let mut bad = good.clone();
        match attack {
            0 => bad.header.parent.0[0] ^= 1,
            1 => bad.header.height += 1,
            2 => bad.header.committee_root.0[0] ^= 1,
            3 => bad.header.capacity.compute += 1,
            4 => {
                bad.certificate.signatures.pop();
            }
            5 => bad.certificate.signatures[0].signature[0] ^= 1,
            6 => bad.certificate.chain_id += 1,
            7 => {
                bad.contributions =
                    VrfBatch::new(good.contributions.entries()[..3].to_vec()).unwrap();
            }
            8 => bad.header.state_root.0[0] ^= 1,
            9 => {
                let StateValueProof::Present(witness) = &mut bad.next_state else {
                    panic!()
                };
                witness.key = StateKey(b"elsewhere".to_vec());
            }
            10 => {
                let StateValueProof::Present(witness) = &mut bad.next_state else {
                    panic!()
                };
                witness.value[44] ^= 1;
            }
            11 => {
                let next = trusted.current().transition(&good.contributions).unwrap();
                bad.certificate = sign(&next, &bad.header);
            }
            _ => {
                let mut entries = bad.contributions.entries().to_vec();
                let entry = &mut entries[0];
                std::mem::swap(&mut entry.committee, &mut entry.producer);
                bad.contributions = VrfBatch::new(entries).unwrap();
            }
        }
        // Give structural header attacks authentic old-quorum signatures: the
        // ancestry, capacity and witness checks must still reject them.
        if matches!(attack, 0..=3 | 8) {
            bad.certificate = sign(trusted.current(), &bad.header);
        }
        let mut verifier = trusted.clone();
        assert!(verifier.apply(&bad).is_err(), "attack {attack}");
        assert_eq!(verifier, trusted);
    }
}

#[test]
fn old_quorum_cannot_substitute_a_different_structurally_valid_next_state() {
    let (genesis, keys) = fixture();
    let mut verifier = HandoffVerifier::new(&genesis, &keys).unwrap();
    let mut proof = handoff(&genesis, &verifier);
    let next = verifier.current().transition(&proof.contributions).unwrap();
    let mut encoded = next.to_bytes().unwrap();
    encoded[52] ^= 1; // A valid but wrong next randomness commitment.
    CommitteeState::from_bytes(&encoded).unwrap();
    let mut db = genesis.materialize().unwrap();
    let mut diff = StateDiff::new();
    diff.put(committee_state_key(), encoded);
    db.commit(db.root(), &[diff]).unwrap();
    proof.header.state_root = db.root();
    proof.certificate = sign(verifier.current(), &proof.header);
    proof.next_state =
        StateValueProof::create(db.snapshot().unwrap().as_ref(), &committee_state_key()).unwrap();
    assert!(verifier.apply(&proof).is_err());
    assert_eq!(verifier.current().height(), 1);
}

#[test]
fn bounded_canonical_decoders_reject_all_truncations_trailing_data_and_bad_counts() {
    let (genesis, keys) = fixture();
    let verifier = HandoffVerifier::new(&genesis, &keys).unwrap();
    let proof = handoff(&genesis, &verifier);
    let state = verifier.current().to_bytes().unwrap();
    let contribution = proof.contributions.entries()[0].to_bytes().unwrap();
    let batch = proof.contributions.to_bytes().unwrap();
    let encoded = proof.to_bytes().unwrap();
    for len in 0..state.len() {
        assert!(CommitteeState::from_bytes(&state[..len]).is_err());
    }
    for len in 0..contribution.len() {
        assert!(VrfContribution::from_bytes(&contribution[..len]).is_err());
    }
    for len in 0..batch.len() {
        assert!(VrfBatch::from_bytes(&batch[..len]).is_err());
    }
    for len in 0..encoded.len() {
        assert!(CommitteeHandoff::from_bytes(&encoded[..len]).is_err());
    }
    assert_eq!(
        CommitteeState::from_bytes(&state).unwrap(),
        *verifier.current()
    );
    assert_eq!(
        VrfContribution::from_bytes(&contribution).unwrap(),
        proof.contributions.entries()[0]
    );
    assert_eq!(VrfBatch::from_bytes(&batch).unwrap(), proof.contributions);
    let mut trailing = encoded;
    trailing.push(0);
    assert!(CommitteeHandoff::from_bytes(&trailing).is_err());
    for offset in [116, 117, 118, 119] {
        let mut invalid = state.clone();
        invalid[offset] = 255;
        assert!(CommitteeState::from_bytes(&invalid).is_err());
    }
    for offset in [120, 152] {
        let mut invalid = state.clone();
        invalid[offset..offset + 32].fill(0);
        assert!(CommitteeState::from_bytes(&invalid).is_err());
    }
    let mut unordered = batch;
    for offset in 0..VrfContribution::BYTES {
        unordered.swap(9 + offset, 9 + VrfContribution::BYTES + offset);
    }
    assert!(VrfBatch::from_bytes(&unordered).is_err());
    assert!(VrfBatch::new(vec![]).is_err());
    assert!(VrfBatch::new(vec![proof.contributions.entries()[0].clone(); 2]).is_err());
}

#[test]
fn bootstrap_requires_exact_strong_registered_keys_and_foreign_genesis_is_rejected() {
    let (genesis, keys) = fixture();
    assert!(HandoffVerifier::new(&genesis, &keys[..3]).is_err());
    let mut invalid = keys.clone();
    invalid[0] = invalid[1];
    assert!(HandoffVerifier::new(&genesis, &invalid).is_err());
    invalid[0] = [0; 32];
    assert!(HandoffVerifier::new(&genesis, &invalid).is_err());
    let trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    let proof = handoff(&genesis, &trusted);
    let mut foreign = genesis;
    foreign.rotation_count = 2;
    let mut verifier = HandoffVerifier::new(&foreign, &keys).unwrap();
    assert!(verifier.apply(&proof).is_err());
}

#[test]
fn rotation_wire_commitments_are_stable() {
    let (genesis, keys) = fixture();
    let verifier = HandoffVerifier::new(&genesis, &keys).unwrap();
    let proof = handoff(&genesis, &verifier);
    let values = [
        verifier.current().to_bytes().unwrap(),
        proof.contributions.entries()[0].to_bytes().unwrap(),
        proof.contributions.to_bytes().unwrap(),
        proof.to_bytes().unwrap(),
    ];
    let expected = [
        (
            472,
            "25386b5b2347219161988d5fe00ac99e5cf248fe4d5ab7866148957fe9110497",
        ),
        (
            280,
            "1df63e1a651265113431f985b8dafe4a46f066b12e7f466a9e6e1fe77d0fea21",
        ),
        (
            1129,
            "2238334e7d0242af9b35b2d1dc5221ad559a8d1412cb8f3e62a35a1b54dcaec9",
        ),
        (
            2343,
            "1f91e03640277c9c104b2421ba2915175ad9276a49215fbe0fad939c13a32b66",
        ),
    ];
    for (bytes, (length, hash)) in values.iter().zip(expected) {
        assert_eq!(bytes.len(), length);
        assert_eq!(crypto::blake2s_hash(bytes).to_string(), hash);
    }
}
