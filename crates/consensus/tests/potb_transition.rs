// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Executed policy, weighted authority, exact inclusion and atomic authenticated replay.

#![allow(clippy::too_many_lines)]

#[path = "support/potb.rs"]
mod support;
use consensus::{
    potb_transition::{PotbBatch, PotbConfiguration, PotbHandoff, PotbState, PotbVerifier},
    rotation::VrfBatch,
};
use std::collections::BTreeMap;
use support::{batch, contributions, fixture, handoff, identity};
use types::Hash256;

#[test]
fn age_is_membership_not_certificate_presence_and_power_changes_only_after_handoff() {
    let (config, keys) = fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let original = trusted.clone();
    let transition = handoff(&trusted, batch(trusted.current()));
    assert_eq!(trusted, original);
    let mut subset = transition.clone();
    subset.certificate.signatures.pop(); // Three out of four equal weights form a quorum.
    let mut other = trusted.clone();
    trusted.apply(&transition).unwrap();
    other.apply(&subset).unwrap();
    assert_eq!(trusted, other);
    assert!(
        trusted
            .current()
            .records()
            .all(|(_, r)| r.eligible_blocks == 1)
    );
    let mut counts: BTreeMap<_, _> = trusted
        .current()
        .records()
        .map(|(id, r)| (id, r.eligible_blocks))
        .collect();
    for _ in 0..16 {
        for id in trusted.current().committee().context().unwrap().members() {
            *counts.get_mut(&id).unwrap() += 1;
        }
        let previous = trusted.current().clone();
        let transition = handoff(&trusted, batch(trusted.current()));
        trusted.apply(&transition).unwrap();
        assert!(
            trusted
                .current()
                .committee()
                .context()
                .unwrap()
                .verify_certificate(&transition.certificate, &transition.header)
                .is_err()
        );
        previous
            .committee()
            .context()
            .unwrap()
            .verify_certificate(&transition.certificate, &transition.header)
            .unwrap();
        for (id, record) in trusted.current().records() {
            assert_eq!(record.eligible_blocks, counts[&id]);
        }
        for member in trusted.current().committee().committee().members {
            assert_eq!(
                member.power,
                config.policy().score(counts[&member.id], false).unwrap()
            );
        }
    }
    assert!(
        trusted
            .current()
            .committee()
            .roster()
            .iter()
            .all(|v| v.weight.0 == 20)
    );
}

#[test]
fn evidence_admission_and_restart_update_one_committed_authority() {
    let (config, keys) = fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let first = trusted.current().committee().clone();
    let mut roots = vec![first.context().unwrap().root()];
    let initial = handoff(&trusted, batch(trusted.current()));
    trusted.apply(&initial).unwrap();
    let evidence = support::evidence(trusted.current(), &first, &roots, 1);
    let admission = support::admission(trusted.current(), trusted.parent(), 99);
    let included = PotbBatch::new(
        contributions(trusted.current()),
        vec![evidence],
        vec![admission],
    )
    .unwrap();
    let mut encoded = vec![initial.to_bytes().unwrap()];
    for step in 0..10 {
        let input = if step == 0 {
            included.clone()
        } else {
            batch(trusted.current())
        };
        roots.push(trusted.current().committee().context().unwrap().root());
        let transition = handoff(&trusted, input);
        trusted.apply(&transition).unwrap();
        assert_eq!(
            trusted.current().last_batch(),
            transition.batch.commitment().unwrap()
        );
        assert_eq!(
            trusted.current().history().entries() + 1,
            trusted.current().committee().height()
        );
        let records: BTreeMap<_, _> = trusted.current().records().collect();
        assert!(records[&identity(1)].disqualification.is_some());
        assert_eq!(records[&identity(99)].admitted_at, 2);
        assert!(
            !trusted
                .current()
                .committee()
                .roster()
                .iter()
                .any(|v| v.public_key == keys[0])
        );
        if step == 0 {
            assert_eq!(records[&identity(99)].eligible_blocks, 0);
            assert!(
                trusted
                    .current()
                    .committee()
                    .context()
                    .unwrap()
                    .voting_power(identity(99))
                    .is_none()
            );
        }
        encoded.push(transition.to_bytes().unwrap());
        let mut restarted = PotbVerifier::new(&config, &keys).unwrap();
        for bytes in &encoded {
            restarted
                .apply(&PotbHandoff::from_bytes(bytes).unwrap())
                .unwrap();
        }
        assert_eq!(restarted, trusted);
        assert_eq!(
            PotbState::from_bytes(&trusted.current().to_bytes().unwrap()).unwrap(),
            *trusted.current()
        );
    }
    assert!(
        trusted
            .current()
            .records()
            .any(|(id, r)| id == identity(99) && r.eligible_blocks > 0)
    );
    let repeated = support::evidence(trusted.current(), &first, &roots, 1);
    assert!(
        trusted
            .current()
            .stage(
                trusted.parent(),
                &PotbBatch::new(contributions(trusted.current()), vec![repeated], vec![]).unwrap()
            )
            .is_err()
    );
    let reentry = support::admission(trusted.current(), trusted.parent(), 1);
    assert!(
        trusted
            .current()
            .stage(
                trusted.parent(),
                &PotbBatch::new(contributions(trusted.current()), vec![], vec![reentry]).unwrap()
            )
            .is_err()
    );
}

#[test]
fn rejected_quorum_fork_witness_batch_and_replay_preserve_all_state() {
    let (config, keys) = fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let transition = handoff(&trusted, batch(trusted.current()));
    let mut cases = vec![];
    let mut changed = transition.clone();
    changed.certificate.signatures.truncate(2);
    cases.push(changed);
    let mut changed = transition.clone();
    changed.header.parent = Hash256([90; 32]);
    cases.push(changed);
    let mut changed = transition.clone();
    changed.header.height += 1;
    cases.push(changed);
    let mut changed = transition.clone();
    changed.header.capacity.io += 1;
    cases.push(changed);
    let mut changed = transition.clone();
    if let state::StateValueProof::Present(witness) = &mut changed.next_state {
        witness.value[8] ^= 1;
    }
    cases.push(changed);
    let mut changed = transition.clone();
    let mut partial = changed.batch.contributions().entries().to_vec();
    partial.pop();
    changed.batch = PotbBatch::new(VrfBatch::new(partial).unwrap(), vec![], vec![]).unwrap();
    cases.push(changed);
    // Valid current quorum plus an authenticated but wrong value must still fail.
    cases.push(support::handoff_with_state(
        &trusted,
        batch(trusted.current()),
        trusted.current(),
    ));
    // Even a valid incumbent certificate and valid Merkle witness cannot install
    // a forged historical frontier, policy, or exact-batch commitment. These
    // states pass structural decoding and claim the correct next height.
    let next = trusted
        .current()
        .stage(trusted.parent(), &transition.batch)
        .unwrap();
    let encoded = next.to_bytes().unwrap();
    let history_at = encoded
        .windows(8)
        .position(|tag| tag == b"ALCHST01")
        .unwrap();
    for at in [8 + 40, 8 + 56, history_at + 52] {
        let mut forged = encoded.clone();
        forged[at] ^= 1;
        let forged = PotbState::from_bytes(&forged).unwrap();
        cases.push(support::handoff_with_state(
            &trusted,
            transition.batch.clone(),
            &forged,
        ));
    }
    for changed in cases {
        let before = trusted.clone();
        assert!(trusted.apply(&changed).is_err());
        assert_eq!(trusted, before);
    }
    trusted.apply(&transition).unwrap();
    let before = trusted.clone();
    assert!(trusted.apply(&transition).is_err());
    assert_eq!(trusted, before);
    let mut changed_policy = config.policy();
    changed_policy.epoch_blocks += 1;
    let other = PotbConfiguration::new(config.genesis().clone(), changed_policy).unwrap();
    assert_ne!(config.commitment(), other.commitment());
    assert!(
        PotbVerifier::new(&other, &keys)
            .unwrap()
            .apply(&transition)
            .is_err()
    );
}

#[test]
fn canonical_order_duplicates_and_aggregate_admission_capacity_are_checked() {
    let (config, keys) = fixture();
    let trusted = PotbVerifier::new(&config, &keys).unwrap();
    let a = support::admission(trusted.current(), trusted.parent(), 98);
    let b = support::admission(trusted.current(), trusted.parent(), 99);
    let left = PotbBatch::new(
        contributions(trusted.current()),
        vec![],
        vec![a.clone(), b.clone()],
    )
    .unwrap();
    let right =
        PotbBatch::new(contributions(trusted.current()), vec![], vec![b, a.clone()]).unwrap();
    assert_eq!(left, right);
    assert!(PotbBatch::new(contributions(trusted.current()), vec![], vec![a.clone(), a]).is_err());
    let certificates = (5..=33)
        .map(|s| support::admission(trusted.current(), trusted.parent(), s))
        .collect();
    let too_many = PotbBatch::new(contributions(trusted.current()), vec![], certificates).unwrap();
    assert!(
        trusted
            .current()
            .stage(trusted.parent(), &too_many)
            .is_err()
    );
    // An admission changes roster and exact batch commitment but cannot alter VRF entropy.
    let empty = trusted
        .current()
        .stage(trusted.parent(), &batch(trusted.current()))
        .unwrap();
    let admitted = trusted.current().stage(trusted.parent(), &left).unwrap();
    assert_eq!(
        empty.committee().randomness(),
        admitted.committee().randomness()
    );
    assert_eq!(
        empty.committee().committee(),
        admitted.committee().committee()
    );
    assert_ne!(empty.last_batch(), admitted.last_batch());
    assert!(trusted.current().stage(Hash256([9; 32]), &left).is_err());
}

#[test]
fn too_few_surviving_seats_and_missing_banned_contributions_fail_closed() {
    let (config, keys) = fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let past = trusted.current().committee().clone();
    let roots = vec![past.context().unwrap().root()];
    trusted
        .apply(&handoff(&trusted, batch(trusted.current())))
        .unwrap();
    let e1 = support::evidence(trusted.current(), &past, &roots, 1);
    let e2 = support::evidence(trusted.current(), &past, &roots, 2);
    assert!(
        PotbBatch::new(
            contributions(trusted.current()),
            vec![e1.clone(), e1.clone()],
            vec![]
        )
        .is_err()
    );
    let too_few = PotbBatch::new(
        contributions(trusted.current()),
        vec![e1.clone(), e2],
        vec![],
    )
    .unwrap();
    assert!(trusted.current().stage(trusted.parent(), &too_few).is_err());
    let partial = VrfBatch::new(
        contributions(trusted.current())
            .entries()
            .iter()
            .filter(|v| v.validator != identity(1))
            .cloned()
            .collect(),
    )
    .unwrap();
    let missing = PotbBatch::new(partial, vec![e1.clone()], vec![]).unwrap();
    assert!(trusted.current().stage(trusted.parent(), &missing).is_err());
    // Valid evidence cannot be smuggled through a newly bootstrapped empty history.
    let fresh = PotbVerifier::new(&config, &keys).unwrap();
    let future = PotbBatch::new(contributions(fresh.current()), vec![e1], vec![]).unwrap();
    assert!(fresh.current().stage(fresh.parent(), &future).is_err());
}

#[test]
fn new_envelopes_are_exact_bounded_and_legacy_genesis_cannot_activate_them() {
    use codec::CanonicalDecode;
    let (config, keys) = fixture();
    let trusted = PotbVerifier::new(&config, &keys).unwrap();
    let transition = handoff(&trusted, batch(trusted.current()));
    let inputs = [
        config.to_bytes(),
        trusted.current().to_bytes().unwrap(),
        transition.batch.to_bytes().unwrap(),
        transition.to_bytes().unwrap(),
    ];
    for (kind, bytes) in inputs.iter().enumerate() {
        let decode = |bytes: &[u8]| match kind {
            0 => PotbConfiguration::from_bytes(bytes).map(|v| v.to_bytes()),
            1 => PotbState::from_bytes(bytes).and_then(|v| v.to_bytes()),
            2 => PotbBatch::from_bytes(bytes).and_then(|v| v.to_bytes()),
            _ => PotbHandoff::from_bytes(bytes).and_then(|v| v.to_bytes()),
        };
        assert_eq!(decode(bytes).unwrap(), *bytes);
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err(), "kind {kind} cut {end}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        let mut unknown = bytes.clone();
        unknown[7] = b'2';
        assert!(decode(&unknown).is_err());
    }
    assert!(genesis::Genesis::decode(&inputs[0]).is_err());
    assert!(PotbConfiguration::from_bytes(&vec![0; PotbConfiguration::MAX_BYTES + 1]).is_err());
    assert!(PotbState::from_bytes(&vec![0; PotbState::MAX_BYTES + 1]).is_err());
    assert!(PotbBatch::from_bytes(&vec![0; PotbBatch::MAX_BYTES + 1]).is_err());
    assert!(PotbHandoff::from_bytes(&vec![0; PotbHandoff::MAX_BYTES + 1]).is_err());
    let mut policy = config.policy();
    policy.maximum_weight = u128::MAX;
    assert!(PotbConfiguration::new(config.genesis().clone(), policy).is_err());
    let mut legacy = config.genesis().clone();
    legacy.version = 1;
    assert!(PotbConfiguration::new(legacy, config.policy()).is_err());
    let mut unequal = config.genesis().clone();
    unequal.validators[0].weight += 1;
    assert!(PotbConfiguration::new(unequal, config.policy()).is_err());
}
