// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Adversarial authorization, canonical framing and delayed epoch activation.

#[path = "support/potb.rs"]
mod support;

use consensus::{
    governance::{
        GovernanceApproval, GovernanceCertificate, GovernanceIntent, GovernanceState,
        NetworkParameters,
    },
    potb_transition::{PotbBatch, PotbConfiguration, PotbState, PotbVerifier},
};
use types::{Hash256, Resources};
type Decode = fn(&[u8]) -> bool;

#[test]
fn quorum_parent_epoch_and_signature_domains_are_authenticated() {
    let (base, keys) = support::fixture();
    let profile = support::governed(base.clone());
    assert_ne!(base.commitment(), profile.commitment());
    assert_eq!(
        PotbConfiguration::from_bytes(&profile.to_bytes()).unwrap(),
        profile
    );
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let state = trusted.current();
    let current = state.committee();
    let policy = state.governance().unwrap();
    let cert = support::parameters(state, trusted.parent());
    let request = *cert.request();
    assert_eq!(request.activate_at, 3);
    let assemble = |approvals| {
        GovernanceCertificate::assemble(request, approvals, current, trusted.parent(), policy)
    };
    let approvals = support::parameter_approvals(&request, current.context().unwrap().members());
    // Bootstrap includes all four registered members; three signatures reach quorum.
    assert_eq!(approvals.len(), 4);
    assert!(assemble(approvals[..2].to_vec()).is_err());
    assert!(assemble(approvals[..3].to_vec()).is_ok());
    assert!(assemble(vec![approvals[0].clone(); 3]).is_err());
    let mut bad = approvals.clone();
    // A bad fourth signature must not be ignored after the first three reach quorum.
    let mut bytes = bad[3].to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    bad[3] = GovernanceApproval::from_bytes(&bytes).unwrap();
    assert!(assemble(bad).is_err());
    assert!(cert.verify(current, Hash256([9; 32]), policy).is_err());
    let foreign = PotbVerifier::new(&base, &keys).unwrap();
    assert!(
        cert.verify(foreign.current().committee(), trusted.parent(), policy)
            .is_err()
    );
    let value = NetworkParameters {
        capacity: request.capacity,
        prices: Resources {
            compute: 11,
            ..Resources::ZERO
        },
    };
    assert!(policy.request(current, trusted.parent(), value).is_err());
    let mut bytes = cert.to_bytes().unwrap();
    // Change the requested activation height without changing approvals.
    bytes[8 + 116] ^= 1;
    if let Ok(changed) = GovernanceCertificate::from_bytes(&bytes) {
        assert!(changed.verify(current, trusted.parent(), policy).is_err());
    }
    assert!(
        foreign
            .current()
            .stage(
                foreign.parent(),
                &support::batch(foreign.current())
                    .with_governance(cert)
                    .unwrap()
            )
            .is_err()
    );
}

#[test]
fn exactly_two_thirds_of_the_rotated_committee_cannot_change_parameters() {
    let (base, keys) = support::fixture();
    let profile = support::governed(base);
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let first = support::handoff(&trusted, support::batch(trusted.current()));
    trusted.apply(&first).unwrap();
    let state = trusted.current();
    let current = state.committee();
    let cert = support::parameters(state, trusted.parent());
    let request = *cert.request();
    let approvals = support::parameter_approvals(&request, current.context().unwrap().members());
    // The first rotation selects three members, before the first weight update.
    assert_eq!(approvals.len(), 3);
    assert!(
        GovernanceCertificate::assemble(
            request,
            approvals[..2].to_vec(),
            current,
            trusted.parent(),
            state.governance().unwrap(),
        )
        .is_err()
    );
    assert!(
        cert.verify(current, trusted.parent(), state.governance().unwrap())
            .is_ok()
    );
}

#[test]
fn pending_update_activates_once_and_handoffs_replay_exactly() {
    let (base, keys) = support::fixture();
    let profile = support::governed(base);
    let mut trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let original = trusted.current().governance().unwrap().active();
    let certificate = support::parameters(trusted.current(), trusted.parent());
    let expected = NetworkParameters {
        capacity: certificate.request().capacity,
        prices: certificate.request().prices,
    };
    let batch = support::batch(trusted.current())
        .with_governance(certificate)
        .unwrap();
    assert_eq!(
        PotbBatch::from_bytes(&batch.to_bytes().unwrap()).unwrap(),
        batch
    );
    let first = support::handoff(&trusted, batch);
    trusted.apply(&first).unwrap();
    assert_eq!(trusted.current().governance().unwrap().active(), original);
    assert_eq!(
        trusted.current().governance().unwrap().pending(),
        Some((3, expected))
    );
    assert!(
        trusted
            .current()
            .governance()
            .unwrap()
            .request(trusted.current().committee(), trusted.parent(), original)
            .is_err()
    );
    let encoded = trusted.current().to_bytes().unwrap();
    assert_eq!(PotbState::from_bytes(&encoded).unwrap(), *trusted.current());
    let pending = trusted.current().governance().unwrap().to_bytes();
    assert_eq!(
        GovernanceState::from_bytes(&pending).unwrap(),
        *trusted.current().governance().unwrap()
    );
    let second = support::handoff(&trusted, support::batch(trusted.current()));
    trusted.apply(&second).unwrap();
    assert_eq!(trusted.current().governance().unwrap().active(), expected);
    assert_eq!(trusted.current().committee().capacity(), expected.capacity);
    assert!(trusted.current().governance().unwrap().pending().is_none());
    let before = trusted.clone();
    assert!(trusted.apply(&second).is_err());
    assert_eq!(trusted, before);
    let mut replay = PotbVerifier::new(&profile, &keys).unwrap();
    replay.apply(&first).unwrap();
    replay.apply(&second).unwrap();
    assert_eq!(replay, trusted);
}

#[test]
fn all_governance_envelopes_reject_truncation_trailing_bytes_and_unknown_versions() {
    let (base, keys) = support::fixture();
    let profile = support::governed(base);
    let trusted = PotbVerifier::new(&profile, &keys).unwrap();
    let certificate = support::parameters(trusted.current(), trusted.parent());
    let approval = support::parameter_approvals(
        certificate.request(),
        trusted.current().committee().context().unwrap().members(),
    )
    .remove(0);
    let cases: Vec<(Vec<u8>, Decode)> = vec![
        (profile.to_bytes(), |b| {
            PotbConfiguration::from_bytes(b).is_ok()
        }),
        (trusted.current().to_bytes().unwrap(), |b| {
            PotbState::from_bytes(b).is_ok()
        }),
        (trusted.current().governance().unwrap().to_bytes(), |b| {
            GovernanceState::from_bytes(b).is_ok()
        }),
        (certificate.request().to_bytes(), |b| {
            GovernanceIntent::from_bytes(b).is_ok()
        }),
        (approval.to_bytes(), |b| {
            GovernanceApproval::from_bytes(b).is_ok()
        }),
        (certificate.to_bytes().unwrap(), |b| {
            GovernanceCertificate::from_bytes(b).is_ok()
        }),
        (
            support::batch(trusted.current())
                .with_governance(certificate)
                .unwrap()
                .to_bytes()
                .unwrap(),
            |b| PotbBatch::from_bytes(b).is_ok(),
        ),
    ];
    for (bytes, decode) in cases {
        assert!(decode(&bytes));
        for length in 0..bytes.len() {
            assert!(!decode(&bytes[..length]));
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(!decode(&extra));
        let mut unknown = bytes;
        unknown[7] = b'9';
        assert!(!decode(&unknown));
    }
}
