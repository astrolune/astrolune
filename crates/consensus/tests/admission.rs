// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Quorum is incumbent power, with exact fork/height and candidate consent binding.

#![allow(clippy::too_many_lines)]

use consensus::{
    admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest},
    rotation::{CommitteeState, HandoffVerifier},
};
use keystore::{DurableSigner, SigningContext};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use types::{Hash256, ValidatorId};

#[path = "support/rotation.rs"]
mod support;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn signer(&self, state: &CommitteeState, seed: u8) -> DurableSigner {
        DurableSigner::create_protected(
            self.0.join(format!("{seed}.journal")),
            SigningContext {
                chain_id: state.chain_id(),
                genesis: state.genesis(),
            },
            [seed; 32],
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.0.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        fs::remove_dir_all(path).unwrap();
    }
}

fn identity(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&[seed; 32])).0)
}

#[test]
fn weighted_quorum_is_strict_and_request_binds_every_authority_coordinate() {
    let fixture = Fixture::new();
    let (mut genesis, keys) = support::fixture();
    genesis.version = 2;
    // A single high-power member has exactly two thirds. Three low-power
    // members are a headcount majority, but neither group alone is a quorum.
    for member in &mut genesis.validators {
        member.weight = if member.id == identity(1) { 6 } else { 1 };
    }
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    let parent = current.genesis();
    let request = AdmissionRequest::sign(&current, parent, &[99; 32]).unwrap();
    let approvals: Vec<_> = (1..=4)
        .map(|seed| {
            AdmissionApproval::sign(&request, &current, parent, &fixture.signer(&current, seed))
                .unwrap()
        })
        .collect();
    assert!(
        AdmissionCertificate::assemble(
            request.clone(),
            vec![approvals[0].clone()],
            &current,
            parent
        )
        .is_err()
    );
    assert!(
        AdmissionCertificate::assemble(request.clone(), approvals[1..].to_vec(), &current, parent)
            .is_err()
    );
    let certificate =
        AdmissionCertificate::assemble(request.clone(), approvals[..2].to_vec(), &current, parent)
            .unwrap();
    assert!(
        AdmissionCertificate::assemble(
            request.clone(),
            vec![approvals[0].clone(); 2],
            &current,
            parent
        )
        .is_err()
    );
    assert_eq!(
        AdmissionCertificate::assemble(
            request.clone(),
            approvals[..2].iter().rev().cloned().collect(),
            &current,
            parent
        )
        .unwrap(),
        certificate
    );
    let encoded = certificate.to_bytes().unwrap();
    assert_eq!(
        AdmissionCertificate::from_bytes(&encoded).unwrap(),
        certificate
    );
    certificate.verify(&current, parent).unwrap();
    assert!(certificate.verify(&current, Hash256([42; 32])).is_err());
    let mut other = genesis.clone();
    other.chain_id += 1;
    assert!(
        certificate
            .verify(
                &CommitteeState::from_genesis(&other, &keys).unwrap(),
                parent
            )
            .is_err()
    );
    other = genesis.clone();
    other.runtime_version = 2; // Same chain and committee, different genesis.
    let other = CommitteeState::from_genesis(&other, &keys).unwrap();
    assert!(certificate.verify(&other, other.genesis()).is_err());
    let next = current.transition(&support::batch(&current)).unwrap();
    assert!(certificate.verify(&next, parent).is_err());
    assert!(AdmissionRequest::sign(&current, parent, &[1; 32]).is_err());
    let another = AdmissionRequest::sign(&current, parent, &[98; 32]).unwrap();
    assert!(approvals[0].verify(&another, &current, parent).is_err());

    for cut in 0..encoded.len() {
        assert!(AdmissionCertificate::from_bytes(&encoded[..cut]).is_err());
    }
    for bit in 0..encoded.len() * 8 {
        let mut changed = encoded.clone();
        changed[bit / 8] ^= 1 << (bit % 8);
        if let Ok(value) = AdmissionCertificate::from_bytes(&changed) {
            assert!(value.verify(&current, parent).is_err());
        }
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(AdmissionCertificate::from_bytes(&trailing).is_err());
    let mut count = encoded.clone();
    count[8 + AdmissionRequest::BYTES] = 33;
    assert!(AdmissionCertificate::from_bytes(&count).is_err());
    assert!(
        AdmissionCertificate::from_bytes(&vec![0; AdmissionCertificate::MAX_BYTES + 1]).is_err()
    );

    // Every signature must verify, including surplus signatures after quorum.
    let all = AdmissionCertificate::assemble(request.clone(), approvals.clone(), &current, parent)
        .unwrap();
    let mut corrupt = all.to_bytes().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        AdmissionCertificate::from_bytes(&corrupt)
            .unwrap()
            .verify(&current, parent)
            .is_err()
    );
    for bytes in [request.to_bytes().unwrap(), approvals[0].to_bytes()] {
        for cut in 0..bytes.len() {
            assert!(AdmissionRequest::from_bytes(&bytes[..cut]).is_err());
            assert!(AdmissionApproval::from_bytes(&bytes[..cut]).is_err());
        }
    }
}

#[test]
fn standby_is_not_an_approver_and_registered_candidate_cannot_reenter() {
    let fixture = Fixture::new();
    let (genesis, keys) = support::fixture();
    let mut verified = HandoffVerifier::new(&genesis, &keys).unwrap();
    verified
        .apply(&support::handoff(&genesis, &verified))
        .unwrap();
    let current = verified.current();
    let parent = verified.parent();
    let request = AdmissionRequest::sign(current, parent, &[99; 32]).unwrap();
    let context = current.context().unwrap();
    let mut approvals = vec![];
    let mut outsiders = 0;
    for seed in 1..=5 {
        let signer = fixture.signer(current, seed);
        let approval = AdmissionApproval::sign(&request, current, parent, &signer);
        if context.voting_power(identity(seed)).is_some() {
            approvals.push(approval.unwrap());
        } else {
            assert!(approval.is_err());
            outsiders += 1;
        }
        if seed <= 4 {
            assert!(AdmissionRequest::sign(current, parent, &[seed; 32]).is_err());
        }
    }
    assert_eq!(outsiders, 2);
    AdmissionCertificate::assemble(request, approvals, current, parent).unwrap();
}

#[test]
fn no_admission_when_bounded_roster_is_full() {
    let (mut genesis, _) = support::fixture();
    let keys: Vec<_> = (1..=32)
        .map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]))
        .collect();
    genesis.validators = keys
        .iter()
        .map(|key| genesis::GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(key).0),
            weight: 1,
        })
        .collect();
    genesis.validators.sort_by_key(|v| v.id);
    let current = CommitteeState::from_genesis(&genesis, &keys).unwrap();
    assert!(AdmissionRequest::sign(&current, current.genesis(), &[99; 32]).is_err());
}
