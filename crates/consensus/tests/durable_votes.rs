// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed vote signing, durable phase mapping, and authenticated quorum integration.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, Committee, CommitteeMember, FinalityEngine,
    PotbWeight, Vote, VotePhase,
};
use keystore::{DurableSigner, KeystoreError, Signer, SigningContext, SigningPosition};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use types::{BlockHeader, Hash256, Resources};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-durable-votes-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, id: u8) -> PathBuf {
        self.0.join(format!("validator-{id}.bin"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context() -> SigningContext {
    SigningContext {
        chain_id: 7,
        genesis: Hash256([8; 32]),
    }
}
fn vote(signer: &DurableSigner, phase: VotePhase) -> Vote {
    Vote {
        chain_id: 7,
        height: 42,
        round: 5,
        phase,
        block: Some(Hash256([6; 32])),
        committee_root: Hash256([9; 32]),
        voter: signer.validator_id(&signer.key_handle()).unwrap(),
        signature: [0; 64],
    }
}

#[test]
fn typed_signing_binds_context_and_cannot_relabel_a_vote_phase() {
    let fixture = Fixture::new();
    let mut signer = DurableSigner::create(fixture.path(1), context(), [1; 32]).unwrap();
    let handle = signer.key_handle();
    let original = vote(&signer, VotePhase::Prevote);
    for field in 0..2 {
        let mut invalid = original.clone();
        if field == 0 {
            invalid.chain_id += 1;
        } else {
            invalid.voter.0[0] ^= 1;
        }
        assert_eq!(
            invalid.sign_with(&mut signer, &handle),
            Err(KeystoreError::ContextMismatch)
        );
        assert_eq!(invalid.signature, [0; 64]);
        assert_eq!(signer.last_position(), None);
    }
    let mut prevote = original;
    prevote.sign_with(&mut signer, &handle).unwrap();
    assert_eq!(
        signer.last_position().unwrap().phase,
        keystore::PREVOTE_PHASE
    );
    assert!(crypto::blake2s::ed25519_verify(
        &signer.public_key(),
        &prevote.signing_hash().0,
        &prevote.signature
    ));
    drop(signer);
    let mut signer = DurableSigner::open(fixture.path(1), context(), [1; 32]).unwrap();
    let mut replay = prevote.clone();
    replay.sign_with(&mut signer, &handle).unwrap();
    assert_eq!(replay, prevote);
    for field in 0..2 {
        let mut invalid = prevote.clone();
        if field == 0 {
            invalid.block = None;
        } else {
            invalid.committee_root.0[0] ^= 1;
        }
        assert_eq!(
            invalid.sign_with(&mut signer, &handle),
            Err(KeystoreError::ConflictingSign)
        );
        assert_eq!(invalid.signature, prevote.signature);
    }
    let mut precommit = prevote.clone();
    precommit.phase = VotePhase::Precommit;
    precommit.sign_with(&mut signer, &handle).unwrap();
    assert_eq!(
        signer.last_position().unwrap().phase,
        keystore::PRECOMMIT_PHASE
    );
    assert_ne!(prevote.signature, precommit.signature);
    assert_eq!(
        prevote.sign_with(&mut signer, &handle),
        Err(KeystoreError::StalePosition)
    );
}

#[test]
fn restarted_signers_produce_an_independently_verified_precommit_certificate() {
    let fixture = Fixture::new();
    let mut members = Vec::new();
    let mut keys = Vec::new();
    for seed in 1..=4 {
        let signer = DurableSigner::create(fixture.path(seed), context(), [seed; 32]).unwrap();
        members.push(CommitteeMember {
            id: signer.validator_id(&signer.key_handle()).unwrap(),
            power: PotbWeight(1),
        });
        keys.push(signer.public_key());
    }
    let committee = Committee {
        height: 42,
        members,
    };
    let authenticated = AuthenticatedCommittee::new(7, &committee, &keys).unwrap();
    let header = BlockHeader {
        height: 42,
        parent: Hash256([1; 32]),
        transactions_root: Hash256([2; 32]),
        state_root: Hash256([3; 32]),
        receipts_root: Hash256([4; 32]),
        committee_root: authenticated.root(),
        capacity: Resources::ZERO,
    };
    let mut engine = BftFinalityEngine::new(authenticated);
    for phase in [VotePhase::Prevote, VotePhase::Precommit] {
        for seed in 1..=3 {
            let mut signer =
                DurableSigner::open(fixture.path(seed), context(), [seed; 32]).unwrap();
            let mut vote = vote(&signer, phase);
            vote.round = 0;
            vote.block = Some(header.compute_hash());
            vote.committee_root = header.committee_root;
            let handle = signer.key_handle();
            vote.sign_with(&mut signer, &handle).unwrap();
            engine.receive_vote(vote).unwrap();
        }
        assert_eq!(
            engine.finalized_block().is_some(),
            phase == VotePhase::Precommit
        );
    }
    let certificate = engine.certificate().unwrap();
    let independent = AuthenticatedCommittee::new(7, &committee, &keys).unwrap();
    independent
        .verify_certificate(certificate, &header)
        .unwrap();
    for seed in 1..=3 {
        let signer = DurableSigner::open(fixture.path(seed), context(), [seed; 32]).unwrap();
        assert_eq!(
            signer.last_position(),
            Some(SigningPosition {
                height: 42,
                round: 0,
                phase: keystore::PRECOMMIT_PHASE
            })
        );
    }
}
