// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State and receipt authentication after independently verified committee handoff.

#[path = "../../consensus/tests/support/rotation.rs"]
mod support;

use consensus::rotation::HandoffVerifier;
use rpc::{CertifiedReceiptProof, CertifiedStateProof};
use state::{StateDatabase, StateDiff, StateValueProof};
use storage::{BlockEffects, StoredReceipts};
use types::{BlockHeader, ExecutionReceipt, Hash256, Resources, StateKey};

#[test]
fn rotated_state_and_receipts_require_exact_independent_handoff_position() {
    let (genesis, keys) = support::fixture();
    let mut trusted = HandoffVerifier::new(&genesis, &keys).unwrap();
    for _ in 0..2 {
        trusted
            .apply(&support::handoff(&genesis, &trusted))
            .unwrap();
    }
    let mut db = genesis.materialize().unwrap();
    let key = StateKey(b"rotated-value".to_vec());
    let mut diff = StateDiff::new();
    diff.put(key.clone(), b"verified".to_vec());
    db.commit(db.root(), &[diff]).unwrap();
    let snapshot = db.snapshot().unwrap();
    let receipt = ExecutionReceipt {
        transaction: Hash256([22; 32]),
        succeeded: true,
        resources: Resources::ZERO,
        output_root: Hash256([23; 32]),
    };
    let header = BlockHeader {
        height: trusted.current().height(),
        parent: trusted.parent(),
        committee_root: trusted.current().context().unwrap().root(),
        capacity: genesis.capacity,
        transactions_root: Hash256([24; 32]),
        state_root: db.root(),
        receipts_root: crypto::compute_receipts_root(&[receipt.commitment()]),
    };
    let certificate = support::sign(trusted.current(), &header).encode().unwrap();
    for query in [&key, &StateKey(b"missing".to_vec())] {
        let proof = CertifiedStateProof::create(
            snapshot.as_ref(),
            query,
            Some((header, certificate.clone())),
        )
        .unwrap();
        assert_eq!(
            proof
                .verify_with_handoffs(&trusted, query, header.height)
                .unwrap(),
            db.get(query)
        );
        assert!(
            proof
                .verify_with_handoffs(&trusted, query, header.height + 1)
                .is_err()
        );
        assert!(proof.verify(&genesis, &keys, query, 0).is_err());
        let fresh = HandoffVerifier::new(&genesis, &keys).unwrap();
        assert!(proof.verify_with_handoffs(&fresh, query, 0).is_err());
        let mut forged = proof;
        forged.certificate[100] ^= 1;
        assert!(forged.verify_with_handoffs(&trusted, query, 0).is_err());
    }
    let proof = CertifiedReceiptProof(StoredReceipts {
        header,
        certificate,
        effects: BlockEffects {
            committee: None,
            potb: None,
            receipts: vec![receipt.clone()],
            genesis: StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap(),
        },
    });
    assert_eq!(
        proof
            .verify_with_handoffs(&trusted, receipt.transaction, header.height)
            .unwrap(),
        &receipt
    );
    assert!(
        proof
            .verify_with_handoffs(&trusted, Hash256::ZERO, 0)
            .is_err()
    );
    assert!(
        proof
            .verify_with_handoffs(&trusted, receipt.transaction, header.height + 1)
            .is_err()
    );
    let mut altered = proof;
    altered.0.effects.receipts[0].succeeded = false;
    assert!(
        altered
            .verify_with_handoffs(&trusted, receipt.transaction, 0)
            .is_err()
    );
}
