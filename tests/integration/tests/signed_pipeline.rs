// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signed admission, mempool selection, and execution planning boundaries.

use std::collections::BTreeMap;

use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{ExecutionScheduler, GreedyScheduler};
use mempool::{Mempool, PoolEntry, PoolLimits};
use transaction::{
    AccountState, RegisteredAccount, SignedValidator, TransactionError, TransactionValidator,
    ValidationContext, address_from_public_key, signing_hash,
};
use types::{Resources, StateKey, Transaction};

fn signed_fixture() -> (
    BTreeMap<types::Address, RegisteredAccount>,
    Vec<Transaction>,
) {
    let mut accounts = BTreeMap::new();
    let mut transactions = Vec::new();

    for seed_byte in 1..=2 {
        let seed = [seed_byte; 32];
        let public_key = ed25519_public_key(&seed);
        let sender = address_from_public_key(&public_key);

        accounts.insert(
            sender,
            RegisteredAccount {
                state: AccountState {
                    nonce: 0,
                    balance: 100,
                },
                public_key,
            },
        );

        let mut tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender,
            nonce: 0,
            access_list: vec![StateKey(vec![seed_byte])],
            resource_limit: Resources {
                compute: 1,
                ..Resources::ZERO
            },
            payload: transaction::Payment {
                public_key,
                recipient: types::Address([9; 32]),
                amount: 1,
            }
            .to_bytes(),
            signature: [0; 64],
        };
        tx.signature = ed25519_sign(&seed, signing_hash(&tx).as_bytes());

        transactions.push(Transaction::decode(&tx.to_bytes()).unwrap());
    }

    (accounts, transactions)
}

#[test]
fn signed_wire_transactions_keep_identity_through_selection_and_scheduling() {
    let (accounts, transactions) = signed_fixture();

    let limits = Resources {
        compute: 100,
        ..Resources::ZERO
    };
    let validator = SignedValidator::new(
        accounts,
        limits,
        Resources {
            compute: 1,
            ..Resources::ZERO
        },
    );
    let context = ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };

    let mut mempool = Mempool::new(PoolLimits {
        max_transactions: 2,
        max_bytes: 2048,
    })
    .unwrap();

    for (sequence, tx) in (0u64..).zip(transactions.iter().cloned()) {
        let encoded_len = tx.to_bytes().len();
        let validated = validator.validate(tx, context).unwrap();
        assert_eq!(validated.id, node::hash_transaction(&validated.transaction));

        mempool
            .insert(
                PoolEntry {
                    id: validated.id,
                    transaction: validated.transaction,
                    priority: 0,
                    sequence,
                },
                encoded_len,
            )
            .unwrap();
    }

    let selected: Vec<_> = mempool
        .select(2, limits)
        .iter()
        .map(|entry| entry.transaction.clone())
        .collect();
    assert_eq!(selected, transactions);

    assert_eq!(
        GreedyScheduler.plan(&selected).waves[0].transaction_indexes,
        vec![0, 1]
    );

    assert_eq!(
        node::compute_transactions_root(&selected),
        crypto::compute_transactions_root(
            &selected
                .iter()
                .map(node::hash_transaction)
                .collect::<Vec<_>>()
        )
    );

    let mut tampered = selected[0].clone();
    tampered.payload.push(9);
    assert_eq!(
        validator.validate(tampered, context),
        Err(TransactionError::InvalidSignature)
    );
    assert_eq!(mempool.len(), 2);
}