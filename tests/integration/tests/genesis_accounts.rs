// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Genesis accounts remain authenticated and usable by admission after recovery.

use std::collections::BTreeMap;

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use state::{FileBackedState, StateDatabase, StateDiff, account_key, read_account};
use transaction::{RegisteredAccount, SignedValidator, TransactionValidator, ValidationContext};
use types::{AccountState, Address, Resources, Transaction, ValidatorId};

fn allocated_genesis(address: Address, capacity: Resources) -> Genesis {
    Genesis {
        version: 1,
        chain_id: 7,
        capacity,
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: 1,
        }],
        allocations: vec![Allocation {
            address,
            amount: 1000,
        }],
    }
}

fn signed_payment(seed: &[u8; 32], chain_id: u32, resources: Resources) -> Transaction {
    let public_key = ed25519_public_key(seed);
    let address = transaction::address_from_public_key(&public_key);

    let mut transaction = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            memory: 1,
            io: 1,
            bandwidth: 1,
        },
        chain_id,
        sender: address,
        nonce: 0,
        access_list: Vec::new(),
        resource_limit: resources,
        payload: transaction::Payment {
            public_key,
            recipient: Address([9; 32]),
            amount: 1,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    transaction.signature = ed25519_sign(seed, transaction::signing_hash(&transaction).as_bytes());

    transaction
}

#[test]
fn recovered_genesis_account_authenticates_signed_admission() {
    let seed = [11; 32];
    let public_key = ed25519_public_key(&seed);
    let address = transaction::address_from_public_key(&public_key);
    let resources = Resources {
        compute: 100,
        memory: 100,
        io: 100,
        bandwidth: 100,
    };

    let genesis = allocated_genesis(address, resources);
    let initial = genesis.materialize().unwrap();

    let directory = std::env::temp_dir().join(format!(
        "astrolune-genesis-admission-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("state.bin");
    std::fs::write(&path, initial.export_snapshot()).unwrap();

    {
        let mut recovered = FileBackedState::open(&path).unwrap();
        assert_eq!(recovered.root(), initial.root());

        let snapshot = recovered.snapshot().unwrap();
        let account = read_account(snapshot.as_ref(), address).unwrap().unwrap();
        assert_eq!(
            account,
            AccountState {
                nonce: 0,
                balance: 1000
            }
        );

        let proof = snapshot.prove(&account_key(address)).unwrap().unwrap();
        assert!(proof.verify(initial.root(), &account_key(address), &account.to_bytes()));

        let validator = SignedValidator::new(
            BTreeMap::from([(
                address,
                RegisteredAccount {
                    state: account,
                    public_key,
                },
            )]),
            resources,
            Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
        );

        let mut transaction = signed_payment(&seed, genesis.chain_id, resources);
        let context = ValidationContext {
            chain_id: 7,
            next_height: 0,
            max_transaction_bytes: 1024,
        };
        assert!(validator.validate(transaction.clone(), context).is_ok());

        transaction.nonce = 1;
        assert!(validator.validate(transaction, context).is_err());

        // Subsequent state publication preserves the immutable genesis account view.
        let mut diff = StateDiff::new();
        diff.put(
            account_key(address),
            AccountState {
                nonce: 1,
                balance: 900,
            }
            .to_bytes(),
        );
        recovered.commit(recovered.root(), &[diff]).unwrap();
        assert_eq!(
            read_account(snapshot.as_ref(), address)
                .unwrap()
                .unwrap()
                .nonce,
            0
        );
    }

    {
        let recovered = FileBackedState::open(&path).unwrap();
        assert_eq!(
            read_account(&recovered, address).unwrap(),
            Some(AccountState {
                nonce: 1,
                balance: 900
            })
        );
    }

    // Only the unique directory created by this test is removed.
    std::fs::remove_dir_all(directory).unwrap();
}
