// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signed deploy/call, mixed-lane equivalence, namespace isolation and rollback.

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{SignedSession, execute_signed, execute_signed_parallel, payment_resources};
use state::{InMemoryState, StateDatabase, StateDiff, account_key, read_account};
use transaction::{
    ContractAction, ContractPayload, Payment, ValidationContext, address_from_public_key,
    contract_address, contract_code_key, contract_state_key, signing_hash,
};
use types::{AccountState, Address, Resources, Transaction, TransactionLane};

fn context() -> ValidationContext {
    ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1_048_576,
    }
}
fn capacity() -> Resources {
    Resources {
        compute: 1_000_000,
        memory: 1_000_000,
        io: 4_000_000,
        bandwidth: 1_000_000,
    }
}
fn address(seed: u8) -> Address {
    address_from_public_key(&ed25519_public_key(&[seed; 32]))
}
fn code() -> Vec<u8> {
    wat::parse_str(
        r#"(module
        (import "astrolune_v2" "input_copy" (func $input (param i32 i32 i32) (result i32)))
        (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
        (import "astrolune_v2" "output" (func $output (param i32 i32) (result i32)))
        (memory (export "memory") 1 1) (data (i32.const 0) "k")
        (func (export "call") (result i32)
          (drop (call $input (i32.const 0) (i32.const 16) (i32.const 1)))
          (drop (call $put (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 1)))
          (if (i32.eq (i32.load8_u (i32.const 16)) (i32.const 255)) (then unreachable))
          (drop (call $output (i32.const 16) (i32.const 1))) (i32.const 0)))"#,
    )
    .unwrap()
}
fn sign(mut tx: Transaction, seed: u8) -> Transaction {
    tx.signature = ed25519_sign(&[seed; 32], signing_hash(&tx).as_bytes());
    tx
}
fn contract(seed: u8, nonce: u64, action: ContractAction) -> Transaction {
    let mut keys = vec![account_key(address(seed))];
    match &action {
        ContractAction::Deploy(_) => {
            keys.push(contract_code_key(contract_address(7, address(seed), nonce)));
        }
        ContractAction::Call {
            address,
            keys: local,
            ..
        } => {
            keys.push(contract_code_key(*address));
            keys.extend(local.iter().map(|key| contract_state_key(*address, key)));
        }
    }
    keys.sort();
    keys.dedup();
    sign(
        Transaction {
            version: 1,
            expires_at: 10,
            lane: TransactionLane::Contracts,
            resource_prices: execution::PAYMENT_PRICES,
            chain_id: 7,
            sender: address(seed),
            nonce,
            access_list: keys,
            resource_limit: Resources {
                compute: 10_000,
                memory: 65_568,
                io: 1_048_576,
                bandwidth: 4096,
            },
            payload: ContractPayload {
                public_key: ed25519_public_key(&[seed; 32]),
                action,
            }
            .to_bytes(),
            signature: [0; 64],
        },
        seed,
    )
}
fn call(seed: u8, nonce: u64, target: Address, value: u8) -> Transaction {
    contract(
        seed,
        nonce,
        ContractAction::Call {
            address: target,
            input: vec![value],
            keys: vec![b"k".to_vec()],
        },
    )
}
fn payment(seed: u8, nonce: u64) -> Transaction {
    let mut tx = contract(seed, nonce, ContractAction::Deploy(code()));
    tx.lane = TransactionLane::Payments;
    tx.payload = Payment {
        public_key: ed25519_public_key(&[seed; 32]),
        recipient: address(seed),
        amount: 1,
    }
    .to_bytes();
    tx.access_list = vec![account_key(tx.sender)];
    tx.resource_limit = payment_resources(&tx).unwrap();
    sign(tx, seed)
}
fn funded() -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for seed in [1, 2, 3] {
        diff.put(
            account_key(address(seed)),
            AccountState {
                nonce: 0,
                balance: 1_000_000,
            }
            .to_bytes(),
        );
    }
    state.commit(state.root(), &[diff]).unwrap();
    state
}
fn batch() -> Vec<Transaction> {
    let a = contract_address(7, address(1), 0);
    let b = contract_address(7, address(2), 0);
    vec![
        contract(1, 0, ContractAction::Deploy(code())),
        contract(2, 0, ContractAction::Deploy(code())),
        call(1, 1, a, 42),
        call(2, 1, b, 43),
        payment(3, 0),
        call(3, 1, a, 44),
    ]
}

#[test]
fn governed_mixed_lane_prices_preserve_parallel_results_fees_and_first_error() {
    let initial = funded();
    let prices = Resources {
        compute: 3,
        memory: 1,
        io: 0,
        bandwidth: 2,
    };
    let txs: Vec<_> = batch()
        .into_iter()
        .map(|mut tx| {
            let seed = (1..=3).find(|seed| address(*seed) == tx.sender).unwrap();
            tx.resource_prices = prices;
            sign(tx, seed)
        })
        .collect();
    let policy = execution::ExecutionPolicy {
        capacity: capacity(),
        prices,
        contracts: true,
    };
    let mut serial = initial.clone();
    let expected =
        execution::execute_parallel(&mut serial, &txs, initial.root(), context(), policy, 1)
            .unwrap();
    for workers in [2, 3, 8, 32] {
        let mut parallel = initial.clone();
        assert_eq!(
            execution::execute_parallel(
                &mut parallel,
                &txs,
                initial.root(),
                context(),
                policy,
                workers
            )
            .unwrap(),
            expected
        );
    }
    for seed in 1..=3 {
        let total: u64 = txs
            .iter()
            .zip(&expected.0)
            .filter(|(tx, _)| tx.sender == address(seed))
            .map(|(_, output)| output.receipt.resources.checked_cost(prices).unwrap())
            .sum();
        assert_eq!(
            read_account(serial.snapshot().unwrap().as_ref(), address(seed))
                .unwrap()
                .unwrap()
                .balance,
            1_000_000 - total
        );
    }
    let mut bad = txs;
    bad[2].resource_prices = execution::PAYMENT_PRICES;
    bad[2] = sign(bad[2].clone(), 1);
    let mut reference = None;
    for workers in [1, 2, 8] {
        let mut state = initial.clone();
        let error = execution::execute_parallel(
            &mut state,
            &bad,
            initial.root(),
            context(),
            policy,
            workers,
        )
        .unwrap_err();
        assert_eq!(state.root(), initial.root());
        if let Some(expected) = &reference {
            assert_eq!(&error, expected);
        } else {
            reference = Some(error);
        }
    }
}

#[test]
fn mixed_waves_match_serial_and_isolate_contract_state() {
    let initial = funded();
    let txs = batch();
    let mut serial = initial.clone();
    let expected =
        execute_signed(&mut serial, &txs, initial.root(), context(), capacity()).unwrap();
    for workers in [1, 2, 3, 8, 32] {
        let mut parallel = initial.clone();
        let result = execute_signed_parallel(
            &mut parallel,
            &txs,
            initial.root(),
            context(),
            capacity(),
            workers,
        )
        .unwrap();
        assert_eq!(result, expected);
        assert_eq!(parallel.root(), serial.root());
    }
    let a = contract_address(7, address(1), 0);
    let b = contract_address(7, address(2), 0);
    assert_eq!(serial.get(&contract_code_key(a)), Some(code().as_slice()));
    assert_eq!(
        serial.get(&contract_state_key(a, b"k")),
        Some([44].as_slice())
    );
    assert_eq!(
        serial.get(&contract_state_key(b, b"k")),
        Some([43].as_slice())
    );
    let snapshot = serial.snapshot().unwrap();
    for seed in [1, 2, 3] {
        let account = read_account(snapshot.as_ref(), address(seed))
            .unwrap()
            .unwrap();
        let fees: u64 = expected
            .0
            .iter()
            .zip(&txs)
            .filter(|(_, tx)| tx.sender == address(seed))
            .map(|(out, _)| out.receipt.resources.compute)
            .sum();
        assert_eq!(
            account,
            AccountState {
                nonce: 2,
                balance: 1_000_000 - fees
            }
        );
    }
}

#[test]
fn failures_discard_the_whole_batch_and_keep_serial_error_order() {
    let initial = funded();
    let mut variants = Vec::new();
    for mutation in 0..8 {
        let mut txs = batch();
        let tx = &mut txs[2];
        match mutation {
            0 => tx.signature[0] ^= 1,
            1 => {
                tx.nonce = 9;
                *tx = sign(tx.clone(), 1);
            }
            2 => {
                tx.resource_limit.compute = 101;
                *tx = sign(tx.clone(), 1);
            }
            3 => {
                tx.access_list.retain(|key| {
                    key != &contract_state_key(contract_address(7, address(1), 0), b"k")
                });
                *tx = sign(tx.clone(), 1);
            }
            4 => *tx = call(1, 1, contract_address(7, address(1), 0), 255),
            5 => {
                tx.expires_at = 0;
                *tx = sign(tx.clone(), 1);
            }
            6 => *tx = call(1, 1, Address([99; 32]), 42),
            _ => {
                tx.resource_prices.compute = 2;
                *tx = sign(tx.clone(), 1);
            }
        }
        variants.push(txs);
    }
    for txs in variants {
        let mut serial = initial.clone();
        let expected =
            execute_signed(&mut serial, &txs, initial.root(), context(), capacity()).unwrap_err();
        assert_eq!(serial.root(), initial.root());
        for workers in [2, 8] {
            let mut parallel = initial.clone();
            assert_eq!(
                execute_signed_parallel(
                    &mut parallel,
                    &txs,
                    initial.root(),
                    context(),
                    capacity(),
                    workers
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(parallel.root(), initial.root());
        }
    }
    let snapshot = initial.snapshot().unwrap();
    let mut legacy = SignedSession::new(snapshot.as_ref(), context(), capacity(), false);
    assert!(legacy.execute(&batch()[0]).is_err());
    assert!(legacy.execute(&payment(1, 0)).is_ok());
}

#[test]
fn payloads_are_canonical_bounded_and_context_signed() {
    for tx in batch() {
        if tx.lane == TransactionLane::Contracts {
            let payload = ContractPayload::decode(&tx.payload).unwrap();
            assert_eq!(payload.to_bytes(), tx.payload);
            for len in 0..tx.payload.len() {
                assert!(ContractPayload::decode(&tx.payload[..len]).is_err());
            }
            let mut trailing = tx.payload.clone();
            trailing.push(0);
            assert!(ContractPayload::decode(&trailing).is_err());
        }
    }
    for keys in [
        vec![vec![]],
        vec![b"k".to_vec(), b"k".to_vec()],
        vec![b"z".to_vec(), b"a".to_vec()],
        vec![vec![1; 257]],
    ] {
        let payload = ContractPayload {
            public_key: [1; 32],
            action: ContractAction::Call {
                address: Address([1; 32]),
                input: vec![],
                keys,
            },
        };
        assert!(ContractPayload::decode(&payload.to_bytes()).is_err());
    }
    assert_ne!(
        contract_address(7, address(1), 0),
        contract_address(8, address(1), 0)
    );
    assert_ne!(
        contract_address(7, address(1), 0),
        contract_address(7, address(1), 1)
    );
}
