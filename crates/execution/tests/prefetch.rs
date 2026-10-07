// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Prefetch is a bounded hint and cannot affect canonical execution results.

use std::cell::RefCell;

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{
    ExecutionError, TransactionOutput, execute_payments, execute_payments_parallel, execute_signed,
    execute_signed_parallel, payment_resources,
};
use state::{InMemoryState, StateDatabase, StateDiff, StateError, StateSnapshot, account_key};
use transaction::{Payment, ValidationContext, address_from_public_key, signing_hash};
use types::{AccountState, Hash256, Resources, StateKey, Transaction};

struct RecordingState {
    inner: InMemoryState,
    calls: RefCell<Vec<Vec<StateKey>>>,
    fail: bool,
}

impl RecordingState {
    fn new(inner: InMemoryState, fail: bool) -> Self {
        Self {
            inner,
            calls: RefCell::new(Vec::new()),
            fail,
        }
    }
}

impl StateDatabase for RecordingState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        self.inner.snapshot()
    }

    fn prefetch(&self, keys: &[StateKey]) -> Result<(), StateError> {
        self.calls.borrow_mut().push(keys.to_vec());
        if self.fail {
            Err(StateError::Io)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
        self.inner.commit(parent, diffs)
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Payments,
    Signed,
    ParallelPayments(usize),
    ParallelSigned(usize),
}

const ROUTES: [Route; 6] = [
    Route::Payments,
    Route::Signed,
    Route::ParallelPayments(1),
    Route::ParallelPayments(4),
    Route::ParallelSigned(1),
    Route::ParallelSigned(4),
];

fn execute(
    route: Route,
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    let context = ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };
    let capacity = Resources {
        compute: 100,
        memory: 1024,
        io: 100,
        bandwidth: 10000,
    };
    match route {
        Route::Payments => execute_payments(database, transactions, parent, context, capacity),
        Route::Signed => execute_signed(database, transactions, parent, context, capacity),
        Route::ParallelPayments(workers) => {
            execute_payments_parallel(database, transactions, parent, context, capacity, workers)
        }
        Route::ParallelSigned(workers) => {
            execute_signed_parallel(database, transactions, parent, context, capacity, workers)
        }
    }
}

fn transfer(nonce: u64) -> Transaction {
    let public_key = ed25519_public_key(&[1; 32]);
    let sender = address_from_public_key(&public_key);
    let recipient = address_from_public_key(&ed25519_public_key(&[2; 32]));
    let mut keys = vec![account_key(sender), account_key(recipient)];
    keys.sort();
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: execution::PAYMENT_PRICES,
        chain_id: 7,
        sender,
        nonce,
        access_list: keys,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key,
            recipient,
            amount: 10,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[1; 32], signing_hash(&tx).as_bytes());
    tx
}

fn funded() -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    diff.put(
        account_key(transfer(0).sender),
        AccountState {
            nonce: 0,
            balance: 1000,
        }
        .to_bytes(),
    );
    state.commit(state.root(), &[diff]).unwrap();
    state
}

#[test]
fn successful_and_failed_hints_preserve_outputs_roots_and_canonical_errors() {
    for route in ROUTES {
        for fail in [false, true] {
            for transactions in [
                vec![transfer(0), transfer(1)],
                vec![transfer(0), transfer(0)],
            ] {
                let mut normal = funded();
                let parent = normal.root();
                let expected = execute(route, &mut normal, &transactions, parent);
                let mut recording = RecordingState::new(funded(), fail);
                let actual = execute(route, &mut recording, &transactions, parent);
                assert_eq!(actual, expected, "{route:?}, fail={fail}");
                assert_eq!(recording.inner.root(), normal.root());
                assert_eq!(recording.calls.borrow().len(), 1, "{route:?}");
                assert_eq!(recording.calls.borrow()[0], transactions[0].access_list);
                if actual.is_err() {
                    assert_eq!(recording.inner.root(), parent);
                }
            }
        }
    }
}

#[test]
fn stale_roots_and_empty_blocks_do_not_prefetch() {
    for route in ROUTES {
        let mut database = RecordingState::new(funded(), false);
        let parent = database.inner.root();
        let stale = Hash256([0xff; 32]);
        assert_ne!(parent, stale);
        assert_eq!(
            execute(route, &mut database, &[transfer(0), transfer(1)], stale),
            Err(StateError::StaleSnapshot.into())
        );
        assert!(database.calls.borrow().is_empty());
        assert!(execute(route, &mut database, &[], parent).is_ok());
        assert!(database.calls.borrow().is_empty());
    }
}

fn hints(transactions: &[Transaction]) -> Vec<Vec<StateKey>> {
    let mut database = RecordingState::new(InMemoryState::new(), false);
    let parent = database.inner.root();
    // Invalid transactions still demonstrate which advisory keys are offered.
    let _ = execute(Route::Payments, &mut database, transactions, parent);
    database.calls.into_inner()
}

#[test]
fn keys_are_sorted_deduplicated_and_empty_lists_are_skipped() {
    let mut first = transfer(0);
    first.access_list = vec![StateKey(vec![3]), StateKey(vec![1]), StateKey(vec![3])];
    let mut second = first.clone();
    second.access_list = vec![StateKey(vec![2]), StateKey(vec![1])];
    assert_eq!(
        hints(&[first.clone(), second]),
        vec![vec![
            StateKey(vec![1]),
            StateKey(vec![2]),
            StateKey(vec![3])
        ]]
    );
    first.access_list.clear();
    assert_eq!(hints(&[first]), [] as [Vec<StateKey>; 0]);
}

#[test]
fn key_count_bytes_and_inspected_prefix_are_bounded() {
    let mut tx = transfer(0);
    tx.access_list = (0..300_u16)
        .map(|number| StateKey(number.to_be_bytes().to_vec()))
        .collect();
    let calls = hints(&[tx.clone()]);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], tx.access_list[..256]);

    tx.access_list = vec![
        StateKey(vec![0; 64 * 1024 + 1]),
        StateKey(vec![1; 32 * 1024]),
        StateKey(vec![2; 32 * 1024]),
        StateKey(vec![3]),
    ];
    let calls = hints(&[tx.clone()]);
    assert_eq!(calls[0], tx.access_list[1..3]);
    assert_eq!(
        calls[0].iter().map(|key| key.0.len()).sum::<usize>(),
        64 * 1024
    );

    tx.access_list = vec![StateKey(vec![1]); 1024];
    tx.access_list.push(StateKey(vec![2]));
    assert_eq!(hints(&[tx.clone()]), vec![vec![StateKey(vec![1])]]);

    tx.access_list.clear();
    let mut transactions = vec![tx.clone(); 256];
    tx.access_list = vec![StateKey(vec![1])];
    transactions.push(tx);
    assert_eq!(hints(&transactions), [] as [Vec<StateKey>; 0]);
}
