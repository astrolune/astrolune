// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Signed account transitions, sequential visibility, and atomic rejection.

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{ExecutionError, PaymentSession, execute_payments, payment_resources};
use state::{InMemoryState, StateDatabase, StateDiff, StateError, account_key, read_account};
use transaction::{
    Payment, TransactionError, ValidationContext, address_from_public_key, signing_hash,
};
use types::{AccountState, Address, Hash256, Resources, Transaction};

fn address(seed: u8) -> Address {
    address_from_public_key(&ed25519_public_key(&[seed; 32]))
}
fn capacity() -> Resources {
    Resources {
        compute: 100,
        memory: 1024,
        io: 100,
        bandwidth: 10000,
    }
}
fn context() -> ValidationContext {
    ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    }
}
fn signed(mut tx: Transaction, seed: u8) -> Transaction {
    tx.signature = ed25519_sign(&[seed; 32], signing_hash(&tx).as_bytes());
    tx
}
fn transfer(seed: u8, recipient: Address, nonce: u64, amount: u64) -> Transaction {
    let mut keys = vec![account_key(address(seed)), account_key(recipient)];
    keys.sort();
    keys.dedup();
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender: address(seed),
        nonce,
        access_list: keys,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key: ed25519_public_key(&[seed; 32]),
            recipient,
            amount,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = payment_resources(&tx).unwrap();
    signed(tx, seed)
}
fn funded(accounts: &[(u8, u64, u64)]) -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for &(seed, nonce, balance) in accounts {
        diff.put(
            account_key(address(seed)),
            AccountState { nonce, balance }.to_bytes(),
        );
    }
    state.commit(state.root(), &[diff]).unwrap();
    state
}
fn account(state: &InMemoryState, seed: u8) -> AccountState {
    read_account(state.snapshot().unwrap().as_ref(), address(seed))
        .unwrap()
        .unwrap()
}
fn execute(state: &mut InMemoryState, txs: &[Transaction]) -> Result<(), ExecutionError> {
    execute_payments(state, txs, state.root(), context(), capacity()).map(|_| ())
}

fn changing_width_payments() -> Vec<Transaction> {
    let mut nonces = [0; 9];
    let mut txs = Vec::new();
    for _ in 0..4 {
        // Four independent transfers create recipients, then those recipients
        // spend their new balances in the next wave. Two bridges join the lanes.
        let transfers = (1..=4)
            .map(|seed| (seed, seed + 4, 20))
            .chain((5..=8).map(|seed| (seed, seed - 4, 5)))
            .chain([(1, 2, 2), (3, 4, 2), (2, 3, 1)]);
        for (seed, recipient, amount) in transfers {
            let nonce = &mut nonces[usize::from(seed)];
            txs.push(transfer(seed, address(recipient), *nonce, amount));
            *nonce += 1;
        }
        // A conservative declaration forms a singleton wave between rounds,
        // so idle workers must resume against the next committed overlay.
        let barrier = txs.last_mut().unwrap();
        barrier.access_list = (1..=8).map(|seed| account_key(address(seed))).collect();
        barrier.access_list.sort();
        barrier.resource_limit = payment_resources(barrier).unwrap();
        *barrier = signed(barrier.clone(), 2);
    }
    txs
}

fn multi_wave_capacity() -> Resources {
    Resources {
        compute: 100,
        memory: 10_000,
        io: 1_000,
        bandwidth: 100_000,
    }
}

fn consecutive_singleton_payments() -> Vec<Transaction> {
    let mut nonces = [0; 11];
    let mut txs = Vec::new();
    for _ in 0..3 {
        // The first wide wave creates four recipients. Three consecutive
        // singleton waves then create and spend from two further accounts,
        // before independent recipients resume spending in a wide wave.
        let transfers = (1..=4)
            .map(|seed| (seed, seed + 4, 20, false))
            .chain([(5, 9, 12, true), (9, 10, 8, true), (10, 5, 4, true)])
            .chain((5..=8).map(|seed| (seed, seed - 4, 5, false)))
            .chain([(1, 2, 2, false), (3, 4, 2, false), (2, 3, 1, true)]);
        for (seed, recipient, amount, barrier) in transfers {
            let nonce = &mut nonces[usize::from(seed)];
            let mut tx = transfer(seed, address(recipient), *nonce, amount);
            *nonce += 1;
            if barrier {
                tx.access_list = (1..=10).map(|seed| account_key(address(seed))).collect();
                tx.access_list.sort();
                tx.resource_limit = payment_resources(&tx).unwrap();
                tx = signed(tx, seed);
            }
            txs.push(tx);
        }
    }
    txs
}

#[test]
fn consecutive_singleton_waves_preserve_creation_nonces_and_wide_wave_visibility() {
    use execution::{ExecutionScheduler, GreedyScheduler};

    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    let txs = consecutive_singleton_payments();
    let widths: Vec<_> = GreedyScheduler
        .plan(&txs)
        .waves
        .iter()
        .map(|wave| wave.transaction_indexes.len())
        .collect();
    assert_eq!(widths, [4, 1, 1, 1, 4, 2, 1].repeat(3));
    assert!(widths.windows(3).any(|widths| widths == [1, 1, 1]));
    let mut serial = initial.clone();
    let expected = execute_payments(
        &mut serial,
        &txs,
        initial.root(),
        context(),
        multi_wave_capacity(),
    )
    .unwrap();
    assert_eq!(
        account(&serial, 9),
        AccountState {
            nonce: 3,
            balance: 9
        }
    );
    assert_eq!(
        account(&serial, 10),
        AccountState {
            nonce: 3,
            balance: 9
        }
    );
    for workers in [1, 2, 3, 8, 32] {
        let mut parallel = initial.clone();
        let old = parallel.snapshot().unwrap();
        let actual = execution::execute_payments_parallel(
            &mut parallel,
            &txs,
            initial.root(),
            context(),
            multi_wave_capacity(),
            workers,
        )
        .unwrap();
        assert_eq!(actual, expected, "workers={workers}");
        assert_eq!(parallel.export_snapshot(), serial.export_snapshot());
        assert_eq!(old.root(), initial.root());
        for seed in 5..=10 {
            assert_eq!(read_account(old.as_ref(), address(seed)).unwrap(), None);
        }
    }
}

#[test]
fn consecutive_singleton_failures_after_a_valid_prefix_allow_clean_retry() {
    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    let valid = consecutive_singleton_payments();
    let mut invalid = valid.clone();
    // The third round's middle singleton follows two full rounds and another
    // successful singleton. Its error must discard every preceding overlay.
    let failed_index = 2 * 14 + 5;
    assert_eq!(invalid[failed_index].sender, address(9));
    invalid[failed_index].resource_limit.io = 0;
    invalid[failed_index] = signed(invalid[failed_index].clone(), 9);
    // Exhaust the block capacity at the last singleton of the third round.
    let bounded = Resources {
        compute: valid[..=failed_index]
            .iter()
            .map(|tx| payment_resources(tx).unwrap().compute)
            .sum(),
        ..multi_wave_capacity()
    };
    let mut prefix = initial.clone();
    execute_payments(
        &mut prefix,
        &valid[..=failed_index],
        initial.root(),
        context(),
        bounded,
    )
    .unwrap();
    let mut serial = initial.clone();
    let expected = execute_payments(
        &mut serial,
        &valid,
        initial.root(),
        context(),
        multi_wave_capacity(),
    )
    .unwrap();
    for (txs, available) in [(&invalid, multi_wave_capacity()), (&valid, bounded)] {
        let mut rejected = initial.clone();
        let expected_error =
            execute_payments(&mut rejected, txs, initial.root(), context(), available);
        assert_eq!(expected_error, Err(ExecutionError::ResourceLimit));
        assert_eq!(rejected.export_snapshot(), initial.export_snapshot());
        for workers in [1, 2, 3, 8, 32] {
            let mut parallel = initial.clone();
            assert_eq!(
                execution::execute_payments_parallel(
                    &mut parallel,
                    txs,
                    initial.root(),
                    context(),
                    available,
                    workers,
                ),
                expected_error,
                "workers={workers}"
            );
            assert_eq!(parallel.export_snapshot(), initial.export_snapshot());
            let actual = execution::execute_payments_parallel(
                &mut parallel,
                &valid,
                initial.root(),
                context(),
                multi_wave_capacity(),
                workers,
            )
            .unwrap();
            assert_eq!(actual, expected, "retry workers={workers}");
            assert_eq!(parallel.export_snapshot(), serial.export_snapshot());
        }
    }
}

#[test]
fn repeated_changing_width_waves_preserve_outputs_and_snapshot_visibility() {
    use execution::{ExecutionScheduler, GreedyScheduler};

    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    let txs = changing_width_payments();
    let widths: Vec<_> = GreedyScheduler
        .plan(&txs)
        .waves
        .iter()
        .map(|wave| wave.transaction_indexes.len())
        .collect();
    assert_eq!(widths, [4, 4, 2, 1].repeat(4));
    let mut serial = initial.clone();
    let expected = execute_payments(
        &mut serial,
        &txs,
        initial.root(),
        context(),
        multi_wave_capacity(),
    )
    .unwrap();
    for workers in [1, 2, 3, 8, 32] {
        let mut parallel = initial.clone();
        let old = parallel.snapshot().unwrap();
        let actual = execution::execute_payments_parallel(
            &mut parallel,
            &txs,
            initial.root(),
            context(),
            multi_wave_capacity(),
            workers,
        )
        .unwrap();
        assert_eq!(actual, expected, "workers={workers}");
        assert_eq!(parallel.export_snapshot(), serial.export_snapshot());
        assert_eq!(old.root(), initial.root());
        for seed in 1..=8 {
            let original =
                read_account(initial.snapshot().unwrap().as_ref(), address(seed)).unwrap();
            assert_eq!(read_account(old.as_ref(), address(seed)).unwrap(), original);
        }
    }
}

#[test]
fn late_wave_resource_failure_allows_clean_retry_on_same_database() {
    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    let valid = changing_width_payments();
    let mut invalid = valid.clone();
    // The fourth round reaches a parallel wave after twelve successful waves.
    invalid[34].resource_limit.io = 0;
    invalid[34] = signed(invalid[34].clone(), 2);
    let mut serial = initial.clone();
    let expected_error = execute_payments(
        &mut serial,
        &invalid,
        initial.root(),
        context(),
        multi_wave_capacity(),
    );
    assert_eq!(expected_error, Err(ExecutionError::ResourceLimit));
    assert_eq!(serial.export_snapshot(), initial.export_snapshot());
    let expected = execute_payments(
        &mut serial,
        &valid,
        initial.root(),
        context(),
        multi_wave_capacity(),
    )
    .unwrap();
    for workers in [1, 2, 3, 8, 32] {
        let mut parallel = initial.clone();
        let old = parallel.snapshot().unwrap();
        assert_eq!(
            execution::execute_payments_parallel(
                &mut parallel,
                &invalid,
                initial.root(),
                context(),
                multi_wave_capacity(),
                workers,
            ),
            expected_error,
            "workers={workers}"
        );
        assert_eq!(parallel.export_snapshot(), initial.export_snapshot());
        let actual = execution::execute_payments_parallel(
            &mut parallel,
            &valid,
            initial.root(),
            context(),
            multi_wave_capacity(),
            workers,
        )
        .unwrap();
        assert_eq!(actual, expected, "workers={workers}");
        assert_eq!(parallel.export_snapshot(), serial.export_snapshot());
        assert_eq!(old.root(), initial.root());
        assert_eq!(read_account(old.as_ref(), address(5)).unwrap(), None);
    }
}

#[test]
fn parallel_executor_reuses_the_same_workers_across_payment_waves() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread::{ThreadId, current};

    use state::{StateAbsenceProof, StateProof, StateSnapshot};
    use types::StateKey;

    struct RecordingState {
        inner: InMemoryState,
        readers: Arc<Mutex<HashSet<ThreadId>>>,
    }
    struct RecordingSnapshot {
        inner: Box<dyn StateSnapshot>,
        readers: Arc<Mutex<HashSet<ThreadId>>>,
    }
    impl StateSnapshot for RecordingSnapshot {
        fn root(&self) -> Hash256 {
            self.inner.root()
        }
        fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
            self.readers.lock().unwrap().insert(current().id());
            self.inner.get(key)
        }
        fn prove(&self, key: &StateKey) -> Result<Option<StateProof>, StateError> {
            self.inner.prove(key)
        }
        fn prove_absence(&self, key: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
            self.inner.prove_absence(key)
        }
    }
    impl StateDatabase for RecordingState {
        fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
            Ok(Box::new(RecordingSnapshot {
                inner: self.inner.snapshot()?,
                readers: Arc::clone(&self.readers),
            }))
        }
        fn prefetch(&self, keys: &[StateKey]) -> Result<(), StateError> {
            self.inner.prefetch(keys)
        }
        fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
            self.inner.commit(parent, diffs)
        }
    }

    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    // New recipients force parent reads in every wave, even when the sender's
    // latest balance is already present in the speculative overlay.
    let txs: Vec<_> = (0..6_u8)
        .flat_map(|round| {
            (1..=4)
                .map(move |seed| transfer(seed, address(9 + round * 4 + seed), u64::from(round), 1))
        })
        .collect();
    let mut serial = initial.clone();
    let expected = execute_payments(
        &mut serial,
        &txs,
        initial.root(),
        context(),
        multi_wave_capacity(),
    )
    .unwrap();
    for workers in [1, 2, 3, 4, 8, 32] {
        let readers = Arc::new(Mutex::new(HashSet::new()));
        let mut parallel = RecordingState {
            inner: initial.clone(),
            readers: Arc::clone(&readers),
        };
        let actual = execution::execute_payments_parallel(
            &mut parallel,
            &txs,
            initial.root(),
            context(),
            multi_wave_capacity(),
            workers,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(parallel.inner.export_snapshot(), serial.export_snapshot());
        let readers = readers.lock().unwrap();
        if workers == 1 {
            assert_eq!(*readers, HashSet::from([current().id()]));
        } else {
            assert!(readers.len() > 1, "parallel execution fell back to serial");
            assert!(!readers.contains(&current().id()));
            let expected_readers = 4_usize.div_ceil(4_usize.div_ceil(workers));
            assert_eq!(
                readers.len(),
                expected_readers,
                "reader threads for {workers} workers across six waves"
            );
        }
    }
}

#[test]
fn parallel_waves_match_sequential_outputs_roots_and_old_snapshots() {
    let initial = funded(&[(1, 0, 1000), (2, 0, 1000), (3, 0, 1000), (4, 0, 1000)]);
    let batches = [
        vec![],
        vec![transfer(1, address(2), 0, 20)],
        vec![
            transfer(1, address(5), 0, 20),
            transfer(2, address(6), 0, 30),
            transfer(3, address(7), 0, 40),
            transfer(4, address(8), 0, 50),
        ],
        vec![
            transfer(1, address(2), 0, 20),
            transfer(3, address(4), 0, 30),
            transfer(2, address(5), 0, 40),
            transfer(1, address(1), 1, 50),
            transfer(5, address(6), 0, 10),
            transfer(4, address(1), 0, 20),
        ],
    ];
    for txs in batches {
        let mut serial = initial.clone();
        let expected =
            execute_payments(&mut serial, &txs, initial.root(), context(), capacity()).unwrap();
        for workers in [1, 2, 3, 8, 32] {
            let mut parallel = initial.clone();
            let old = parallel.snapshot().unwrap();
            let actual = execution::execute_payments_parallel(
                &mut parallel,
                &txs,
                initial.root(),
                context(),
                capacity(),
                workers,
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(parallel.root(), serial.root());
            assert_eq!(old.root(), initial.root());
            assert_eq!(
                read_account(old.as_ref(), address(1))
                    .unwrap()
                    .unwrap()
                    .balance,
                1000
            );
        }
    }
}

#[test]
fn parallel_replays_invalid_inputs_to_preserve_first_error_and_atomicity() {
    let initial = funded(&[(1, 0, 100), (2, 0, 100), (3, 0, 100)]);
    let valid = vec![
        transfer(1, address(4), 0, 10),
        transfer(2, address(5), 0, 10),
        transfer(3, address(6), 0, 10),
    ];
    let mut variants = Vec::new();
    for index in 0..valid.len() {
        let mut txs = valid.clone();
        txs[index].signature[0] ^= 1;
        variants.push(txs);
        let mut txs = valid.clone();
        txs[index].access_list.clear();
        txs[index] = signed(txs[index].clone(), u8::try_from(index + 1).unwrap());
        variants.push(txs);
        let mut txs = valid.clone();
        txs[index].nonce = 8;
        variants.push(txs);
    }
    // Conflicting failures must still report the earliest canonical transaction.
    let mut txs = valid;
    txs[0].signature = [0; 64];
    txs[2].payload.clear();
    variants.push(txs);
    for txs in variants {
        let mut serial = initial.clone();
        let expected = execute_payments(&mut serial, &txs, initial.root(), context(), capacity());
        assert!(expected.is_err());
        for workers in [2, 4] {
            let mut parallel = initial.clone();
            let actual = execution::execute_payments_parallel(
                &mut parallel,
                &txs,
                initial.root(),
                context(),
                capacity(),
                workers,
            );
            assert_eq!(actual, expected);
            assert_eq!(parallel.root(), initial.root());
        }
    }
}

#[test]
fn parallel_global_capacity_stale_parent_and_worker_bounds_fail_atomically() {
    let initial = funded(&[(1, 0, 100), (2, 0, 100)]);
    let txs = [
        transfer(1, address(3), 0, 10),
        transfer(2, address(4), 0, 10),
    ];
    for workers in [2, 8] {
        let mut state = initial.clone();
        let bounded = Resources {
            compute: 1,
            ..capacity()
        };
        assert_eq!(
            execution::execute_payments_parallel(
                &mut state,
                &txs,
                initial.root(),
                context(),
                bounded,
                workers,
            ),
            Err(ExecutionError::ResourceLimit)
        );
        assert_eq!(state.root(), initial.root());
        assert_eq!(
            execution::execute_payments_parallel(
                &mut state,
                &txs,
                Hash256::ZERO,
                context(),
                capacity(),
                workers,
            ),
            Err(ExecutionError::State(StateError::StaleSnapshot))
        );
        assert_eq!(state.root(), initial.root());
    }
    for workers in [0, 33, usize::MAX] {
        let mut state = initial.clone();
        assert!(
            execution::execute_payments_parallel(
                &mut state,
                &txs,
                initial.root(),
                context(),
                capacity(),
                workers,
            )
            .is_err()
        );
        assert_eq!(state.root(), initial.root());
    }
}

#[test]
fn sequential_transfers_create_accounts_burn_fees_and_preserve_old_snapshots() {
    let mut state = funded(&[(1, 0, 100)]);
    let old = state.snapshot().unwrap();
    let txs = [
        transfer(1, address(2), 0, 40),
        transfer(2, address(3), 0, 10),
        transfer(1, address(1), 1, 5),
    ];
    let root = state.root();
    let (outputs, _) = execute_payments(&mut state, &txs, root, context(), capacity()).unwrap();
    assert_eq!(
        account(&state, 1),
        AccountState {
            nonce: 2,
            balance: 58
        }
    );
    assert_eq!(
        account(&state, 2),
        AccountState {
            nonce: 1,
            balance: 29
        }
    );
    assert_eq!(
        account(&state, 3),
        AccountState {
            nonce: 0,
            balance: 10
        }
    );
    assert_eq!(
        read_account(old.as_ref(), address(1))
            .unwrap()
            .unwrap()
            .balance,
        100
    );
    assert_eq!(read_account(old.as_ref(), address(2)).unwrap(), None);
    assert_eq!(outputs[2].diff.len(), 1);
    assert_eq!(outputs[2].observed_lease.requests.len(), 1);
    for (output, tx) in outputs.iter().zip(txs) {
        assert_eq!(output.receipt.resources, payment_resources(&tx).unwrap());
        assert_eq!(output.receipt.output_root, output.diff.commitment());
    }
}

#[test]
fn malformed_or_unauthorized_payments_roll_back_the_entire_block() {
    let mut state = funded(&[(1, 0, 100), (2, 0, u64::MAX)]);
    let before = state.export_snapshot();
    let good = transfer(1, address(3), 0, 10);
    let base = transfer(1, address(3), 1, 10);
    let mut invalid = Vec::new();
    let mut tx = base.clone();
    tx.signature[0] ^= 1;
    invalid.push(tx);
    let mut tx = base.clone();
    tx.chain_id = 8;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.nonce = 0;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.nonce = u64::MAX;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.access_list.clear();
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.resource_limit.io = 0;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.resource_limit.compute = u64::MAX;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.payload[0] ^= 1;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.payload[8] ^= 1;
    invalid.push(signed(tx, 1));
    invalid.push(transfer(1, address(3), 1, 90));
    invalid.push(transfer(1, address(3), 1, u64::MAX));
    invalid.push(transfer(1, address(2), 1, 1));
    invalid.push(transfer(4, address(3), 0, 1));
    for tx in invalid {
        assert!(execute(&mut state, &[good.clone(), tx]).is_err());
        assert_eq!(state.export_snapshot(), before);
    }
}

#[test]
fn rejected_overlay_entry_does_not_consume_balance_nonce_or_resources() {
    let state = funded(&[(1, 0, 100), (2, 0, u64::MAX)]);
    let snapshot = state.snapshot().unwrap();
    let mut session = PaymentSession::new(snapshot.as_ref(), context(), capacity());
    assert_eq!(
        session.execute(&transfer(1, address(2), 0, 1)),
        Err(ExecutionError::Trap)
    );
    let output = session.execute(&transfer(1, address(3), 0, 99)).unwrap();
    let committed = state.prepare(state.root(), &[output.diff]).unwrap();
    assert_eq!(
        account(&committed, 1),
        AccountState {
            nonce: 1,
            balance: 0
        }
    );
}

#[test]
fn stale_roots_corrupt_accounts_and_total_resource_exhaustion_fail_closed() {
    let mut state = funded(&[(1, 0, 100)]);
    let before = state.export_snapshot();
    assert_eq!(
        execute_payments(&mut state, &[], Hash256::ZERO, context(), capacity()),
        Err(ExecutionError::State(StateError::StaleSnapshot))
    );
    let txs = [transfer(1, address(2), 0, 1), transfer(1, address(2), 1, 1)];
    let root = state.root();
    assert_eq!(
        execute_payments(
            &mut state,
            &txs,
            root,
            context(),
            Resources {
                compute: 1,
                ..capacity()
            }
        ),
        Err(ExecutionError::ResourceLimit)
    );
    assert_eq!(state.export_snapshot(), before);
    let mut diff = StateDiff::new();
    diff.put(account_key(address(2)), vec![0]);
    state.commit(root, &[diff]).unwrap();
    let before = state.export_snapshot();
    assert_eq!(
        execute(&mut state, &txs[..1]),
        Err(ExecutionError::State(StateError::Corrupt))
    );
    assert_eq!(state.export_snapshot(), before);
}

#[test]
fn fee_reserve_nonce_exhaustion_and_transaction_bounds_are_checked() {
    let mut state = funded(&[(1, 0, 100), (2, u64::MAX, 100)]);
    let mut tx = transfer(1, address(1), 0, 90);
    tx.resource_limit.compute = 11;
    assert_eq!(
        execute(&mut state, &[signed(tx, 1)]),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InsufficientResources
        ))
    );
    assert_eq!(
        execute(&mut state, &[transfer(2, address(1), u64::MAX, 1)]),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InvalidNonce
        ))
    );
    let tx = transfer(1, address(3), 0, 1);
    let root = state.root();
    assert_eq!(
        execute_payments(
            &mut state,
            &[tx],
            root,
            ValidationContext {
                max_transaction_bytes: 10,
                ..context()
            },
            capacity()
        ),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InvalidEnvelope
        ))
    );
}

#[test]
fn payment_payload_has_fixed_canonical_bytes_and_rejects_every_truncation() {
    let payment = Payment {
        public_key: [7; 32],
        recipient: Address([8; 32]),
        amount: 0x0102_0304_0506_0708,
    };
    let bytes = payment.to_bytes();
    assert_eq!(&bytes[..8], b"ALPAY001");
    assert_eq!(&bytes[8..40], &[7; 32]);
    assert_eq!(&bytes[40..72], &[8; 32]);
    assert_eq!(&bytes[72..], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(Payment::decode(&bytes), Ok(payment));
    for len in 0..bytes.len() {
        assert!(Payment::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Payment::decode(&trailing).is_err());
    assert!(
        Payment::decode(
            &Payment {
                amount: 0,
                ..payment
            }
            .to_bytes()
        )
        .is_err()
    );
    assert!(
        Payment::decode(
            &Payment {
                recipient: Address([0; 32]),
                ..payment
            }
            .to_bytes()
        )
        .is_err()
    );
}

#[test]
fn changed_height_lane_or_prices_reject_the_entire_block() {
    for (field, expected) in [
        (0, TransactionError::Expired),
        (1, TransactionError::UnsupportedPayload),
        (2, TransactionError::InsufficientResources),
    ] {
        let mut state = funded(&[(1, 0, 100), (2, 0, 100)]);
        let root = state.root();
        let first = transfer(1, address(3), 0, 5);
        let mut second = transfer(2, address(3), 0, 5);
        match field {
            0 => second.expires_at = 0,
            1 => second.lane = types::TransactionLane::Contracts,
            _ => second.resource_prices = Resources::ZERO,
        }
        assert_eq!(
            execute(&mut state, &[first, signed(second, 2)]),
            Err(ExecutionError::TransactionValidation(expected))
        );
        assert_eq!(state.root(), root);
        assert_eq!(account(&state, 1).nonce, 0);
        assert_eq!(account(&state, 2).nonce, 0);
    }
    let mut state = funded(&[(1, 0, 100)]);
    let root = state.root();
    let mut tx = transfer(1, address(2), 0, 5);
    tx.expires_at = 1;
    let tx = signed(tx, 1);
    let mut later = context();
    later.next_height = 2;
    assert!(
        execute_payments(
            &mut state,
            std::slice::from_ref(&tx),
            root,
            later,
            capacity()
        )
        .is_err()
    );
    assert_eq!(state.root(), root);
    execute(&mut state, &[tx]).unwrap();
}
