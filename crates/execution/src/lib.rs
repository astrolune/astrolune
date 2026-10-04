// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic parallel transaction scheduling and execution.
//!
//! This crate provides:
//! - An [`ExecutionScheduler`] for building canonical execution plans
//! - A [`SimpleExecutor`] that validates, executes, and commits transactions
//! - The [`TransactionOutput`] type linking execution results to state diffs

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

mod contract;
mod error;
mod executor;
mod parallel_payment;
mod payment;
mod scheduler;
mod signed;
mod wave;

pub use error::ExecutionError;
pub use executor::{ExecutorConfig, SimpleExecutor, TransactionOutput};
pub use parallel_payment::{
    ExecutionPolicy, MAX_PAYMENT_WORKERS, execute_parallel, execute_payments_parallel,
    execute_signed_parallel,
};
pub use payment::{PAYMENT_PRICES, PaymentSession, execute_payments, payment_resources};
pub use scheduler::{ExecutionScheduler, GreedyScheduler, SerialScheduler};
pub use signed::{SignedSession, execute_signed};
pub use wave::{ExecutionLane, ExecutionPlan, ExecutionWave};

#[cfg(test)]
mod tests {
    use super::*;
    use state::{AccessMode, InMemoryState};
    use transaction::{AccountState, BasicValidator};
    use types::{Address, Resources, Transaction};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>) -> Transaction {
        Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload,
            signature: [0xFF; 64],
        }
    }

    fn config() -> ExecutorConfig {
        ExecutorConfig {
            chain_id: 7,
            next_height: 1,
            max_transaction_bytes: 1024,
        }
    }

    #[test]
    fn serial_scheduler_plan_one_per_wave() {
        let scheduler = SerialScheduler;
        let txs = vec![make_tx(0, vec![]), make_tx(0, vec![]), make_tx(0, vec![])];
        let plan = scheduler.plan(&txs);
        assert_eq!(plan.waves.len(), 3);
        assert_eq!(plan.waves[0].transaction_indexes, vec![0]);
        assert_eq!(plan.waves[1].transaction_indexes, vec![1]);
        assert_eq!(plan.waves[2].transaction_indexes, vec![2]);
    }

    #[test]
    fn serial_scheduler_lease_from_access_list() {
        let scheduler = SerialScheduler;
        let mut tx = make_tx(0, vec![]);
        tx.access_list = vec![types::StateKey(vec![1, 2]), types::StateKey(vec![3, 4])];
        let lease = scheduler.lease(&tx);
        assert_eq!(lease.requests.len(), 2);
        assert!(lease.covers(&types::StateKey(vec![1, 2]), AccessMode::Write));
        assert!(lease.covers(&types::StateKey(vec![3, 4]), AccessMode::Write));
    }

    #[test]
    fn lane_conversion() {
        assert_eq!(
            ExecutionLane::from(transaction::TransactionLane::Payments),
            ExecutionLane::Payments
        );
        assert_eq!(
            ExecutionLane::from(transaction::TransactionLane::Contracts),
            ExecutionLane::Contracts
        );
        assert_eq!(
            ExecutionLane::from(transaction::TransactionLane::System),
            ExecutionLane::System
        );
    }

    #[test]
    fn executor_empty_block() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let (outputs, root1) = executor.execute_block(&[], root0).unwrap();
        assert_eq!(outputs.len(), 0);
        assert_eq!(root0, root1);
    }

    #[test]
    fn executor_single_transaction() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![make_tx(0, vec![1, 2, 3])];
        let (outputs, root1) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_ne!(root0, root1);
        assert!(outputs[0].receipt.succeeded);
    }

    #[test]
    fn executor_multiple_transactions_sequential() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 10_000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![
            make_tx(0, vec![1]),
            make_tx(0, vec![2]),
            make_tx(0, vec![3]),
        ];
        let (outputs, _root) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 3);
        for output in &outputs {
            assert!(output.receipt.succeeded);
        }
    }

    #[test]
    fn executor_accepts_pre_validated_transaction() {
        let validator = BasicValidator::empty();
        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![make_tx(1, vec![])];
        let (outputs, _root) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].receipt.succeeded);
    }

    #[test]
    fn executor_accepts_any_chain_id() {
        let validator = BasicValidator::empty();
        let mut state = InMemoryState::new();
        let root0 = state.root();
        let config = ExecutorConfig {
            chain_id: 7,
            ..config()
        };
        let mut executor = SimpleExecutor::new(&mut state, validator, config);

        let mut tx = make_tx(0, vec![]);
        tx.chain_id = 99;
        tx.signature = [0xFF; 64];
        let txs = vec![tx];
        let (outputs, _root) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].receipt.succeeded);
    }

    #[test]
    fn executor_receipt_commitment_deterministic() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![make_tx(0, vec![1, 2, 3])];
        let (outputs, _) = executor.execute_block(&txs, root0).unwrap();
        let c1 = outputs[0].receipt.commitment();
        let c2 = outputs[0].receipt.commitment();
        assert_eq!(c1, c2);
    }

    #[test]
    fn execution_error_display() {
        let errors = [
            ExecutionError::InvalidContract,
            ExecutionError::UndeclaredStateAccess,
            ExecutionError::ResourceLimit,
            ExecutionError::Conflict,
            ExecutionError::Trap,
        ];
        for e in &errors {
            assert_ne!(e.to_string().len(), 0);
        }
    }

    #[test]
    fn execution_error_from_transaction_error() {
        let e = ExecutionError::from(transaction::TransactionError::WrongChain);
        assert!(matches!(e, ExecutionError::TransactionValidation(_)));
    }

    #[test]
    fn execution_error_from_state_error() {
        let e = ExecutionError::from(state::StateError::StaleSnapshot);
        assert!(matches!(e, ExecutionError::State(_)));
    }
}
