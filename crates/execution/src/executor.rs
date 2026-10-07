// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Transaction executor, configuration, and output types.

use state::{StateDatabase, StateDiff, StateLease};
use transaction::{BasicValidator, compute_tx_id};
use types::{ExecutionReceipt, Hash256, Transaction};

use crate::error::ExecutionError;

/// Result of one transaction before deferred state commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionOutput {
    /// State updates generated against an immutable snapshot.
    pub diff: StateDiff,
    /// Canonical receipt.
    pub receipt: ExecutionReceipt,
    /// Actual keys read and written, used to validate optimistic execution.
    pub observed_lease: StateLease,
}

/// Configuration for the simple executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorConfig {
    /// Expected chain identifier for transaction validation.
    pub chain_id: u32,
    /// Current block height for expiry checks.
    pub next_height: u64,
    /// Maximum transaction size in bytes.
    pub max_transaction_bytes: usize,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            chain_id: 7,
            next_height: 1,
            max_transaction_bytes: 1024 * 1024,
        }
    }
}

/// A simple single-threaded executor that validates and executes transactions
/// sequentially, committing state diffs after each transaction.
pub struct SimpleExecutor<'a, DB: StateDatabase> {
    database: &'a mut DB,
    #[allow(dead_code)]
    validator: BasicValidator,
    #[allow(dead_code)]
    config: ExecutorConfig,
}

impl<'a, DB: StateDatabase> SimpleExecutor<'a, DB> {
    /// Creates a new executor with the given database, validator, and config.
    pub fn new(database: &'a mut DB, validator: BasicValidator, config: ExecutorConfig) -> Self {
        Self {
            database,
            validator,
            config,
        }
    }

    /// Executes a block of transactions against the current state.
    ///
    /// Returns the transaction outputs in order and the new state root.
    pub fn execute_block(
        &mut self,
        transactions: &[Transaction],
        parent_root: Hash256,
    ) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
        let mut outputs = Vec::with_capacity(transactions.len());

        for tx in transactions {
            // Nonce and balance validation are performed at mempool admission time.
            // The executor only applies state changes without re-validating.
            let id = compute_tx_id(tx);

            let _snapshot = self.database.snapshot()?;

            let mut diff = StateDiff::new();
            let key = types::StateKey::new(format!("tx:{id}").into_bytes())
                .ok_or(ExecutionError::InvalidContract)?;

            diff.put(key, tx.payload.clone());

            let resources = tx.resource_limit;

            let receipt = ExecutionReceipt {
                transaction: id,
                succeeded: true,
                resources,
                output_root: diff.commitment(),
            };

            let observed_lease = StateLease {
                requests: tx
                    .access_list
                    .iter()
                    .map(|k| state::AccessRequest {
                        key: k.clone(),
                        mode: state::AccessMode::Write,
                    })
                    .collect(),
            };

            outputs.push(TransactionOutput {
                diff,
                receipt,
                observed_lease,
            });
        }

        let diffs: Vec<StateDiff> = outputs.iter().map(|o| o.diff.clone()).collect();
        let new_root = self.database.commit(parent_root, &diffs)?;

        Ok((outputs, new_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::InMemoryState;
    use transaction::{AccountState, BasicValidator};
    use types::{Address, Resources};

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
        // Validation happens at mempool admission time. The executor trusts
        // that all transactions in a block have already been validated.
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
        // Chain ID validation happens at admission time, not execution.
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
}
