// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic serial and dependency-preserving wave scheduling.

use state::{AccessMode, StateLease};
use std::collections::BTreeMap;
use types::Transaction;

use crate::wave::{ExecutionPlan, ExecutionWave};

/// Schedules declared and predicted state accesses.
pub trait ExecutionScheduler {
    /// Builds a canonical plan. Predictions may improve placement, but validators
    /// must derive the same fallback ordering when predictions are absent or wrong.
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan;

    /// Reserves declared keys for a transaction during its execution wave.
    fn lease(&self, transaction: &Transaction) -> StateLease;
}

/// Default scheduler that places each transaction in its own wave (serial execution).
pub struct SerialScheduler;

impl ExecutionScheduler for SerialScheduler {
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan {
        let waves = (0..transactions.len())
            .map(|i| ExecutionWave {
                transaction_indexes: vec![i],
            })
            .collect();
        ExecutionPlan { waves }
    }

    fn lease(&self, transaction: &Transaction) -> StateLease {
        StateLease::new(
            transaction
                .access_list
                .iter()
                .map(|key| state::AccessRequest {
                    key: key.clone(),
                    mode: AccessMode::Write,
                }),
        )
    }
}

/// Places each transaction in the earliest wave after its conflicting predecessors.
///
/// Declared keys are conservatively treated as writes until transactions encode
/// access modes. Transactions from the same sender stay ordered for nonce and
/// balance effects, even when their declared keys differ.
pub struct GreedyScheduler;

impl ExecutionScheduler for GreedyScheduler {
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan {
        let mut last_key_wave = BTreeMap::new();
        let mut last_sender_wave = BTreeMap::new();
        let mut waves: Vec<ExecutionWave> = Vec::new();

        for (index, transaction) in transactions.iter().enumerate() {
            // Planning only needs key equality; borrow the original keys instead
            // of cloning and normalizing a lease for every transaction.
            let predecessor = transaction
                .access_list
                .iter()
                .filter_map(|key| last_key_wave.get(key).copied())
                .chain(last_sender_wave.get(&transaction.sender).copied())
                .max();
            let wave = predecessor.map_or(0, |previous| previous + 1);
            if wave == waves.len() {
                waves.push(ExecutionWave {
                    transaction_indexes: Vec::new(),
                });
            }
            waves[wave].transaction_indexes.push(index);
            // Update only after all predecessors are read so duplicate keys
            // cannot make a transaction depend on itself.
            for key in &transaction.access_list {
                last_key_wave.insert(key, wave);
            }
            last_sender_wave.insert(transaction.sender, wave);
        }
        ExecutionPlan { waves }
    }

    fn lease(&self, transaction: &Transaction) -> StateLease {
        SerialScheduler.lease(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
