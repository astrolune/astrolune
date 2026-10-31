// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic serial and dependency-preserving wave scheduling.

use state::{AccessMode, StateLease};
use std::collections::BTreeMap;
use transaction::{ContractAction, ContractPayload, contract_code_key};
use types::{StateKey, Transaction, TransactionLane};

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
/// A canonical contract call reads its immutable code key. All other declared
/// keys remain writes, including deployment code and unknown payloads. Readers
/// can share a wave, while read/write and write/write dependencies retain block
/// order. Transactions from the same sender also stay ordered for nonce and
/// balance effects, even when their declared keys differ.
pub struct GreedyScheduler;

#[derive(Clone, Copy)]
struct KeyHistory {
    writer: Option<usize>,
    last_access: usize,
}

fn read_only_code(transaction: &Transaction) -> Option<StateKey> {
    if transaction.lane != TransactionLane::Contracts
        // The canonical header is eight bytes plus a 32-byte public key. Avoid
        // copying a deployment's potentially large code merely to classify it.
        || !transaction.payload.starts_with(b"ALCON002")
        || transaction.payload.get(40) != Some(&1)
    {
        return None;
    }
    match ContractPayload::decode(&transaction.payload).ok()?.action {
        ContractAction::Call { address, .. } => Some(contract_code_key(address)),
        ContractAction::Deploy(_) => None,
    }
}

fn access_mode(key: &StateKey, read_only: Option<&StateKey>) -> AccessMode {
    if read_only == Some(key) {
        AccessMode::Read
    } else {
        AccessMode::Write
    }
}

impl ExecutionScheduler for GreedyScheduler {
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan {
        let mut key_history: BTreeMap<&StateKey, KeyHistory> = BTreeMap::new();
        let mut last_sender_wave = BTreeMap::new();
        let mut waves: Vec<ExecutionWave> = Vec::new();

        for (index, transaction) in transactions.iter().enumerate() {
            let read_only = read_only_code(transaction);
            // Planning only needs key equality; borrow the original keys instead
            // of cloning and normalizing a lease for every transaction.
            let predecessor = transaction
                .access_list
                .iter()
                .filter_map(|key| {
                    let history = key_history.get(key)?;
                    match access_mode(key, read_only.as_ref()) {
                        AccessMode::Read => history.writer,
                        AccessMode::Write => Some(history.last_access),
                    }
                })
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
                let write = access_mode(key, read_only.as_ref()) == AccessMode::Write;
                key_history
                    .entry(key)
                    .and_modify(|history| {
                        // A later independent reader can occupy an earlier wave.
                        // A future writer must still wait for every prior reader.
                        history.last_access = history.last_access.max(wave);
                        if write {
                            history.writer = Some(wave);
                        }
                    })
                    .or_insert(KeyHistory {
                        writer: write.then_some(wave),
                        last_access: wave,
                    });
            }
            last_sender_wave.insert(transaction.sender, wave);
        }
        ExecutionPlan { waves }
    }

    fn lease(&self, transaction: &Transaction) -> StateLease {
        let read_only = read_only_code(transaction);
        StateLease::new(
            transaction
                .access_list
                .iter()
                .map(|key| state::AccessRequest {
                    key: key.clone(),
                    mode: access_mode(key, read_only.as_ref()),
                }),
        )
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
