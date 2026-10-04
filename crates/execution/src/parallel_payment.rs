// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded parallel payment waves with a private overlay and serial error replay.

use std::collections::BTreeMap;

use state::{
    StateAbsenceProof, StateChange, StateDatabase, StateDiff, StateError, StateProof, StateSnapshot,
};
use transaction::{
    ContractAction, ContractPayload, Payment, ValidationContext, contract_address,
    contract_code_key, contract_state_key,
};
use types::{Hash256, Resources, StateKey, Transaction};

use crate::{
    ExecutionError, ExecutionScheduler, GreedyScheduler, SignedSession, TransactionOutput,
};

/// Maximum local payment workers. Worker count never enters protocol commitments.
pub const MAX_PAYMENT_WORKERS: usize = 32;

/// Executes conflict-free payment waves concurrently and commits in original order.
///
/// Actual payment keys are checked before planning. All intermediate results stay
/// private. Any speculative failure is replayed serially to preserve the canonical
/// first error and resource accounting. Spawn failure also falls back to serial.
pub fn execute_payments_parallel(
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
    context: ValidationContext,
    capacity: Resources,
    workers: usize,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    execute_parallel(
        database,
        transactions,
        parent,
        context,
        ExecutionPolicy {
            capacity,
            prices: crate::PAYMENT_PRICES,
            contracts: false,
        },
        workers,
    )
}

/// Executes authenticated payment and contract waves under the activated ABI-v2 profile.
pub fn execute_signed_parallel(
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
    context: ValidationContext,
    capacity: Resources,
    workers: usize,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    execute_parallel(
        database,
        transactions,
        parent,
        context,
        ExecutionPolicy {
            capacity,
            prices: crate::PAYMENT_PRICES,
            contracts: true,
        },
        workers,
    )
}

/// Parent-authenticated execution parameters, shared by serial and parallel paths.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionPolicy {
    /// Application capacity after system resource reservation.
    pub capacity: Resources,
    /// Current consensus prices.
    pub prices: Resources,
    /// Explicit contract activation.
    pub contracts: bool,
}

/// Executes under authenticated parameters, preserving serial errors and atomic publication.
pub fn execute_parallel(
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
    context: ValidationContext,
    policy: ExecutionPolicy,
    workers: usize,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    let capacity = policy.capacity;
    let serial = |database: &mut _, transactions: &[_], parent, context| {
        execute_serial(database, transactions, parent, context, policy)
    };
    if workers == 0 || workers > MAX_PAYMENT_WORKERS {
        return Err(ExecutionError::ResourceLimit);
    }
    if workers == 1 || transactions.len() < 2 {
        return serial(database, transactions, parent, context);
    }
    let snapshot = database.snapshot()?;
    if snapshot.root() != parent {
        return Err(StateError::StaleSnapshot.into());
    }
    let outputs = speculate(snapshot.as_ref(), transactions, context, policy, workers);
    let Ok(outputs) = outputs else {
        return serial(database, transactions, parent, context);
    };
    let mut used = Resources::ZERO;
    for output in &outputs {
        used = used
            .checked_add(output.receipt.resources)
            .ok_or(ExecutionError::ResourceLimit)?;
        if !used.fits_in(capacity) {
            return Err(ExecutionError::ResourceLimit);
        }
    }
    let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
    let root = database.commit(parent, &diffs)?;
    Ok((outputs, root))
}

fn execute_serial(
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
    context: ValidationContext,
    policy: ExecutionPolicy,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    let snapshot = database.snapshot()?;
    if snapshot.root() != parent {
        return Err(StateError::StaleSnapshot.into());
    }
    let mut session = SignedSession::new(
        snapshot.as_ref(),
        context,
        policy.capacity,
        policy.contracts,
    )
    .with_prices(policy.prices);
    let outputs = transactions
        .iter()
        .map(|tx| session.execute(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
    let root = database.commit(parent, &diffs)?;
    Ok((outputs, root))
}

pub(crate) struct Overlay<'a> {
    pub(crate) parent: &'a dyn StateSnapshot,
    pub(crate) values: BTreeMap<StateKey, Option<Vec<u8>>>,
}
impl StateSnapshot for Overlay<'_> {
    fn root(&self) -> Hash256 {
        self.parent.root()
    }
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        self.values
            .get(key)
            .cloned()
            .map_or_else(|| self.parent.get(key), Ok)
    }
    // Speculative overlay data must never be returned as an authenticated proof.
    fn prove(&self, _: &StateKey) -> Result<Option<StateProof>, StateError> {
        Err(StateError::StaleSnapshot)
    }
    fn prove_absence(&self, _: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
        Err(StateError::StaleSnapshot)
    }
}
impl Overlay<'_> {
    pub(crate) fn apply(&mut self, diff: &StateDiff) {
        for change in &diff.changes {
            match change {
                StateChange::Put(key, value) => {
                    self.values.insert(key.clone(), Some(value.clone()));
                }
                StateChange::Delete(key) => {
                    self.values.insert(key.clone(), None);
                }
            }
        }
    }
}

fn speculate(
    parent: &dyn StateSnapshot,
    transactions: &[Transaction],
    context: ValidationContext,
    policy: ExecutionPolicy,
    workers: usize,
) -> Result<Vec<TransactionOutput>, ExecutionError> {
    // Ensure declarations cover actual keys before trusting the wave planner.
    for tx in transactions {
        if !required_keys(tx)?
            .iter()
            .all(|key| tx.access_list.contains(key))
        {
            return Err(ExecutionError::UndeclaredStateAccess);
        }
    }
    let plan = GreedyScheduler.plan(transactions);
    let mut overlay = Overlay {
        parent,
        values: BTreeMap::new(),
    };
    let mut outputs = vec![None; transactions.len()];
    for wave in plan.waves {
        if let [index] = wave.transaction_indexes.as_slice() {
            let output = SignedSession::new(&overlay, context, policy.capacity, policy.contracts)
                .with_prices(policy.prices)
                .execute(&transactions[*index])?;
            overlay.apply(&output.diff);
            outputs[*index] = Some(output);
            continue;
        }
        let overlay_view = &overlay;
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            let mut failure = None;
            for chunk in wave
                .transaction_indexes
                .chunks(wave.transaction_indexes.len().div_ceil(workers))
            {
                if let Ok(handle) = std::thread::Builder::new().spawn_scoped(scope, move || {
                    let mut session = SignedSession::new(
                        overlay_view,
                        context,
                        policy.capacity,
                        policy.contracts,
                    )
                    .with_prices(policy.prices);
                    chunk
                        .iter()
                        .map(|&index| {
                            session
                                .execute(&transactions[index])
                                .map(|output| (index, output))
                        })
                        .collect::<Result<Vec<_>, _>>()
                }) {
                    handles.push(handle);
                } else {
                    failure = Some(ExecutionError::Trap);
                    break;
                }
            }
            let mut results = Vec::new();
            // Join every worker even on failure, keeping panic/error handling local.
            for handle in handles {
                match handle.join() {
                    Ok(Ok(outputs)) => results.extend(outputs),
                    Ok(Err(error)) => failure = Some(error),
                    Err(_) => failure = Some(ExecutionError::Trap),
                }
            }
            failure.map_or(Ok(results), Err)
        })?;
        for (index, output) in results {
            overlay.apply(&output.diff);
            outputs[index] = Some(output);
        }
    }
    outputs
        .into_iter()
        .map(|value| value.ok_or(ExecutionError::Conflict))
        .collect()
}

fn required_keys(tx: &Transaction) -> Result<Vec<StateKey>, ExecutionError> {
    let mut keys = vec![state::account_key(tx.sender)];
    match tx.lane {
        types::TransactionLane::Payments => {
            keys.push(state::account_key(Payment::decode(&tx.payload)?.recipient));
        }
        types::TransactionLane::Contracts => match ContractPayload::decode(&tx.payload)?.action {
            ContractAction::Deploy(_) => keys.push(contract_code_key(contract_address(
                tx.chain_id,
                tx.sender,
                tx.nonce,
            ))),
            ContractAction::Call {
                address,
                keys: local,
                ..
            } => {
                keys.push(contract_code_key(address));
                keys.extend(local.iter().map(|key| contract_state_key(address, key)));
            }
        },
        types::TransactionLane::System => {
            return Err(transaction::TransactionError::UnsupportedPayload.into());
        }
    }
    Ok(keys)
}
