// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded parallel payment waves with a private overlay and serial error replay.

use std::{collections::BTreeMap, sync::RwLock};

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
    let serial = |database: &mut _, transactions: &[_], parent, context, prefetch| {
        execute_serial(database, transactions, parent, context, policy, prefetch)
    };
    if workers == 0 || workers > MAX_PAYMENT_WORKERS {
        return Err(ExecutionError::ResourceLimit);
    }
    if workers == 1 || transactions.len() < 2 {
        return serial(database, transactions, parent, context, true);
    }
    let snapshot = database.snapshot()?;
    if snapshot.root() != parent {
        return Err(StateError::StaleSnapshot.into());
    }
    crate::prefetch::declared_keys(database, transactions);
    let cached = crate::snapshot_cache::CachedSnapshot::new(snapshot.as_ref());
    let view = execution_view(snapshot.as_ref(), &cached, policy.contracts);
    let outputs = speculate(view, transactions, context, policy, workers);
    let Ok(outputs) = outputs else {
        drop(cached);
        return serial(database, transactions, parent, context, false);
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
    prefetch: bool,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    let snapshot = database.snapshot()?;
    if snapshot.root() != parent {
        return Err(StateError::StaleSnapshot.into());
    }
    if prefetch {
        crate::prefetch::declared_keys(database, transactions);
    }
    let cached = crate::snapshot_cache::CachedSnapshot::new(snapshot.as_ref());
    let view = execution_view(snapshot.as_ref(), &cached, policy.contracts);
    let mut session = SignedSession::new(view, context, policy.capacity, policy.contracts)
        .with_prices(policy.prices);
    let outputs = transactions
        .iter()
        .map(|tx| session.execute(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
    let root = database.commit(parent, &diffs)?;
    Ok((outputs, root))
}

fn execution_view<'a>(
    parent: &'a dyn StateSnapshot,
    cached: &'a crate::snapshot_cache::CachedSnapshot<'_>,
    contracts: bool,
) -> &'a dyn StateSnapshot {
    // Payments write every account they read, so the existing overlay already
    // serves their repeated accesses without an additional read cache.
    if contracts { cached } else { parent }
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
    let overlay = RwLock::new(Overlay {
        parent,
        values: BTreeMap::new(),
    });
    let mut outputs = vec![None; transactions.len()];
    let pool_size = plan
        .waves
        .iter()
        .map(|wave| wave.transaction_indexes.len())
        .max()
        .unwrap_or(0)
        .min(workers);
    let execute_chunk = |(chunk, mut results): (&[usize], Vec<(usize, TransactionOutput)>)| {
        results.clear();
        let view = overlay.read().map_err(|_| ExecutionError::Trap)?;
        let mut session = SignedSession::new(&*view, context, policy.capacity, policy.contracts)
            .with_prices(policy.prices);
        for &index in chunk {
            results.push((index, session.execute(&transactions[index])?));
        }
        Ok(results)
    };
    std::thread::scope(|scope| {
        let mut pool = if pool_size > 1 {
            Some(crate::worker_pool::ScopedWorkerPool::new(
                scope,
                pool_size,
                &execute_chunk,
            )?)
        } else {
            None
        };
        let mut buffers: Vec<Vec<_>> = (0..pool_size).map(|_| Vec::new()).collect();
        let mut returned = Vec::with_capacity(pool_size);
        let mut serial_buffer = Vec::new();
        let mut fused_indexes = Vec::new();
        let mut waves = plan.waves.iter().peekable();
        while let Some(wave) = waves.next() {
            let indexes = wave.transaction_indexes.as_slice();
            if let [index] = indexes {
                // Consecutive singleton waves form one sequential session. Its
                // private writes feed dependent transactions without publishing
                // intermediate state to the coordinator between each call.
                fused_indexes.clear();
                fused_indexes.push(*index);
                while let Some(next) = waves.next_if(|next| next.transaction_indexes.len() == 1) {
                    fused_indexes.push(next.transaction_indexes[0]);
                }
                serial_buffer = execute_chunk((&fused_indexes, serial_buffer))?;
                let mut view = overlay.write().map_err(|_| ExecutionError::Trap)?;
                for (index, output) in serial_buffer.drain(..) {
                    view.apply(&output.diff);
                    outputs[index] = Some(output);
                }
            } else {
                let tasks = indexes
                    .chunks(indexes.len().div_ceil(workers))
                    .zip(buffers.iter_mut())
                    .map(|(chunk, buffer)| (chunk, std::mem::take(buffer)));
                pool.as_mut()
                    .ok_or(ExecutionError::Conflict)?
                    .map_into(tasks, &mut returned)?;
                // All readers have finished. Move outputs into their final
                // positions, then return empty allocations to the buffer pool.
                let mut view = overlay.write().map_err(|_| ExecutionError::Trap)?;
                for (buffer, mut results) in buffers.iter_mut().zip(returned.drain(..)) {
                    for (index, output) in results.drain(..) {
                        view.apply(&output.diff);
                        outputs[index] = Some(output);
                    }
                    *buffer = results;
                }
            }
        }
        Ok::<_, ExecutionError>(())
    })?;
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
