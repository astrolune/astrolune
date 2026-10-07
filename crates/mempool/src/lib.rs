// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded transaction admission and deterministic proposal selection.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use types::{Address, Hash256, Resources, Transaction};

/// Local transaction metadata used for deterministic selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolEntry {
    /// Canonical transaction identifier.
    pub id: Hash256,
    /// Canonical transaction.
    pub transaction: Transaction,
    /// Fee priority fixed at admission.
    pub priority: u64,
    /// Local monotonic admission sequence used only as a stable tie-breaker.
    pub sequence: u64,
}

/// Item and byte bounds for local admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolLimits {
    /// Maximum resident transactions.
    pub max_transactions: usize,
    /// Maximum sum of canonical transaction bytes.
    pub max_bytes: usize,
}

/// Deterministic in-memory reference pool.
#[derive(Debug)]
pub struct Mempool {
    limits: PoolLimits,
    entries: BTreeMap<(Address, u64), (PoolEntry, usize)>,
    bytes: usize,
}

impl Mempool {
    /// Creates an empty bounded pool.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::InvalidLimits`] when either bound is zero.
    pub fn new(limits: PoolLimits) -> Result<Self, MempoolError> {
        if limits.max_transactions == 0 || limits.max_bytes == 0 {
            return Err(MempoolError::InvalidLimits);
        }
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
            bytes: 0,
        })
    }

    /// Inserts an entry under a unique sender and nonce.
    ///
    /// `encoded_len` must be the already validated canonical byte length.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError`] for duplicates, conflicting sender nonces, or
    /// configured item and byte capacity exhaustion.
    pub fn insert(&mut self, entry: PoolEntry, encoded_len: usize) -> Result<(), MempoolError> {
        if encoded_len > self.limits.max_bytes {
            return Err(MempoolError::CapacityExceeded);
        }
        let key = (entry.transaction.sender, entry.transaction.nonce);
        if self
            .entries
            .values()
            .any(|(current, _)| current.id == entry.id)
        {
            return Err(MempoolError::Duplicate);
        }
        if self.entries.contains_key(&key) {
            return Err(MempoolError::ConflictingNonce);
        }
        if self.entries.len() == self.limits.max_transactions
            || self
                .bytes
                .checked_add(encoded_len)
                .is_none_or(|bytes| bytes > self.limits.max_bytes)
        {
            return Err(MempoolError::CapacityExceeded);
        }
        self.bytes += encoded_len;
        self.entries.insert(key, (entry, encoded_len));
        Ok(())
    }

    /// Selects entries by descending priority and stable admission sequence.
    ///
    /// This is a reference local policy. Consensus commits the resulting order.
    #[must_use]
    pub fn select(&self, max_transactions: usize, capacity: Resources) -> Vec<&PoolEntry> {
        let candidates = self.candidates();

        let mut used = Resources::default();
        candidates
            .into_iter()
            .filter(|entry| {
                let Some(next) = checked_add_resources(used, entry.transaction.resource_limit)
                else {
                    return false;
                };
                if next.compute > capacity.compute
                    || next.memory > capacity.memory
                    || next.io > capacity.io
                    || next.bandwidth > capacity.bandwidth
                {
                    return false;
                }
                used = next;
                true
            })
            .take(max_transactions)
            .collect()
    }

    /// Returns the resident transaction count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no transactions are resident.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes a transaction by its sender and nonce.
    pub fn remove(&mut self, sender: &Address, nonce: u64) {
        if let Some((_, bytes)) = self.entries.remove(&(*sender, nonce)) {
            self.bytes -= bytes;
        }
    }

    /// Releases entries and their byte budget once their last valid height has passed.
    pub fn remove_expired(&mut self, next_height: u64) {
        self.entries.retain(|_, (entry, bytes)| {
            if entry.transaction.expires_at < next_height {
                self.bytes -= *bytes;
                false
            } else {
                true
            }
        });
    }

    /// Removes multiple transactions by sender and nonce pairs.
    pub fn remove_batch(&mut self, keys: &[(Address, u64)]) {
        for (sender, nonce) in keys {
            self.remove(sender, *nonce);
        }
    }

    /// Returns all bounded resident entries in deterministic proposal order.
    /// Stateful selectors can skip invalid entries without reserving their capacity.
    #[must_use]
    pub fn candidates(&self) -> Vec<&PoolEntry> {
        let mut candidates: Vec<_> = self.entries.values().map(|(entry, _)| entry).collect();
        candidates
            .sort_by_key(|entry| (core::cmp::Reverse(entry.priority), entry.sequence, entry.id));
        candidates
    }
}

fn checked_add_resources(left: Resources, right: Resources) -> Option<Resources> {
    Some(Resources {
        compute: left.compute.checked_add(right.compute)?,
        memory: left.memory.checked_add(right.memory)?,
        io: left.io.checked_add(right.io)?,
        bandwidth: left.bandwidth.checked_add(right.bandwidth)?,
    })
}

/// Local pool admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MempoolError {
    /// One or more configured bounds are zero.
    InvalidLimits,
    /// Transaction identifier already exists.
    Duplicate,
    /// The same sender and nonce already identify another transaction.
    ConflictingNonce,
    /// An item or byte bound would be exceeded.
    CapacityExceeded,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => write!(f, "invalid pool limits"),
            Self::Duplicate => write!(f, "duplicate transaction"),
            Self::ConflictingNonce => write!(f, "conflicting sender nonce"),
            Self::CapacityExceeded => write!(f, "pool capacity exceeded"),
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::{Mempool, PoolEntry, PoolLimits};
    use types::{Address, Hash256, Resources, Transaction};

    fn entry(sender: u8, nonce: u64, id: u8, priority: u64, sequence: u64) -> PoolEntry {
        PoolEntry {
            id: Hash256([id; 32]),
            transaction: Transaction {
                version: types::TRANSACTION_VERSION,
                expires_at: u64::MAX,
                lane: types::TransactionLane::Payments,
                resource_prices: types::Resources {
                    compute: 1,
                    ..types::Resources::ZERO
                },
                chain_id: 1,
                sender: Address([sender; 32]),
                nonce,
                access_list: Vec::new(),
                resource_limit: Resources {
                    compute: 1,
                    memory: 1,
                    io: 1,
                    bandwidth: 1,
                },
                payload: Vec::new(),
                signature: [0; 64],
            },
            priority,
            sequence,
        }
    }

    #[test]
    fn removal_releases_exact_byte_capacity_even_when_repeated() {
        let mut pool = Mempool::new(PoolLimits {
            max_transactions: 2,
            max_bytes: 30,
        })
        .unwrap();
        for nonce in 0..10 {
            pool.insert(entry(1, nonce, 1, 0, nonce), 30).unwrap();
            pool.remove_batch(&[(Address([1; 32]), nonce), (Address([1; 32]), nonce)]);
            assert_eq!(pool.bytes, 0);
        }
        pool.insert(entry(1, 10, 1, 0, 10), 30).unwrap();
        pool.remove(&Address([1; 32]), 10);
        assert_eq!(pool.bytes, 0);
    }

    #[test]
    fn expiry_releases_item_and_byte_capacity_at_the_next_height() {
        let mut pool = Mempool::new(PoolLimits {
            max_transactions: 1,
            max_bytes: 30,
        })
        .unwrap();
        let mut expiring = entry(1, 0, 1, 0, 0);
        expiring.transaction.expires_at = 10;
        pool.insert(expiring, 30).unwrap();
        pool.remove_expired(10);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.bytes, 30);
        pool.remove_expired(11);
        assert!(pool.is_empty());
        assert_eq!(pool.bytes, 0);
        pool.insert(entry(2, 0, 1, 0, 1), 30).unwrap();
        pool.remove_expired(u64::MAX);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn selection_is_priority_then_sequence() {
        let mut pool = Mempool::new(PoolLimits {
            max_transactions: 3,
            max_bytes: 30,
        })
        .expect("valid limits");
        pool.insert(entry(1, 0, 1, 3, 2), 10).expect("insert");
        pool.insert(entry(2, 0, 2, 5, 1), 10).expect("insert");
        pool.insert(entry(3, 0, 3, 5, 0), 10).expect("insert");

        let selected = pool.select(
            3,
            Resources {
                compute: 3,
                memory: 3,
                io: 3,
                bandwidth: 3,
            },
        );
        let ids: Vec<_> = selected.iter().map(|entry| entry.id.0[0]).collect();
        assert_eq!(ids, [3, 2, 1]);
    }
}
