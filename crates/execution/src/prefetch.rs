// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded, advisory hints for database implementations with a prefetch facility.
//! The existing backends are no-ops; this hook alone makes no speedup claim.

use std::collections::BTreeSet;

use state::StateDatabase;
use types::Transaction;

const MAX_TRANSACTIONS: usize = 256;
const MAX_ACCESSES: usize = 1024;
const MAX_KEYS: usize = 256;
const MAX_KEY_BYTES: usize = 64 * 1024;

/// Offers a bounded prefix of declared keys after checking the parent root.
/// Hints do not replace reads or validation, and failure never changes execution.
pub(crate) fn declared_keys(database: &impl StateDatabase, transactions: &[Transaction]) {
    let mut keys = BTreeSet::new();
    let mut bytes = 0;
    for key in transactions
        .iter()
        .take(MAX_TRANSACTIONS)
        .flat_map(|tx| &tx.access_list)
        .take(MAX_ACCESSES)
    {
        // Inspect length before comparing or copying an oversized key.
        if key.0.len() > MAX_KEY_BYTES - bytes {
            continue;
        }
        if keys.insert(key) {
            bytes += key.0.len();
            if keys.len() == MAX_KEYS {
                break;
            }
        }
    }
    if !keys.is_empty() {
        let keys: Vec<_> = keys.into_iter().cloned().collect();
        let _ = database.prefetch(&keys);
    }
}
