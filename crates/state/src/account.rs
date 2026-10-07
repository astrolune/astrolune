// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical account keys and reads from immutable committed state.

use codec::CanonicalDecode;
use types::{AccountState, Address, StateKey};

use crate::{StateError, StateSnapshot};

/// Returns the version-1 account key (namespace followed by the full address).
#[must_use]
pub fn account_key(address: Address) -> StateKey {
    let mut bytes = b"astrolune/account/v1/".to_vec();
    bytes.extend_from_slice(address.as_bytes());
    StateKey(bytes)
}

/// Reads an account, rejecting corrupt values instead of treating them as absent.
///
/// The caller must independently authenticate the snapshot's root.
pub fn read_account(
    snapshot: &dyn StateSnapshot,
    address: Address,
) -> Result<Option<AccountState>, StateError> {
    snapshot
        .get(&account_key(address))?
        .map(|bytes| AccountState::decode(&bytes).map_err(|_| StateError::Corrupt))
        .transpose()
}
