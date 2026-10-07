// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Account fields committed by the version-1 state layout.

/// Account state required for transaction validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountState {
    /// Next sender nonce.
    pub nonce: u64,
    /// Available smallest-unit balance.
    pub balance: u64,
}
