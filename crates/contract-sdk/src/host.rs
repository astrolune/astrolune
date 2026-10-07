// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic host functions exposed to Rust contracts.

use crate::{Address, ContractError};

/// Deterministic host functions exposed to Rust contracts.
pub trait Host: Send {
    /// Returns the transaction sender.
    fn caller(&self) -> Address;

    /// Returns the balance of an account in the smallest unit.
    fn balance(&mut self, account: &Address) -> u64;

    /// Transfers tokens from the contract's account to another account.
    fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError>;

    /// Reads contract-local state into the supplied output buffer.
    ///
    /// Returns the number of bytes actually read.
    fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError>;

    /// Writes contract-local state under an access lease.
    fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError>;

    /// Deletes contract-local state under a key.
    fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError>;

    /// Emits a canonical event.
    fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError>;

    /// Returns the current block height.
    fn block_height(&self) -> u64;

    /// Returns the current timestamp (Unix seconds).
    fn block_timestamp(&self) -> u64;
}
