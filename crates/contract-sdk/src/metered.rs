// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Resource metering wrapper for the [`Host`] trait.

use crate::{Address, ContractError, Host};

/// Execution resources charged by their actual class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceUsage {
    /// Metered instruction and host-call work.
    pub compute: u64,
    /// Peak linear-memory usage.
    pub memory: u64,
    /// State input/output bytes and operations.
    pub io: u64,
}

impl ResourceUsage {
    /// All-zero resource usage.
    pub const ZERO: Self = Self {
        compute: 0,
        memory: 0,
        io: 0,
    };

    /// Returns `true` if all resource classes are zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.compute == 0 && self.memory == 0 && self.io == 0
    }

    /// Adds another resource usage to this one.
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            compute: self.compute.saturating_add(other.compute),
            memory: self.memory.saturating_add(other.memory),
            io: self.io.saturating_add(other.io),
        }
    }
}

/// A `Host` wrapper that tracks resource usage during execution.
///
/// `MeteredHost` delegates all host calls to the inner implementation while
/// accumulating the resource cost of each operation.
pub struct MeteredHost<H: Host> {
    inner: H,
    usage: ResourceUsage,
}

impl<H: Host> MeteredHost<H> {
    /// Wraps a host implementation with resource metering.
    #[must_use]
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            usage: ResourceUsage::ZERO,
        }
    }

    /// Returns the accumulated resource usage.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.usage
    }

    /// Consumes the wrapper and returns the inner host and final usage.
    #[must_use]
    pub fn into_parts(self) -> (H, ResourceUsage) {
        (self.inner, self.usage)
    }
}

impl<H: Host> Host for MeteredHost<H> {
    fn caller(&self) -> Address {
        self.inner.caller()
    }

    fn balance(&mut self, account: &Address) -> u64 {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: 1,
        });
        self.inner.balance(account)
    }

    fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 2,
            memory: 0,
            io: 2,
        });
        self.inner.transfer(to, amount)
    }

    fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError> {
        let cost = key.len() as u64 + output.len() as u64;
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: cost,
        });
        self.inner.state_read(key, output)
    }

    fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError> {
        let cost = key.len() as u64 + value.len() as u64;
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 2,
            memory: 0,
            io: cost,
        });
        self.inner.state_write(key, value)
    }

    fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: key.len() as u64,
        });
        self.inner.state_delete(key)
    }

    fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: 32 + data.len() as u64,
        });
        self.inner.emit(topic, data)
    }

    fn block_height(&self) -> u64 {
        self.inner.block_height()
    }

    fn block_timestamp(&self) -> u64 {
        self.inner.block_timestamp()
    }
}
