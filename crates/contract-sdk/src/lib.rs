// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Rust smart-contract SDK boundary for `AstroLune`.
//!
//! Contracts are authored in a deterministic Rust subset and compiled to the
//! canonical runtime target. The target, ABI, metering instrumentation, and
//! compiler version are consensus-controlled; arbitrary native Rust binaries
//! are never deployed directly.
//!
//! The host interface provides a minimal, auditable surface for state access,
//! resource metering, and cross-contract communication.

#![forbid(unsafe_code)]
#![no_std]
#![allow(clippy::missing_errors_doc)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod buffer;
pub mod error;
pub mod host;
pub mod metered;
pub mod registry;

#[cfg(feature = "alloc")]
pub use buffer::MemoryBuffer;
pub use contract_abi::AbiError;
/// Allocation-free ABI-v2 host calls on the canonical wasm32 target.
#[cfg(target_arch = "wasm32")]
pub use contract_abi::Guest;
pub use error::ContractError;
pub use host::Host;
pub use metered::{MeteredHost, ResourceUsage};

/// A contract-visible 32-byte address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Returns `true` if the address is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::collections::BTreeMap;
    use alloc::format;
    use alloc::vec::Vec;

    use super::*;

    struct MockHost {
        balances: BTreeMap<Address, u64>,
        storage: BTreeMap<Vec<u8>, Vec<u8>>,
        events: Vec<([u8; 32], Vec<u8>)>,
        height: u64,
        timestamp: u64,
    }

    impl MockHost {
        fn new() -> Self {
            let mut balances = BTreeMap::new();
            let contract_addr = Address([0x42; 32]);
            balances.insert(contract_addr, 1000);
            Self {
                balances,
                storage: BTreeMap::new(),
                events: Vec::new(),
                height: 1,
                timestamp: 1_000_000,
            }
        }
    }

    impl Host for MockHost {
        fn caller(&self) -> Address {
            Address([0x01; 32])
        }

        fn balance(&mut self, account: &Address) -> u64 {
            self.balances.get(account).copied().unwrap_or(0)
        }

        fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError> {
            let from = Address([0x42; 32]);
            let balance = self.balances.get(&from).copied().unwrap_or(0);
            if balance < amount {
                return Err(ContractError::InsufficientBalance);
            }
            *self.balances.entry(from).or_insert(0) -= amount;
            *self.balances.entry(*to).or_insert(0) += amount;
            Ok(())
        }

        fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError> {
            match self.storage.get(key) {
                Some(value) => {
                    let len = value.len().min(output.len());
                    output[..len].copy_from_slice(&value[..len]);
                    Ok(len)
                }
                None => Ok(0),
            }
        }

        fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError> {
            self.storage.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError> {
            self.storage.remove(key);
            Ok(())
        }

        fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError> {
            self.events.push((*topic, data.to_vec()));
            Ok(())
        }

        fn block_height(&self) -> u64 {
            self.height
        }

        fn block_timestamp(&self) -> u64 {
            self.timestamp
        }
    }

    #[test]
    fn mock_host_basic_operations() {
        let mut host = MockHost::new();
        let caller = host.caller();
        assert!(!caller.is_zero());

        let contract = Address([0x42; 32]);
        assert_eq!(host.balance(&contract), 1000);

        let recipient = Address([0x03; 32]);
        host.transfer(&recipient, 100).unwrap();
        assert_eq!(host.balance(&contract), 900);
        assert_eq!(host.balance(&recipient), 100);
    }

    #[test]
    fn mock_host_insufficient_balance() {
        let mut host = MockHost::new();
        let recipient = Address([0x03; 32]);
        assert_eq!(
            host.transfer(&recipient, 2000),
            Err(ContractError::InsufficientBalance)
        );
    }

    #[test]
    fn mock_host_state_operations() {
        let mut host = MockHost::new();

        host.state_write(b"key1", b"value1").unwrap();
        let mut buf = [0u8; 16];
        let n = host.state_read(b"key1", &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf[..n], b"value1");

        host.state_delete(b"key1").unwrap();
        let n = host.state_read(b"key1", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn mock_host_events() {
        let mut host = MockHost::new();
        let topic = [0xAA; 32];
        host.emit(&topic, b"hello").unwrap();
        assert_eq!(host.events.len(), 1);
        assert_eq!(host.events[0].0, topic);
        assert_eq!(host.events[0].1, b"hello");
    }

    #[test]
    fn metered_host_tracks_usage() {
        let host = MockHost::new();
        let mut metered = MeteredHost::new(host);

        let _ = metered.balance(&Address([0x42; 32]));
        let usage = metered.usage();
        assert!(usage.compute > 0);
        assert!(usage.io > 0);
    }

    #[test]
    fn metered_host_state_io_cost() {
        let host = MockHost::new();
        let mut metered = MeteredHost::new(host);

        metered.state_write(b"key", b"value").unwrap();
        let usage = metered.usage();
        assert!(usage.io > 0);
    }

    #[test]
    fn resource_usage_saturating_add() {
        let a = ResourceUsage {
            compute: 1,
            memory: 2,
            io: 3,
        };
        let b = ResourceUsage {
            compute: 4,
            memory: 5,
            io: 6,
        };
        let sum = a.saturating_add(b);
        assert_eq!(
            sum,
            ResourceUsage {
                compute: 5,
                memory: 7,
                io: 9
            }
        );
    }

    #[test]
    fn resource_usage_overflow_saturates() {
        let max = ResourceUsage {
            compute: u64::MAX,
            memory: 0,
            io: 0,
        };
        let one = ResourceUsage {
            compute: 1,
            memory: 0,
            io: 0,
        };
        let sum = max.saturating_add(one);
        assert_eq!(sum.compute, u64::MAX);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn memory_buffer_fill_and_read() {
        let mut buf = MemoryBuffer::new(8);
        assert_eq!(buf.capacity(), 8);

        let copied = buf.fill_from(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(copied, 8);
        assert_eq!(buf.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn memory_buffer_into_vec() {
        let mut buf = MemoryBuffer::new(4);
        buf.fill_from(&[10, 20, 30]);
        let data = buf.into_vec();
        assert_eq!(data, &[10, 20, 30, 0]);
    }

    #[test]
    fn contract_error_display() {
        let _ = format!("{}", ContractError::InvalidInput);
        let _ = format!("{}", ContractError::AccessDenied);
        let _ = format!("{}", ContractError::ResourceLimit);
        let _ = format!("{}", ContractError::HostFailure);
        let _ = format!("{}", ContractError::InsufficientBalance);
    }

    #[test]
    fn address_zero() {
        assert!(Address::ZERO.is_zero());
        assert!(!Address([1u8; 32]).is_zero());
    }
}
