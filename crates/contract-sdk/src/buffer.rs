// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! A fixed-capacity buffer provided by the host to the contract.

extern crate alloc;

use alloc::vec::Vec;

/// A fixed-capacity buffer provided by the host to the contract.
///
/// The contract reads from and writes into this buffer. The host enforces
/// size limits and tracks I/O for resource metering.
pub struct MemoryBuffer {
    data: Vec<u8>,
    capacity: usize,
}

impl MemoryBuffer {
    /// Creates a new buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: alloc::vec![0u8; capacity],
            capacity,
        }
    }

    /// Returns the buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current buffer length (bytes written).
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the buffer contents.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the buffer contents.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Copies data into the buffer from a source slice.
    ///
    /// Returns the number of bytes actually copied (limited by capacity).
    pub fn fill_from(&mut self, source: &[u8]) -> usize {
        let len = source.len().min(self.capacity);
        self.data[..len].copy_from_slice(&source[..len]);
        len
    }

    /// Consumes the buffer and returns the underlying data.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}
