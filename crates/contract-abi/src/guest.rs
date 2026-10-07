// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! The only external-call boundary. See ../SAFETY.md for the complete review.

use crate::AbiError;

#[link(wasm_import_module = "astrolune_v2")]
unsafe extern "C" {
    fn input_len() -> i32;
    fn input_copy(offset: i32, output: i32, length: i32) -> i32;
    fn output(pointer: i32, length: i32) -> i32;
    fn state_get(key: i32, length: i32, output: i32, capacity: i32) -> i32;
    fn state_put(key: i32, length: i32, value: i32, size: i32) -> i32;
    fn state_delete(key: i32, length: i32) -> i32;
    fn caller(output: i32) -> i32;
    fn block_height() -> i64;
    fn emit(topic: i32, data: i32, length: i32) -> i32;
}

/// Safe, allocation-free access to the fixed runtime imports.
///
/// All buffers stay borrowed for the call duration. The host copies bytes
/// synchronously, retains no guest pointers, and never reenters guest code.
pub struct Guest;

impl Guest {
    /// Returns the call input length.
    ///
    /// # Errors
    /// Returns `Host` for a negative host result.
    pub fn input_len() -> Result<usize, AbiError> {
        // SAFETY: no pointers; the trusted ABI returns a bounded input length.
        usize::try_from(unsafe { input_len() }).map_err(|_| AbiError::Host)
    }

    /// Copies exactly the output slice length from the given input offset.
    ///
    /// # Errors
    /// Rejects lengths/offsets outside i32; out-of-input bounds trap in the host.
    pub fn input_copy(offset: usize, bytes: &mut [u8]) -> Result<(), AbiError> {
        let offset = count(offset)?;
        let (pointer, length) = mutable(bytes)?;
        // SAFETY: the exclusive slice is live and writable for exactly length bytes.
        status(unsafe { input_copy(offset, pointer, length) })
    }

    /// Replaces the return data with a synchronous copy of the supplied bytes.
    ///
    /// # Errors
    /// Rejects lengths outside i32 or unexpected host status; host bounds may trap.
    pub fn output(bytes: &[u8]) -> Result<(), AbiError> {
        let (pointer, length) = shared(bytes)?;
        // SAFETY: the host only reads the live shared slice and retains no pointer.
        status(unsafe { output(pointer, length) })
    }

    /// Reads a complete value; `None` distinguishes absence from an empty value.
    ///
    /// # Errors
    /// Rejects invalid lengths/status; an undersized output or undeclared key traps.
    pub fn state_get(key: &[u8], bytes: &mut [u8]) -> Result<Option<usize>, AbiError> {
        let (key, length) = shared(key)?;
        let (pointer, capacity) = mutable(bytes)?;
        // SAFETY: Rust borrows exclude key/output aliasing; the host writes at most capacity.
        let result = unsafe { state_get(key, length, pointer, capacity) };
        match result {
            -1 => Ok(None),
            value if (0..=capacity).contains(&value) => {
                usize::try_from(value).map(Some).map_err(|_| AbiError::Host)
            }
            _ => Err(AbiError::Host),
        }
    }

    /// Stages one local value. Both slices may alias because both are read-only.
    ///
    /// # Errors
    /// Rejects unrepresentable slices or unexpected status; authorization is checked by the host.
    pub fn state_put(key: &[u8], bytes: &[u8]) -> Result<(), AbiError> {
        let (key, length) = shared(key)?;
        let (pointer, size) = shared(bytes)?;
        // SAFETY: both inputs are live read-only slices, synchronously copied by the host.
        status(unsafe { state_put(key, length, pointer, size) })
    }

    /// Stages deletion of a declared local key.
    ///
    /// # Errors
    /// Rejects unrepresentable slices or unexpected host status.
    pub fn state_delete(key: &[u8]) -> Result<(), AbiError> {
        let (pointer, length) = shared(key)?;
        // SAFETY: the host only reads this live key slice.
        status(unsafe { state_delete(pointer, length) })
    }

    /// Returns the authenticated transaction sender.
    ///
    /// # Errors
    /// Rejects an unrepresentable destination or unexpected host status.
    pub fn caller() -> Result<[u8; 32], AbiError> {
        let mut bytes = [0; 32];
        let (pointer, _) = mutable(&mut bytes)?;
        // SAFETY: caller writes exactly 32 bytes to this exclusive initialized array.
        status(unsafe { caller(pointer) })?;
        Ok(bytes)
    }

    /// Returns the finalized execution height, preserving all unsigned bits.
    #[must_use]
    pub fn block_height() -> u64 {
        // SAFETY: scalar-only trusted import, no pointers or reentry.
        u64::from_le_bytes(unsafe { block_height() }.to_le_bytes())
    }

    /// Stages a 32-byte event topic and body.
    ///
    /// # Errors
    /// Rejects unrepresentable slices or unexpected status; resource bounds may trap.
    pub fn emit(topic: &[u8; 32], bytes: &[u8]) -> Result<(), AbiError> {
        let (topic, _) = shared(topic)?;
        let (pointer, length) = shared(bytes)?;
        // SAFETY: the host copies exactly 32 topic bytes and length body bytes, read-only.
        status(unsafe { emit(topic, pointer, length) })
    }
}

fn status(value: i32) -> Result<(), AbiError> {
    if value == 0 {
        Ok(())
    } else {
        Err(AbiError::Host)
    }
}
fn count(value: usize) -> Result<i32, AbiError> {
    i32::try_from(value).map_err(|_| AbiError::Length)
}
fn shared(bytes: &[u8]) -> Result<(i32, i32), AbiError> {
    Ok((count(bytes.as_ptr() as usize)?, count(bytes.len())?))
}
fn mutable(bytes: &mut [u8]) -> Result<(i32, i32), AbiError> {
    Ok((count(bytes.as_mut_ptr() as usize)?, count(bytes.len())?))
}
