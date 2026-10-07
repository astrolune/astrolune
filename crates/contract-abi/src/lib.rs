// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Allocation-free safe bindings to the trusted `AstroLune` WASM ABI-v2 host.
//! The only unsafe implementation is isolated to wasm32 and documented in SAFETY.md.
//! There is no native host, ambient I/O, allocator or mutable global state.

#![no_std]
#![deny(unsafe_code)]

/// Binding-level errors; runtime traps abort the enclosing call instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiError {
    /// A byte count, offset or pointer exceeds the signed 32-bit ABI range.
    Length,
    /// The host returned an unexpected status or result length.
    Host,
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod guest;
#[cfg(target_arch = "wasm32")]
pub use guest::Guest;
