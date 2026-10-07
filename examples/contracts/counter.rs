// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Build with: cargo contract build examples/contracts/counter.rs counter.wasm
//! Calls declare the local key `counter` (hex 636f756e746572).
//! Each successful call increments a checked u64 and returns its little-endian bytes.

#![no_std]

use contract_sdk::{AbiError, Guest};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn increment() -> Result<(), AbiError> {
    let mut bytes = [0; 8];

    match Guest::state_get(b"counter", &mut bytes)? {
        None | Some(8) => {}
        _ => return Err(AbiError::Host),
    }

    let value = u64::from_le_bytes(bytes).checked_add(1).ok_or(AbiError::Host)?;
    let bytes = value.to_le_bytes();

    Guest::state_put(b"counter", &bytes)?;
    Guest::emit(&Guest::caller()?, &bytes)?;
    Guest::output(&bytes)
}

// Rust 2024 marks export names as unsafe attributes. The fixed unique entrypoint
// has the exact ABI-v2 signature; no unsafe operation occurs in contract logic.
#[unsafe(export_name = "call")]
pub extern "C" fn contract_call() -> i32 {
    match increment() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}