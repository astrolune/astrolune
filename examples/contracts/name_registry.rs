// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Closed-network DNS registry, built with cargo contract build.
#![no_std]

use contract_sdk::{Guest, registry::{self, RegistryCall}};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(export_name = "call")]
pub extern "C" fn call() -> i32 {
    execute().map_or(1, |()| 0)
}

fn execute() -> Result<(), ()> {
    let length = Guest::input_len().map_err(|_| ())?;
    let mut input = [0; registry::MAX_CALL];
    let input = input.get_mut(..length).ok_or(())?;
    Guest::input_copy(0, input).map_err(|_| ())?;

    let call = RegistryCall::decode(input).map_err(|_| ())?;

    let mut key = [0; registry::MAX_NAME + 7];
    let length = registry::registry_key(call.name, &mut key).map_err(|_| ())?;
    let key = &key[..length];

    let mut current = [0; registry::MAX_LEASE];
    let previous = Guest::state_get(key, &mut current).map_err(|_| ())?;

    let mut next = [0; registry::MAX_LEASE];
    let caller = Guest::caller().map_err(|_| ())?;

    match registry::transition(call, previous.map(|len| &current[..len]), caller, Guest::block_height(), &mut next).map_err(|_| ())? {
        Some(length) => Guest::state_put(key, &next[..length]).map_err(|_| ())?,
        None => Guest::state_delete(key).map_err(|_| ())?,
    }

    Guest::output(call.name).map_err(|_| ())
}