// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fuzz target for `Address` decoding.

#![no_main]

use codec::CanonicalDecode;
use libfuzzer_sys::fuzz_target;
use types::Address;

fuzz_target!(|data: &[u8]| {
    let _ = Address::decode(data);
});
