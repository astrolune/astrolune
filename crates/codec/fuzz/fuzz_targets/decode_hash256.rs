// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `Hash256` decoding.

#![no_main]

use codec::CanonicalDecode;
use libfuzzer_sys::fuzz_target;
use types::Hash256;

fuzz_target!(|data: &[u8]| {
    let _ = Hash256::decode(data);
});
