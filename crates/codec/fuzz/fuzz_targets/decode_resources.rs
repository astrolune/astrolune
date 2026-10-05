// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `Resources` decoding.

#![no_main]

use codec::CanonicalDecode;
use libfuzzer_sys::fuzz_target;
use types::Resources;

fuzz_target!(|data: &[u8]| {
    let _ = Resources::decode(data);
});
