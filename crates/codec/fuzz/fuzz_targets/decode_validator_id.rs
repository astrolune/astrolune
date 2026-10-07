// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fuzz target for `ValidatorId` decoding.

#![no_main]

use codec::CanonicalDecode;
use libfuzzer_sys::fuzz_target;
use types::ValidatorId;

fuzz_target!(|data: &[u8]| {
    let _ = ValidatorId::decode(data);
});
