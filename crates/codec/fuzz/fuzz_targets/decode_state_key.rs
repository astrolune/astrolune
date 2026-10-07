// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fuzz target for `StateKey` decoding.

#![no_main]

use codec::{CanonicalDecode, CanonicalEncode};
use libfuzzer_sys::fuzz_target;
use types::StateKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = StateKey::decode(data) {
        assert_eq!(value.to_bytes(), data);
    }
});
