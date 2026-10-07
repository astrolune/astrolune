// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

#![no_main]

use codec::{CanonicalDecode, CanonicalEncode};
use genesis::Genesis;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(genesis) = Genesis::decode(data) {
        assert_eq!(genesis.to_bytes(), data);
        assert!(genesis.validate().is_ok());
    }
});
