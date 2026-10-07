// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Accepted transactions must re-encode to the exact input bytes.

#![no_main]

use codec::{CanonicalDecode, CanonicalEncode};
use libfuzzer_sys::fuzz_target;
use types::Transaction;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = Transaction::decode(data) {
        assert_eq!(value.to_bytes(), data);
    }
});
