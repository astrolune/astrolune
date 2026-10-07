// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Accepted receipts must re-encode to the exact input bytes.

#![no_main]

use codec::{CanonicalDecode, CanonicalEncode};
use libfuzzer_sys::fuzz_target;
use types::ExecutionReceipt;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = ExecutionReceipt::decode(data) {
        assert_eq!(value.to_bytes(), data);
    }
});
