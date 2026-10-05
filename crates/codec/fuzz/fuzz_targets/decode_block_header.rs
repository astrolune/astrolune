// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `BlockHeader` decoding.
//!
//! Feeds random byte slices into the canonical decoder to ensure it never
//! panics and only returns `DecodeError` variants. Run with:
//!
//! ```sh
//! cargo fuzz run decode_block_header
//! ```

#![no_main]

use codec::CanonicalDecode;
use libfuzzer_sys::fuzz_target;
use types::BlockHeader;

fuzz_target!(|data: &[u8]| {
    // The decoder must never panic on arbitrary input. It either succeeds
    // or returns a well-defined DecodeError.
    let _ = BlockHeader::decode(data);
});
