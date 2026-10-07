// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Snapshot parsing and exact re-encoding of all accepted inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use state::InMemoryState;
use types::Hash256;

fuzz_target!(|data: &[u8]| {
    let Some(root) = data.get(18..50) else { return };
    let root = Hash256(root.try_into().unwrap());
    // The embedded root is used only to exercise parsing. Network imports need a trusted root.
    if let Ok(state) = InMemoryState::from_snapshot(data, root) {
        assert_eq!(state.export_snapshot(), data);
    }
});
