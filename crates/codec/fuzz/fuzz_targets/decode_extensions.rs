// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

#![no_main]

#[path = "../../../../tests/integration/tests/support/extensions.rs"]
mod extensions;
use libfuzzer_sys::fuzz_target;
use std::{cell::RefCell, io::Write};

thread_local! {
    static CURRENT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fuzz_target!(init: {
    // Coverage-only Windows runs lack ASan's death callback. Preserve the exact
    // input before libfuzzer-sys's panic hook aborts, without catching the failure.
    let directory = std::env::var_os("ASTROLUNE_FUZZ_ARTIFACTS").map(std::path::PathBuf::from);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(directory) = &directory {
            CURRENT.with(|current| {
                if let Ok(bytes) = current.try_borrow() {
                    let name = format!("panic-{}.bin", crypto::blake2s_hash(&bytes));
                    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).create_new(true)
                        .open(directory.join(name)) {
                        let _ = file.write_all(&bytes);
                        let _ = file.sync_all();
                    }
                }
            });
        }
        previous(info);
    }));
}, |bytes: &[u8]| {
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        current.clear();
        current.extend_from_slice(bytes);
    });
    extensions::check(bytes);
});
