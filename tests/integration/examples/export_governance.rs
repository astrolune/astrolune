// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Produces review candidates in a new directory; never rewrites checked-in fixtures.

#[path = "../tests/support/governance_compatibility.rs"]
mod compatibility;

use std::{fmt::Write as _, io::Write as _};

fn main() {
    let output = std::env::args_os()
        .nth(1)
        .expect("supply a NEW candidate directory");
    let output = std::path::Path::new(&output);

    std::fs::create_dir(output).expect("candidate directory must not already exist");

    let mut manifest = String::new();

    for (name, bytes) in compatibility::build() {
        let path = output.join(&name);

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();

        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();

        writeln!(
            manifest,
            "{} {} {name}",
            crypto::blake2s_hash(&bytes),
            bytes.len()
        )
        .unwrap();
    }

    std::fs::write(output.join("MANIFEST.blake2s"), manifest).unwrap();
}
