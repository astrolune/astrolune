// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Produces `PoTB` compatibility candidates exclusively in a new directory.

#[path = "../tests/support/potb_compatibility.rs"]
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
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output.join(&name))
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

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("MANIFEST.blake2s"))
        .unwrap();

    file.write_all(manifest.as_bytes()).unwrap();
    file.sync_all().unwrap();
}