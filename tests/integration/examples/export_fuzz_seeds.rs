// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Exports the same structured corpus used by deterministic mutation qualification.
#[path = "../tests/mutations.rs"]
#[allow(dead_code)]
mod mutations;

fn main() {
    let output = std::env::args_os()
        .nth(1)
        .expect("supply a NEW corpus directory");
    let output = std::path::Path::new(&output);
    std::fs::create_dir(output).expect("corpus directory must not already exist");
    let mut seeds = mutations::seeds();
    // Keep malformed regressions separate from the mutation test's accepted seeds.
    let valid = seeds[7].clone();
    assert!(valid.ends_with(&[10, 6, 1, 4, 0, 65, 0, 11]));
    for (index, opcode) in [0x01, 0x0b, 0x0f].into_iter().enumerate() {
        let mut invalid = valid.clone();
        let start = invalid.len() - 8;
        invalid[start + 1] += 1;
        invalid[start + 3] += 1;
        invalid.push(opcode);
        seeds.insert(9 + index, invalid);
    }
    for (index, bytes) in seeds.iter().enumerate() {
        std::fs::write(output.join(format!("seed-{index:03}")), bytes).unwrap();
    }
    println!("Exported {} structured seeds", seeds.len());
}
