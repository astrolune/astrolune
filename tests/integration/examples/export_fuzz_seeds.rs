// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Exports the same structured corpus used by deterministic mutation qualification.

#[path = "../tests/support/contract_modules.rs"]
#[allow(dead_code)]
mod contract_modules;
#[path = "../tests/mutations.rs"]
#[allow(dead_code)]
mod mutations;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().expect("supply a NEW corpus directory");
    let output = std::path::Path::new(&output);
    let set = arguments.next().unwrap_or_else(|| "extensions".into());
    let set = set.to_str().expect("corpus name must be UTF-8");

    std::fs::create_dir(output).expect("corpus directory must not already exist");

    let seeds = match set {
        "extensions" => extension_corpus(),
        "contracts" => contract_modules::corpus(),
        other => panic!("unknown corpus {other}; expected extensions or contracts"),
    };

    for (index, bytes) in seeds.iter().enumerate() {
        std::fs::write(output.join(format!("seed-{index:03}")), bytes).unwrap();
    }

    println!("Exported {} structured {set} seeds", seeds.len());
}

fn extension_corpus() -> Vec<Vec<u8>> {
    let mut seeds = mutations::seeds();

    // Keep malformed regressions separate from the mutation test's accepted seeds.
    let valid = seeds[7].clone();
    assert!(valid.ends_with(&contract_modules::MINIMAL_TAIL));

    for (index, invalid) in contract_modules::regressions(&valid)
        .into_iter()
        .enumerate()
    {
        seeds.insert(9 + index, invalid);
    }

    seeds
}
