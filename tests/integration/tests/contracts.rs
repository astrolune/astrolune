// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic seeded contract mutation coverage on the pinned stable toolchain.

#[path = "support/contract_modules.rs"]
mod contract_modules;
#[path = "support/contracts.rs"]
mod contracts;

/// Same xorshift64 stream and fixed seed as the extension mutation campaign.
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;

    *state
}

fn campaign(rounds: usize) {
    let modules = contract_modules::modules();

    for bytes in &modules {
        assert!(
            contracts::check(bytes) > 0,
            "every structured contract module must validate"
        );
    }

    for bytes in contract_modules::regressions(&modules[0]) {
        assert_eq!(
            contracts::check(&bytes),
            0,
            "an instruction after a function's end must stay rejected"
        );
    }

    let seeds = contract_modules::corpus();
    let mut random_state = 0x6173_7472_6f6c_756e;
    let mut accepted = 0;

    for index in 0..rounds {
        let mut bytes = seeds[index % seeds.len()].clone();
        let at = usize::try_from(random(&mut random_state) % bytes.len() as u64).unwrap();

        match index % 5 {
            0 => bytes[at] ^= u8::try_from(random(&mut random_state) & 255).unwrap(),
            1 => bytes.truncate(at),
            2 => bytes.insert(at, u8::try_from(random(&mut random_state) & 255).unwrap()),
            3 => {
                bytes.remove(at);
            }
            _ => {
                let end = (at + 8).min(bytes.len());
                bytes[at..end].fill(255);
            }
        }

        accepted += contracts::check(&bytes);
    }

    println!(
        "{rounds} contract mutations; {} structured modules; {accepted} accepted contract paths",
        seeds.len()
    );
    assert!(
        accepted > 0,
        "mutations must also reach accepted validation and execution paths"
    );
}

#[test]
fn contract_mutation_smoke() {
    campaign(3000);
}

#[test]
#[ignore = "extended deterministic contract mutation campaign; no coverage-guided fuzzing claim"]
fn extended_contract_mutations() {
    campaign(100_000);
}

#[test]
#[ignore = "million-input deterministic contract campaign; no coverage-guided fuzzing claim"]
fn million_contract_mutations() {
    campaign(1_000_000);
}
