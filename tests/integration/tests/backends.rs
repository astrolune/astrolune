// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic seeded backend qualification on the pinned stable toolchain.
//!
//! The campaign replays the shared contract corpus and its mutations through
//! the reference interpreter and every qualified alternate engine profile,
//! asserting that acceptance, error variant, staged effects and charged
//! resources agree exactly. The profiles differ in value-stack allocation and
//! stack pooling only; none of them is an ahead-of-time, just-in-time or SIMD
//! backend, and no such backend exists.

#[path = "support/backends.rs"]
mod backends;
#[path = "support/contract_modules.rs"]
mod contract_modules;

use backends::Compared;

/// Same xorshift64 stream and fixed seed as the contract mutation campaign.
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;

    *state
}

fn campaign(rounds: usize) {
    backends::assert_disqualified_profiles_stay_excluded();

    let mut totals = Compared::default();
    let modules = contract_modules::modules();

    for bytes in &modules {
        backends::check(bytes, &mut totals);
    }
    assert_eq!(
        totals.accepted_modules,
        modules.len(),
        "every structured contract module must validate under the reference"
    );

    for bytes in contract_modules::regressions(&modules[0]) {
        backends::check(&bytes, &mut totals);
    }
    assert_eq!(
        totals.accepted_modules,
        modules.len(),
        "an instruction after a function's end must stay rejected by every profile"
    );

    let seeds = contract_modules::corpus();
    let mut random_state = 0x6173_7472_6f6c_756e;

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

        backends::check(&bytes, &mut totals);
    }

    println!(
        "{rounds} backend mutations; {} structured modules; {} candidates; \
         {} accepted modules; {} compared validations; {} compared executions \
         ({} accepted, {} rejected); {} compared seam executions; 0 disagreements",
        seeds.len(),
        totals.candidates,
        totals.accepted_modules,
        totals.validations,
        totals.executions,
        totals.accepted,
        totals.rejected,
        totals.seams
    );
    assert!(
        totals.accepted > 0,
        "mutations must also reach accepted execution paths on every profile"
    );
    assert!(
        totals.rejected > 0,
        "mutations must also reach rejected execution paths on every profile"
    );
    assert!(
        totals.seams > 0,
        "the RuntimeBackend seam must also be compared"
    );
}

#[test]
fn backend_qualification_smoke() {
    campaign(3000);
}

#[test]
#[ignore = "extended deterministic engine-configuration qualification; the compared profiles vary value-stack allocation only and are not AOT, JIT or SIMD backends"]
fn extended_backend_qualification() {
    campaign(100_000);
}

#[test]
#[ignore = "million-input deterministic engine-configuration qualification; the compared profiles vary value-stack allocation only and are not AOT, JIT or SIMD backends"]
fn million_backend_qualification() {
    campaign(1_000_000);
}
