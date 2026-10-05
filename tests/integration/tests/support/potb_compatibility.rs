// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Public deterministic vectors for the explicitly separate policy profile.

#[path = "../../../../crates/consensus/tests/support/potb.rs"]
mod fixture;

use consensus::potb_transition::{PotbBatch, PotbVerifier};
use std::collections::BTreeMap;

pub fn build() -> BTreeMap<String, Vec<u8>> {
    let (config, keys) = fixture::fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();

    let first = trusted.current().committee().clone();
    let roots = vec![first.context().unwrap().root()];

    let mut result = BTreeMap::from([
        ("configuration.bin".into(), config.to_bytes()),
        (
            "initial-state.bin".into(),
            trusted.current().to_bytes().unwrap(),
        ),
    ]);

    for height in 1..=2 {
        let batch = if height == 1 {
            fixture::batch(trusted.current())
        } else {
            PotbBatch::new(
                fixture::contributions(trusted.current()),
                vec![fixture::evidence(trusted.current(), &first, &roots, 1)],
                vec![fixture::admission(trusted.current(), trusted.parent(), 99)],
            )
            .unwrap()
        };

        let handoff = fixture::handoff(&trusted, batch);
        trusted.apply(&handoff).unwrap();

        result.insert(
            format!("height-{height}-batch.bin"),
            handoff.batch.to_bytes().unwrap(),
        );
        result.insert(
            format!("height-{height}-handoff.bin"),
            handoff.to_bytes().unwrap(),
        );
        result.insert(
            format!("height-{height}-state.bin"),
            trusted.current().to_bytes().unwrap(),
        );
    }

    result
}