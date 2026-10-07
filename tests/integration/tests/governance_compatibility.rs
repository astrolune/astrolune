// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Frozen policy envelopes and independently anchored authority replay.

#[path = "support/governance_compatibility.rs"]
mod compatibility;

use consensus::potb_transition::{PotbConfiguration, PotbHandoff, PotbState, PotbVerifier};
use std::{collections::BTreeSet, path::PathBuf};

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/governance-v1")
}

#[test]
fn frozen_governance_bytes_and_complete_manifest_are_preserved() {
    let expected = compatibility::build();
    let manifest = std::fs::read_to_string(directory().join("MANIFEST.blake2s")).unwrap();

    let mut seen = BTreeSet::new();

    for line in manifest.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [hash, size, name] = fields.as_slice() else {
            panic!("invalid manifest");
        };
        assert!(seen.insert(*name));

        let bytes = std::fs::read(directory().join(name)).unwrap();
        assert_eq!(bytes.len(), size.parse::<usize>().unwrap());
        assert_eq!(crypto::blake2s_hash(&bytes).to_string(), *hash);
        assert_eq!(
            &bytes,
            expected.get(*name).unwrap(),
            "profile compatibility changed: {name}"
        );
    }

    assert_eq!(seen.len(), expected.len());
    assert_eq!(seen.len(), 18);

    let actual: BTreeSet<_> = std::fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
        })
        .collect();
    assert_eq!(actual, seen.into_iter().map(str::to_owned).collect());
}

#[test]
fn frozen_handoffs_authenticate_governance_and_reject_old_profile_authority() {
    let read = |name: &str| std::fs::read(directory().join(name)).unwrap();

    let config = PotbConfiguration::from_bytes(&read("configuration.bin")).unwrap();
    let keys: Vec<_> = (1..=4)
        .map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]))
        .collect();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    assert_eq!(
        trusted.current().to_bytes().unwrap(),
        read("initial-state.bin")
    );

    for height in 1..=3 {
        let handoff =
            PotbHandoff::from_bytes(&read(&format!("height-{height}-handoff.bin"))).unwrap();
        assert_eq!(
            handoff.batch.to_bytes().unwrap(),
            read(&format!("height-{height}-batch.bin"))
        );

        trusted.apply(&handoff).unwrap();

        let state_bytes = read(&format!("height-{height}-state.bin"));
        assert_eq!(trusted.current().to_bytes().unwrap(), state_bytes);
        assert_eq!(
            PotbState::from_bytes(&state_bytes).unwrap(),
            *trusted.current()
        );
    }

    let first = PotbHandoff::from_bytes(&read("height-1-handoff.bin")).unwrap();

    let legacy = consensus::rotation::HandoffVerifier::new(config.genesis(), &keys).unwrap();
    assert!(
        legacy
            .verify_header(&first.header, &first.certificate)
            .is_err()
    );

    let mut policy = config.policy();
    policy.epoch_blocks += 1;
    let other = PotbConfiguration::new(config.genesis().clone(), policy).unwrap();
    assert!(
        PotbVerifier::new(&other, &keys)
            .unwrap()
            .apply(&first)
            .is_err()
    );
}
