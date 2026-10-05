// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic public parameter-governance history, before and after activation.

#[path = "../../../../crates/consensus/tests/support/potb.rs"]
pub mod fixture;
use consensus::potb_transition::PotbVerifier;
use std::collections::BTreeMap;

pub fn build() -> BTreeMap<String, Vec<u8>> {
    let (base, keys) = fixture::fixture();
    let config = fixture::governed(base);
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let certificate = fixture::parameters(trusted.current(), trusted.parent());
    let approval = fixture::parameter_approvals(
        certificate.request(),
        trusted.current().committee().context().unwrap().members(),
    )
    .remove(0);
    let mut result = BTreeMap::from([
        ("configuration.bin".into(), config.to_bytes()),
        (
            "initial-state.bin".into(),
            trusted.current().to_bytes().unwrap(),
        ),
        ("request.bin".into(), certificate.request().to_bytes()),
        ("approval.bin".into(), approval.to_bytes()),
        ("certificate.bin".into(), certificate.to_bytes().unwrap()),
        (
            "network.bin".into(),
            node::network_wire::encode_exchange(
                config.commitment(),
                &[node::network_wire::NetworkMessage::Governance(
                    certificate.clone(),
                )],
            )
            .unwrap(),
        ),
    ]);
    for height in 1..=3 {
        let mut batch = fixture::batch(trusted.current());
        if height == 1 {
            batch = batch.with_governance(certificate.clone()).unwrap();
        }
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
        result.insert(
            format!("height-{height}-parameters.bin"),
            trusted.current().governance().unwrap().to_bytes(),
        );
    }
    result
}
