// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit configuration and bounded historical evidence inclusion tooling.

use crate::{
    CliError,
    contracts::read_bounded,
    proofs::{Anchor, anchors},
    wallet,
};
use codec::CanonicalDecode;
use consensus::{
    DoubleVoteEvidence,
    history::HistoricalEvidence,
    potb::PotbPolicy,
    potb_transition::{PotbConfiguration, PotbVerifier},
};
use std::{ffi::OsString, path::Path, time::Duration};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    if command == "potb-config" {
        return configuration(args);
    }
    let expected = if command == "potb-evidence" { 5 } else { 3 };
    if !(expected..=expected + 1).contains(&args.len()) {
        return Err(error("invalid PoTB arguments; run cli help"));
    }
    let (Anchor::Potb(profile), keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))? else {
        return Err(error("explicit PoTB configuration required"));
    };
    let client = wallet::client(args.get(expected))?;
    let mut trusted = PotbVerifier::new(&profile, &keys).map_err(error)?;
    if command == "potb-submit-evidence" {
        return submit_evidence(Path::new(&args[2]), &client, &mut trusted);
    }
    let output = Path::new(&args[4]);
    if output.exists() {
        return Err(error("output already exists"));
    }
    let evidence = DoubleVoteEvidence::decode(&read_bounded(
        Path::new(&args[2]),
        DoubleVoteEvidence::ENCODED_LEN,
    )?)
    .map_err(error)?;
    let height = wallet::integer(&args[3])?;
    if height <= evidence.height() || height > 10_001 {
        return Err(error(
            "inclusion must follow the offence within the 10,000-transition CLI bound",
        ));
    }
    let mut roots = Vec::new();
    client
        .advance_potb_handoffs_with(
            &mut trusted,
            evidence.height(),
            10_000,
            Duration::from_secs(60),
            |handoff| {
                roots.push(handoff.header.committee_root);
                Ok(())
            },
        )
        .map_err(error)?;
    let past = trusted.current().committee().clone();
    evidence
        .verify(&past.context().map_err(error)?)
        .map_err(error)?;
    client
        .advance_potb_handoffs_with(
            &mut trusted,
            height,
            10_000,
            Duration::from_secs(60),
            |handoff| {
                roots.push(handoff.header.committee_root);
                Ok(())
            },
        )
        .map_err(error)?;
    let history = trusted.current().history();
    let proof = history
        .prove(evidence.height(), 10_000, |height| {
            roots
                .get(
                    usize::try_from(height - 1)
                        .map_err(|_| consensus::ConsensusError::InvalidProof)?,
                )
                .copied()
                .ok_or(consensus::ConsensusError::InvalidProof)
        })
        .map_err(error)?;
    let committee = past.committee();
    let keys: Vec<_> = past
        .roster()
        .iter()
        .filter(|v| {
            committee.members.iter().any(|member| {
                member.id == types::ValidatorId(crypto::blake2s_hash(&v.public_key).0)
            })
        })
        .map(|v| v.public_key)
        .collect();
    let bundle =
        HistoricalEvidence::new(history, &committee, &keys, proof, evidence).map_err(error)?;
    wallet::write_new(output, &bundle.to_bytes().map_err(error)?)?;
    println!("offence: {}", bundle.evidence().offence_id());
    println!("inclusion_height: {height}");
    Ok(())
}

fn configuration(args: &[OsString]) -> Result<(), CliError> {
    let [genesis, epoch, initial, increment, maximum, output] = args else {
        return Err(error("invalid PoTB configuration arguments; run cli help"));
    };
    let genesis = genesis::Genesis::decode(&read_bounded(
        Path::new(genesis),
        genesis::MAX_GENESIS_BYTES,
    )?)
    .map_err(error)?;
    let weight = |value: &OsString| -> Result<u128, CliError> {
        let text = wallet::text(value)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(error("weight must be an unsigned integer"));
        }
        text.parse().map_err(error)
    };
    let profile = PotbConfiguration::new(
        genesis,
        PotbPolicy {
            epoch_blocks: wallet::integer(epoch)?,
            initial_weight: weight(initial)?,
            age_increment: weight(increment)?,
            maximum_weight: weight(maximum)?,
        },
    )
    .map_err(error)?;
    wallet::write_new(Path::new(output), &profile.to_bytes())?;
    println!("potb_configuration: {}", profile.commitment());
    Ok(())
}

fn submit_evidence(
    path: &Path,
    client: &rpc::TcpRpcClient,
    trusted: &mut PotbVerifier,
) -> Result<(), CliError> {
    let evidence =
        HistoricalEvidence::from_bytes(&read_bounded(path, HistoricalEvidence::MAX_BYTES)?)
            .map_err(error)?;
    let height = client
        .chain_status()
        .map_err(error)?
        .finalized_height
        .checked_add(1)
        .ok_or_else(|| error("height exhausted"))?;
    client
        .advance_potb_handoffs(trusted, height, 10_000, Duration::from_secs(60))
        .map_err(error)?;
    evidence
        .verify(trusted.current().history())
        .map_err(error)?;
    let id = client.submit_potb_evidence(&evidence).map_err(error)?;
    println!("pending_offence: {id}");
    Ok(())
}
