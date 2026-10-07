// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independent evidence verification against genesis and authenticated committee history.

use crate::CliError;
use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, DoubleVoteEvidence, PotbWeight, Vote,
};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > maximum {
        return Err(error("input exceeds its size limit"));
    }
    Ok(bytes)
}
fn context(
    genesis_path: &Path,
    keys_path: &Path,
    height: u64,
    proof_path: &Path,
    client: Option<&rpc::TcpRpcClient>,
) -> Result<(AuthenticatedCommittee, Option<crate::handoffs::Trust>), CliError> {
    let (genesis, keys) = crate::proofs::anchors(genesis_path, keys_path)?;
    if genesis.version == genesis::ROTATING_GENESIS_VERSION {
        let trusted = crate::handoffs::anchor(proof_path, &genesis, &keys, height, client)?;
        return Ok((
            trusted.verifier.current().context().map_err(error)?,
            Some(trusted),
        ));
    }
    if genesis.committee_size != genesis.validators.len() {
        return Err(error(
            "version-1 evidence requires the complete genesis committee",
        ));
    }
    let committee = Committee {
        height,
        members: genesis
            .validators
            .iter()
            .map(|member| CommitteeMember {
                id: member.id,
                power: PotbWeight(member.weight),
            })
            .collect(),
    };
    Ok((
        AuthenticatedCommittee::new(genesis.chain_id, &committee, &keys).map_err(error)?,
        None,
    ))
}

pub(super) fn run(command: &str) -> Result<(), CliError> {
    let args: Vec<OsString> = std::env::args_os().skip(2).collect();
    let proof = match (command, args.as_slice()) {
        ("evidence-create", [genesis, keys, a, b, output, ..]) if (5..=6).contains(&args.len()) => {
            if Path::new(output).exists() {
                return Err(error("output already exists"));
            }
            let a = Vote::decode(&read(Path::new(a), 186)?).map_err(error)?;
            let b = Vote::decode(&read(Path::new(b), 186)?).map_err(error)?;
            let client = crate::wallet::client(args.get(5))?;
            let (context, handoffs) = context(
                Path::new(genesis),
                Path::new(keys),
                a.height,
                Path::new(output),
                Some(&client),
            )?;
            let proof = DoubleVoteEvidence::from_votes(&context, a, b).map_err(error)?;
            if let Some(trusted) = &handoffs {
                trusted.publish()?;
            }
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output)
                .map_err(error)?;
            file.write_all(&proof.encode())
                .and_then(|()| file.sync_all())
                .map_err(error)?;
            proof
        }
        ("evidence-verify", [genesis, keys, path]) => {
            let proof = DoubleVoteEvidence::decode(&read(
                Path::new(path),
                DoubleVoteEvidence::ENCODED_LEN,
            )?)
            .map_err(error)?;
            proof
                .verify(
                    &context(
                        Path::new(genesis),
                        Path::new(keys),
                        proof.height(),
                        Path::new(path),
                        None,
                    )?
                    .0,
                )
                .map_err(error)?;
            proof
        }
        _ => return Err(error("invalid evidence command arguments; run cli help")),
    };
    println!("evidence_id: {}", proof.id());
    println!("offence_id: {}", proof.offence_id());
    println!("validator: {}", proof.voter());
    println!("height: {}", proof.height());
    println!("round: {}", proof.votes().0.round);
    println!("phase: {:?}", proof.votes().0.phase);
    println!("verification: valid double vote (no automatic on-chain penalty)");
    Ok(())
}
