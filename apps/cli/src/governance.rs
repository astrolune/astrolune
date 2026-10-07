// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit offline parameter approvals with authenticated committee sidecars.

use crate::{
    CliError,
    contracts::read_bounded,
    handoffs::{Authority, Trust},
    wallet,
};
use consensus::governance::{
    GovernanceApproval, GovernanceCertificate, GovernanceIntent, GovernancePolicy,
    NetworkParameters,
};
use consensus::potb_transition::PotbConfiguration;
use std::{ffi::OsString, path::Path};
use types::Resources;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

pub(super) fn resources(value: &OsString) -> Result<Resources, CliError> {
    let values = wallet::text(value)?
        .split(',')
        .map(|part| wallet::integer(&OsString::from(part)))
        .collect::<Result<Vec<_>, _>>()?;
    let [compute, memory, io, bandwidth] = values.as_slice() else {
        return Err(error("expected compute,memory,io,bandwidth"));
    };
    Ok(Resources {
        compute: *compute,
        memory: *memory,
        io: *io,
        bandwidth: *bandwidth,
    })
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    match (command, args) {
        ("governance-config", [profile, epoch, floor, ceiling, prices, output]) => {
            let profile = PotbConfiguration::from_bytes(&read_bounded(
                Path::new(profile),
                PotbConfiguration::MAX_BYTES,
            )?)
            .map_err(error)?;
            let profile = profile
                .with_governance(GovernancePolicy {
                    epoch_blocks: wallet::integer(epoch)?,
                    minimum_capacity: resources(floor)?,
                    maximum_capacity: resources(ceiling)?,
                    maximum_prices: resources(prices)?,
                })
                .map_err(error)?;
            wallet::write_new(Path::new(output), &profile.to_bytes())?;
            println!("configuration: {}", profile.commitment());
        }
        ("governance-request", _) => request(args)?,
        ("governance-inspect", [profile, keys, path]) => {
            let (request, _) = load(profile, keys, path)?;
            print(&request);
        }
        ("governance-approve", [profile, keys, path, seed, journal, output]) => {
            if Path::new(output).exists() {
                return Err(error("output already exists"));
            }
            let (request, trust) = load(profile, keys, path)?;
            let Authority::Potb(trusted) = &trust.verifier else {
                unreachable!()
            };
            let signer = keystore::DurableSigner::open(
                Path::new(journal),
                keystore::SigningContext {
                    chain_id: request.chain_id,
                    genesis: request.genesis,
                },
                *wallet::read_raw_seed(Path::new(seed))?,
            )
            .map_err(error)?;
            let approval = GovernanceApproval::sign(
                &request,
                trusted.current().committee(),
                trusted.parent(),
                trusted
                    .current()
                    .governance()
                    .ok_or_else(|| error("governance disabled"))?,
                &signer,
            )
            .map_err(error)?;
            wallet::write_new(Path::new(output), &approval.to_bytes())?;
            print(&request);
            println!("approver: {}", approval.voter());
        }
        ("governance-assemble", [profile, keys, path, output, approvals @ ..])
            if (1..=32).contains(&approvals.len()) =>
        {
            let (request, trust) = load(profile, keys, path)?;
            let Authority::Potb(trusted) = &trust.verifier else {
                unreachable!()
            };
            let approvals = approvals
                .iter()
                .map(|path| {
                    GovernanceApproval::from_bytes(&read_bounded(
                        Path::new(path),
                        GovernanceApproval::BYTES,
                    )?)
                    .map_err(error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let certificate = GovernanceCertificate::assemble(
                request,
                approvals,
                trusted.current().committee(),
                trusted.parent(),
                trusted
                    .current()
                    .governance()
                    .ok_or_else(|| error("governance disabled"))?,
            )
            .map_err(error)?;
            wallet::write_new(Path::new(output), &certificate.to_bytes().map_err(error)?)?;
            print(certificate.request());
        }
        ("governance-verify" | "governance-submit", _) => verify(command, args)?,
        _ => return Err(error("invalid governance arguments; run cli help")),
    }
    Ok(())
}

fn load(
    profile: &OsString,
    keys: &OsString,
    path: &OsString,
) -> Result<(GovernanceIntent, Trust), CliError> {
    let (profile, keys) = crate::proofs::anchors(Path::new(profile), Path::new(keys))?;
    let request =
        GovernanceIntent::from_bytes(&read_bounded(Path::new(path), GovernanceIntent::BYTES)?)
            .map_err(error)?;
    let trust = crate::handoffs::anchor(Path::new(path), &profile, &keys, request.height, None)?;
    let Authority::Potb(trusted) = &trust.verifier else {
        return Err(error("governance requires an explicit PoTB configuration"));
    };
    let policy = trusted
        .current()
        .governance()
        .ok_or_else(|| error("governance disabled"))?;
    let expected = policy
        .request(
            trusted.current().committee(),
            trusted.parent(),
            NetworkParameters {
                capacity: request.capacity,
                prices: request.prices,
            },
        )
        .map_err(error)?;
    if request != expected {
        return Err(error("request context differs from authenticated history"));
    }
    Ok((request, trust))
}

fn request(args: &[OsString]) -> Result<(), CliError> {
    if !(6..=7).contains(&args.len()) {
        return Err(error("invalid governance request arguments"));
    }
    let output = Path::new(&args[5]);
    if output.exists() {
        return Err(error("output already exists"));
    }
    let (profile, keys) = crate::proofs::anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let client = wallet::client(args.get(6))?;
    let trust = crate::handoffs::anchor(
        output,
        &profile,
        &keys,
        wallet::integer(&args[2])?,
        Some(&client),
    )?;
    let Authority::Potb(trusted) = &trust.verifier else {
        return Err(error("governance requires an explicit PoTB configuration"));
    };
    let request = trusted
        .current()
        .governance()
        .ok_or_else(|| error("governance disabled"))?
        .request(
            trusted.current().committee(),
            trusted.parent(),
            NetworkParameters {
                capacity: resources(&args[3])?,
                prices: resources(&args[4])?,
            },
        )
        .map_err(error)?;
    trust.publish()?;
    wallet::write_new(output, &request.to_bytes())?;
    print(&request);
    Ok(())
}

fn verify(command: &str, args: &[OsString]) -> Result<(), CliError> {
    if args.len() != 4 && !(command == "governance-submit" && args.len() == 5) {
        return Err(error("invalid governance verification arguments"));
    }
    let (request, trust) = load(&args[0], &args[1], &args[2])?;
    let certificate = GovernanceCertificate::from_bytes(&read_bounded(
        Path::new(&args[3]),
        GovernanceCertificate::MAX_BYTES,
    )?)
    .map_err(error)?;
    let Authority::Potb(trusted) = &trust.verifier else {
        unreachable!()
    };
    if certificate.request() != &request {
        return Err(error("certificate does not authorize this request"));
    }
    certificate
        .verify(
            trusted.current().committee(),
            trusted.parent(),
            trusted
                .current()
                .governance()
                .ok_or_else(|| error("governance disabled"))?,
        )
        .map_err(error)?;
    print(&request);
    println!("authorization: valid incumbent weighted quorum");
    if command == "governance-submit" {
        let id = wallet::client(args.get(4))?
            .submit_governance(&certificate)
            .map_err(error)?;
        println!("pending_request: {id}");
    }
    Ok(())
}

fn print(request: &GovernanceIntent) {
    println!("request: {}", request.id());
    println!("genesis: {}", request.genesis);
    println!("inclusion_height: {}", request.height);
    println!("activation_height: {}", request.activate_at);
    println!("capacity: {:?}", request.capacity);
    println!("prices: {:?}", request.prices);
}
