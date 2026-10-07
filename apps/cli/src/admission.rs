// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline incumbent-quorum authorizations. Existing profiles do not activate them.

use consensus::admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest};
use keystore::{DurableSigner, SigningContext};
use std::{ffi::OsString, fs::File, io::Read, path::Path};

use crate::{
    CliError,
    handoffs::Trust,
    wallet::{integer, read_raw_seed, read_seed, write_new},
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
        return Err(error("admission input exceeds size limit"));
    }
    Ok(bytes)
}

fn load(genesis: &Path, keys: &Path, path: &Path) -> Result<(AdmissionRequest, Trust), CliError> {
    let (genesis, keys) = crate::proofs::anchors(genesis, keys)?;
    if genesis.version != genesis::ROTATING_GENESIS_VERSION {
        return Err(error(
            "admission qualification requires an authenticated rotating profile",
        ));
    }
    let request =
        AdmissionRequest::from_bytes(&read(path, AdmissionRequest::BYTES)?).map_err(error)?;
    let trust = crate::handoffs::anchor(path, &genesis, &keys, request.intent().height, None)?;
    request
        .verify(trust.verifier.current(), trust.verifier.parent())
        .map_err(error)?;
    Ok((request, trust))
}

fn print_request(request: &AdmissionRequest) {
    println!("request: {}", request.id());
    println!("candidate: {}", request.candidate());
    println!("genesis: {}", request.intent().genesis);
    println!("inclusion_height: {}", request.intent().height);
    println!("finalized_parent: {}", request.intent().parent);
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    match (command, args) {
        ("admission-request", [genesis, keys, seed, height, output, ..])
            if (5..=6).contains(&args.len()) =>
        {
            create_request(genesis, keys, seed, height, output, args.get(5))?;
        }
        ("admission-inspect", [genesis, keys, path]) => {
            let (request, _) = load(Path::new(genesis), Path::new(keys), Path::new(path))?;
            print_request(&request);
            println!("candidate_consent: valid");
        }
        ("admission-approve", [genesis, keys, path, seed, journal, output]) => {
            if Path::new(output).exists() {
                return Err(error("output already exists"));
            }
            let (request, trust) = load(Path::new(genesis), Path::new(keys), Path::new(path))?;
            let seed = read_raw_seed(Path::new(seed))?;
            let signer = DurableSigner::open(
                Path::new(journal),
                SigningContext {
                    chain_id: request.intent().chain_id,
                    genesis: request.intent().genesis,
                },
                *seed,
            )
            .map_err(error)?;
            let approval = AdmissionApproval::sign(
                &request,
                trust.verifier.current(),
                trust.verifier.parent(),
                &signer,
            )
            .map_err(error)?;
            write_new(Path::new(output), &approval.to_bytes())?;
            print_request(&request);
            println!("approver: {}", approval.voter());
        }
        ("admission-assemble", [genesis, keys, path, output, approvals @ ..])
            if (1..=32).contains(&approvals.len()) =>
        {
            if Path::new(output).exists() {
                return Err(error("output already exists"));
            }
            let (request, trust) = load(Path::new(genesis), Path::new(keys), Path::new(path))?;
            let approvals = approvals
                .iter()
                .map(|path| {
                    AdmissionApproval::from_bytes(&read(Path::new(path), AdmissionApproval::BYTES)?)
                        .map_err(error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let certificate = AdmissionCertificate::assemble(
                request,
                approvals,
                trust.verifier.current(),
                trust.verifier.parent(),
            )
            .map_err(error)?;
            write_new(Path::new(output), &certificate.to_bytes().map_err(error)?)?;
            print_request(certificate.request());
            println!("authorization: valid incumbent weighted quorum");
        }
        ("admission-verify" | "admission-submit", [genesis, keys, path, certificate, ..])
            if args.len() == 4 || command == "admission-submit" && args.len() == 5 =>
        {
            let (request, trust) = load(Path::new(genesis), Path::new(keys), Path::new(path))?;
            let certificate = AdmissionCertificate::from_bytes(&read(
                Path::new(certificate),
                AdmissionCertificate::MAX_BYTES,
            )?)
            .map_err(error)?;
            if certificate.request() != &request {
                return Err(error("certificate does not authorize the supplied request"));
            }
            certificate
                .verify(trust.verifier.current(), trust.verifier.parent())
                .map_err(error)?;
            print_request(&request);
            println!("authorization: valid incumbent weighted quorum");
            if command == "admission-submit" {
                if !matches!(trust.verifier, crate::handoffs::Authority::Potb(_)) {
                    return Err(error("submission requires the explicit PoTB profile"));
                }
                let id = crate::wallet::client(args.get(4))?
                    .submit_potb_admission(&certificate)
                    .map_err(error)?;
                println!("pending_request: {id}");
            }
        }
        _ => return Err(error("invalid admission arguments; run cli help")),
    }
    println!(
        "activation: not included; membership changes only after inclusion in a finalized PoTB block"
    );
    Ok(())
}

fn create_request(
    genesis: &OsString,
    keys: &OsString,
    seed: &OsString,
    height: &OsString,
    output: &OsString,
    address: Option<&OsString>,
) -> Result<(), CliError> {
    if Path::new(output).exists() {
        return Err(error("output already exists"));
    }
    let (genesis, keys) = crate::proofs::anchors(Path::new(genesis), Path::new(keys))?;
    if genesis.version != genesis::ROTATING_GENESIS_VERSION {
        return Err(error(
            "admission qualification requires an authenticated rotating profile",
        ));
    }
    let client = crate::wallet::client(address)?;
    let trust = crate::handoffs::anchor(
        Path::new(output),
        &genesis,
        &keys,
        integer(height)?,
        Some(&client),
    )?;
    let seed = read_seed(Path::new(seed))?;
    let request = AdmissionRequest::sign(trust.verifier.current(), trust.verifier.parent(), &seed)
        .map_err(error)?;
    // Validate everything before publishing either non-overwritable file.
    let encoded = request.to_bytes().map_err(error)?;
    trust.publish()?;
    write_new(Path::new(output), &encoded)?;
    print_request(&request);
    println!("candidate_consent: valid");
    Ok(())
}
