// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticate receipt queries, save proofs and wait without transaction resubmission.

use crate::{CliError, contracts::read_bounded, proofs::anchors, wallet};
use rpc::CertifiedReceiptProof;
use std::{ffi::OsString, path::Path, time::Duration};
use types::Hash256;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Wallet(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let maximum = match command {
        "verify-receipt" => 5,
        "wait-finality" => 6,
        _ => 7,
    };
    if args.len() < 5 || args.len() > maximum {
        return Err(error("invalid receipt arguments; run cli help"));
    }
    let (genesis, keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let id = Hash256(rpc::client::decode_hex(wallet::text(&args[2])?).map_err(error)?);
    let parameter = wallet::integer(&args[3])?;
    let output = Path::new(&args[4]);
    if command != "verify-receipt" && output.exists() {
        return Err(error("output already exists"));
    }
    let proof = match command {
        "verify-receipt" => CertifiedReceiptProof::from_bytes(&read_bounded(output, CertifiedReceiptProof::MAX_BYTES)?).map_err(error)?,
        "wait-finality" => wallet::client(args.get(5))?.wait_receipt(id, Duration::from_secs(parameter)).map_err(error)?
            .ok_or_else(|| error("finality wait timed out; this does not prove rejection; transaction was not resubmitted"))?,
        _ => {
            let height = args.get(6).map(|value| wallet::integer(value)).transpose()?;
            wallet::client(args.get(5))?.receipt(id, height).map_err(error)?
                .ok_or_else(|| error("receipt unavailable; transaction may be pending, absent, outside the recent index or stored without receipt metadata"))?
        }
    };
    let minimum = if command == "wait-finality" {
        1
    } else {
        parameter
    };
    if proof.0.header.height < minimum {
        return Err(error("receipt proof precedes minimum height"));
    }
    let client = (command != "verify-receipt")
        .then(|| wallet::client(args.get(5)))
        .transpose()?;
    let handoffs = if genesis.version == genesis::ROTATING_GENESIS_VERSION {
        Some(crate::handoffs::anchor(
            output,
            &genesis,
            &keys,
            proof.0.header.height,
            client.as_ref(),
        )?)
    } else {
        None
    };
    let receipt = match &handoffs {
        Some(trust) => trust.verifier.verify_receipt(&proof, id, minimum),
        None => proof.verify(&genesis, &keys, id, minimum),
    }
    .map_err(|_| error("receipt proof failed independent authentication"))?;
    if command != "verify-receipt" {
        if let Some(trust) = &handoffs {
            trust.publish()?;
        }
        wallet::write_new(output, &proof.to_bytes().map_err(error)?)?;
    }
    println!("transaction_id: {id}");
    println!("finalized_height: {}", proof.0.header.height);
    println!("finalized_block: {}", proof.0.header.compute_hash());
    println!("succeeded: {}", receipt.succeeded);
    println!("resources: {:?}", receipt.resources);
    println!("output_root: {}", receipt.output_root);
    Ok(())
}
