// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Streaming sidecars let saved rotating state/receipt proofs be verified offline.

use crate::CliError;
use crate::proofs::Anchor;
use consensus::potb_transition::{PotbHandoff, PotbVerifier};
use consensus::rotation::{CommitteeHandoff, HandoffVerifier};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_STEPS: u64 = 10_000;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Wallet(value.to_string())
}

pub(super) struct Trust {
    pub(super) verifier: Authority,
    pending: Option<Pending>,
}
struct Pending {
    file: File,
    path: PathBuf,
    destination: PathBuf,
}
impl Drop for Pending {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
impl Trust {
    /// Publishes only after the caller authenticates its state/receipt proof.
    pub(super) fn publish(&self) -> Result<(), CliError> {
        if let Some(pending) = &self.pending {
            pending.file.sync_all().map_err(error)?;
            std::fs::hard_link(&pending.path, &pending.destination).map_err(error)?;
        }
        Ok(())
    }
}

pub(super) fn anchor(
    path: &Path,
    genesis: &Anchor,
    keys: &[[u8; 32]],
    height: u64,
    client: Option<&rpc::TcpRpcClient>,
) -> Result<Trust, CliError> {
    if height == 0 || height - 1 > MAX_STEPS {
        return Err(error(
            "handoff history exceeds the 10,000-transition CLI bound",
        ));
    }
    let mut verifier = match genesis {
        Anchor::Genesis(value) => {
            Authority::Rotation(HandoffVerifier::new(value, keys).map_err(error)?)
        }
        Anchor::Potb(value) => Authority::Potb(PotbVerifier::new(value, keys).map_err(error)?),
    };
    let mut suffix = path.as_os_str().to_owned();
    suffix.push(".handoffs");
    let destination = PathBuf::from(suffix);
    let mut header = if matches!(genesis, Anchor::Potb(_)) {
        b"ALPTHIS1"
    } else {
        b"ALHIST01"
    }
    .to_vec();
    header.extend_from_slice(&height.to_le_bytes());
    header.extend_from_slice(genesis.commitment().map_err(error)?.as_bytes());
    let pending = if let Some(client) = client {
        if destination.exists() {
            return Err(error("handoff sidecar already exists"));
        }
        let mut temporary = destination.as_os_str().to_owned();
        temporary.push(format!(".pending-{}", std::process::id()));
        let temporary = PathBuf::from(temporary);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(error)?;
        let mut pending = Pending {
            file,
            path: temporary,
            destination,
        };
        pending.file.write_all(&header).map_err(error)?;
        let mut write = |bytes: Vec<u8>| {
            pending.file.write_all(
                &u32::try_from(bytes.len())
                    .map_err(|_| rpc::ClientError::LimitExceeded)?
                    .to_le_bytes(),
            )?;
            pending.file.write_all(&bytes)?;
            Ok(())
        };
        match &mut verifier {
            Authority::Rotation(trusted) => client.advance_handoffs_with(
                trusted,
                height,
                MAX_STEPS,
                Duration::from_secs(60),
                |handoff| {
                    write(
                        handoff
                            .to_bytes()
                            .map_err(|_| rpc::ClientError::Protocol("invalid handoff"))?,
                    )
                },
            ),
            Authority::Potb(trusted) => client.advance_potb_handoffs_with(
                trusted,
                height,
                MAX_STEPS,
                Duration::from_secs(60),
                |handoff| {
                    write(
                        handoff
                            .to_bytes()
                            .map_err(|_| rpc::ClientError::Protocol("invalid PoTB handoff"))?,
                    )
                },
            ),
        }
        .map_err(error)?;
        Some(pending)
    } else {
        read_history(&destination, &header, height, &mut verifier)?;
        None
    };
    Ok(Trust { verifier, pending })
}

pub(super) enum Authority {
    Rotation(HandoffVerifier),
    Potb(PotbVerifier),
}
impl Authority {
    pub(super) fn current(&self) -> &consensus::rotation::CommitteeState {
        match self {
            Self::Rotation(value) => value.current(),
            Self::Potb(value) => value.current().committee(),
        }
    }
    pub(super) fn parent(&self) -> types::Hash256 {
        match self {
            Self::Rotation(value) => value.parent(),
            Self::Potb(value) => value.parent(),
        }
    }
    pub(super) fn verify_state<'a>(
        &self,
        proof: &'a rpc::CertifiedStateProof,
        key: &types::StateKey,
        minimum: u64,
    ) -> Result<Option<&'a [u8]>, rpc::RpcError> {
        match self {
            Self::Rotation(value) => proof.verify_with_handoffs(value, key, minimum),
            Self::Potb(value) => proof.verify_with_potb(value, key, minimum),
        }
    }
    pub(super) fn verify_receipt<'a>(
        &self,
        proof: &'a rpc::CertifiedReceiptProof,
        id: types::Hash256,
        minimum: u64,
    ) -> Result<&'a types::ExecutionReceipt, rpc::RpcError> {
        match self {
            Self::Rotation(value) => proof.verify_with_handoffs(value, id, minimum),
            Self::Potb(value) => proof.verify_with_potb(value, id, minimum),
        }
    }
}

fn read_history(
    destination: &Path,
    header: &[u8],
    height: u64,
    verifier: &mut Authority,
) -> Result<(), CliError> {
    let mut file = File::open(destination).map_err(error)?;
    let mut encoded_header = [0; 48];
    file.read_exact(&mut encoded_header).map_err(error)?;
    if encoded_header.as_slice() != header {
        return Err(error("handoff sidecar anchor mismatch"));
    }
    for _ in 1..height {
        let mut length = [0; 4];
        file.read_exact(&mut length).map_err(error)?;
        let length = u32::from_le_bytes(length) as usize;
        if length
            > match verifier {
                Authority::Rotation(_) => CommitteeHandoff::MAX_BYTES,
                Authority::Potb(_) => PotbHandoff::MAX_BYTES,
            }
        {
            return Err(error("handoff frame exceeds limit"));
        }
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).map_err(error)?;
        match &mut *verifier {
            Authority::Rotation(trusted) => {
                trusted.apply(&CommitteeHandoff::from_bytes(&bytes).map_err(error)?)
            }
            Authority::Potb(trusted) => {
                trusted.apply(&PotbHandoff::from_bytes(&bytes).map_err(error)?)
            }
        }
        .map_err(error)?;
    }
    if file.read(&mut [0]).map_err(error)? != 0 {
        return Err(error("trailing handoff data"));
    }
    Ok(())
}
