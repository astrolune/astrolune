// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded local evidence outbox. Proofs do not change consensus or account state.

use crate::network::{NetworkNodeError, StaticNetwork, local};
use consensus::DoubleVoteEvidence;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use types::ValidatorId;

pub(crate) struct EvidenceStore {
    directory: PathBuf,
    proofs: BTreeMap<ValidatorId, DoubleVoteEvidence>,
}

impl EvidenceStore {
    pub(crate) fn open(
        directory: &Path,
        network: &StaticNetwork,
        storage: &storage::ChainStorage,
        identities: &[ValidatorId],
    ) -> Result<Self, NetworkNodeError> {
        let directory = directory.join("equivocation");
        let mut result = Self {
            directory,
            proofs: BTreeMap::new(),
        };
        if !plain_directory(&result.directory)? {
            return Ok(result);
        }
        for &id in identities {
            let path = result.directory.join(format!("{id}.bin"));
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_file() && !meta.file_type().is_symlink() => {}
                Ok(_) => return Err(local("invalid equivocation proof file type")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(local(error)),
            }
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(local)?
                .take(DoubleVoteEvidence::ENCODED_LEN as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(local)?;
            let proof = DoubleVoteEvidence::decode(&bytes).map_err(local)?;
            if proof.voter() != id {
                return Err(local("equivocation proof identity mismatch"));
            }
            result.proofs.insert(id, proof);
        }
        network.verify_evidence_history(storage, &result.proofs)?;
        Ok(result)
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = &DoubleVoteEvidence> {
        self.proofs.values()
    }

    pub(crate) fn persist(&mut self, proof: DoubleVoteEvidence) -> Result<(), NetworkNodeError> {
        if self.proofs.contains_key(&proof.voter()) {
            return Ok(());
        }
        if !plain_directory(&self.directory)? {
            std::fs::create_dir(&self.directory).map_err(local)?;
            sync_directory(
                self.directory
                    .parent()
                    .ok_or_else(|| local("missing evidence parent"))?,
            )?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(format!("{}.bin", proof.voter())))
            .map_err(local)?;
        file.write_all(&proof.encode())
            .and_then(|()| file.sync_all())
            .map_err(local)?;
        sync_directory(&self.directory)?;
        self.proofs.insert(proof.voter(), proof);
        Ok(())
    }
}

fn plain_directory(path: &Path) -> Result<bool, NetworkNodeError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(local("invalid equivocation directory type")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(local(error)),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), NetworkNodeError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(local)
}
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> Result<(), NetworkNodeError> {
    Ok(())
}
