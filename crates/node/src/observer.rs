// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Non-voting full nodes independently verify finalized history and execution.
//! This module never loads a consensus key, reserves a signature, or creates a vote.

use crate::{
    network::{NetworkNodeError, PreparedResponse, RecoveredNetwork, StaticNetwork, input, local},
    network_wire::{NetworkMessage, SyncRequest, decode_exchange},
};
use std::{
    io::{Read, Write},
    path::Path,
};
use storage::ChainStorage;
use types::{Hash256, Transaction};

/// Persistent role marker preventing accidental use of a demonstration daemon.
pub const OBSERVER_MARKER: &str = "observer.mode";

/// A non-voting full node with independent certified recovery and state-aware gossip.
pub struct ObserverNode {
    network: StaticNetwork,
    chain: RecoveredNetwork,
}

impl ObserverNode {
    /// Checks role compatibility without creating files or opening the archive.
    pub fn validate_directory(
        network: &StaticNetwork,
        directory: &Path,
    ) -> Result<(), NetworkNodeError> {
        for name in ["signing.journal", "consensus-cache.bin"] {
            match std::fs::symlink_metadata(directory.join(name)) {
                Ok(_) => {
                    return Err(input(
                        "observer requires a separate directory without validator signing state",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(local(error)),
            }
        }
        match std::fs::File::open(directory.join(OBSERVER_MARKER)) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(37).read_to_end(&mut bytes).map_err(local)?;
                if bytes != marker_bytes(network) {
                    return Err(input("observer role marker or genesis mismatch"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(local(error)),
        }
        Ok(())
    }

    /// Opens or initializes a certified archive without any consensus signing authority.
    /// Recovered certificates use the same trusted-genesis checks as a validator.
    pub fn open(network: StaticNetwork, directory: &Path) -> Result<Self, NetworkNodeError> {
        Self::validate_directory(&network, directory)?;
        std::fs::create_dir_all(directory).map_err(local)?;
        let chain = network.recover(directory)?;
        // The archive's exclusive writer lock remains held while provisioning the marker.
        Self::validate_directory(&network, directory)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(OBSERVER_MARKER))
        {
            Ok(mut file) => {
                file.write_all(&marker_bytes(&network)).map_err(local)?;
                file.sync_all().map_err(local)?;
                #[cfg(unix)]
                std::fs::File::open(directory)
                    .and_then(|parent| parent.sync_all())
                    .map_err(local)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::validate_directory(&network, directory)?;
            }
            Err(error) => return Err(local(error)),
        }
        Ok(Self { network, chain })
    }

    /// Current committed state and archive. Pending transactions are never exposed as state.
    #[must_use]
    pub const fn storage(&self) -> &ChainStorage {
        &self.chain.storage
    }

    /// Requests the first missing finalized block from the trusted genesis namespace.
    #[must_use]
    pub fn request(&self) -> SyncRequest {
        SyncRequest {
            genesis: self.network.genesis_hash(),
            height: self.chain.producer.height(),
        }
    }

    /// Validates a signed transaction against committed state for subsequent peer gossip.
    pub fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<Hash256, NetworkNodeError> {
        self.chain
            .producer
            .submit_transaction(transaction)
            .map_err(Into::into)
    }

    /// Serves already authenticated finalized blocks or bounded pending transactions.
    /// Proposals, prevotes, precommits and available-value proofs are never originated or relayed.
    pub fn respond(&self, request: SyncRequest) -> Result<Vec<u8>, NetworkNodeError> {
        self.prepare_response(request)?.encode()
    }

    /// Selects an owned response snapshot for encoding outside the node lock.
    /// The exchange codec's size and message limits are checked during encoding.
    pub fn prepare_response(
        &self,
        request: SyncRequest,
    ) -> Result<PreparedResponse, NetworkNodeError> {
        if request.genesis != self.network.genesis_hash() {
            return Err(input("peer genesis mismatch"));
        }
        let messages = if let Some((block, encoded)) = self
            .chain
            .storage
            .read_finalized(request.height)
            .map_err(local)?
        {
            vec![NetworkMessage::Finalized {
                block,
                certificate: consensus::FinalityCertificate::decode(&encoded).map_err(local)?,
            }]
        } else if request.height == self.request().height {
            self.chain
                .producer
                .pending_transactions()
                .into_iter()
                .map(NetworkMessage::Transaction)
                .collect()
        } else {
            Vec::new()
        };
        Ok(PreparedResponse::new(self.network.genesis_hash(), messages))
    }

    /// Decodes an entire bounded exchange before processing.
    /// Returns rejected transaction/block count; ignores live consensus messages.
    /// Local storage failures are fatal and never downgraded to peer input failures.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<usize, NetworkNodeError> {
        let messages = decode_exchange(self.network.genesis_hash(), bytes).map_err(input)?;
        let mut rejected = 0;
        for message in messages {
            match self.receive_message(message) {
                Ok(()) => {}
                Err(NetworkNodeError::Input(_)) => rejected += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(rejected)
    }

    fn receive_message(&mut self, message: NetworkMessage) -> Result<(), NetworkNodeError> {
        match message {
            NetworkMessage::Finalized { block, certificate } => {
                if block.header.height != self.request().height {
                    return Err(input("stale or nonsequential finalized block"));
                }
                let committee = self.network.current_committee(&self.chain.producer)?;
                committee
                    .verify_certificate(&certificate, &block.header)
                    .map_err(input)?;
                self.chain.producer.prepare_received_vrf(&block)?;
                let proposal = self.chain.producer.execute_received_block(block)?;
                self.chain.producer.commit_certified_block(
                    &proposal,
                    &certificate,
                    &committee,
                    &mut self.chain.storage,
                )?;
            }
            NetworkMessage::Transaction(transaction) => {
                self.submit_transaction(transaction)?;
            }
            NetworkMessage::VrfContribution { .. }
            | NetworkMessage::PotbAdmission(_)
            | NetworkMessage::PotbEvidence(_)
            | NetworkMessage::Governance(_)
            | NetworkMessage::Proposal { .. }
            | NetworkMessage::Vote(_)
            | NetworkMessage::ValidValue { .. } => {}
        }
        Ok(())
    }
}

fn marker_bytes(network: &StaticNetwork) -> Vec<u8> {
    let mut bytes = b"ALOB".to_vec();
    bytes.extend_from_slice(network.genesis_hash().as_bytes());
    bytes
}
