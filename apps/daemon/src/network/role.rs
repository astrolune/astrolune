// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit daemon roles sharing transport and committed-state RPC.

use crate::{DaemonError, io_error, options::Options};
use node::{
    network::{NetworkNode, NetworkNodeError, PreparedExchange, PreparedResponse, StaticNetwork},
    network_wire::SyncRequest,
    observer::ObserverNode,
};
use std::time::{Duration, Instant};
use storage::ChainStorage;
use types::{Hash256, Transaction};

pub(super) enum PeerNode {
    Validator(Box<NetworkNode>),
    Observer(Box<ObserverNode>),
}

impl PeerNode {
    pub(super) fn submit_potb(
        &mut self,
        message: node::network_wire::NetworkMessage,
    ) -> Result<Hash256, NetworkNodeError> {
        let Self::Validator(node) = self else {
            return Err(NetworkNodeError::Input(
                "PoTB submissions require a validator endpoint".into(),
            ));
        };
        match message {
            node::network_wire::NetworkMessage::Governance(value) => node.submit_governance(value),
            node::network_wire::NetworkMessage::PotbAdmission(value) => {
                node.submit_potb_admission(value)
            }
            node::network_wire::NetworkMessage::PotbEvidence(value) => {
                node.submit_potb_evidence(value)
            }
            _ => Err(NetworkNodeError::Input("invalid PoTB submission".into())),
        }
    }
    pub(super) fn open(
        options: &Options,
        network: StaticNetwork,
        seed: Option<zeroize::Zeroizing<[u8; 32]>>,
    ) -> Result<Self, DaemonError> {
        if options.observer {
            if seed.is_some() {
                return Err(DaemonError::Config(
                    "observer cannot have a consensus seed".into(),
                ));
            }
            return ObserverNode::open(network, &options.config.data_dir)
                .map(Box::new)
                .map(Self::Observer)
                .map_err(io_error);
        }
        let seed = seed.ok_or_else(|| DaemonError::Config("validator seed required".into()))?;
        // Open-only: selecting the voting role never provisions or recreates a journal.
        let signer = keystore::DurableSigner::open(
            options.config.data_dir.join("signing.journal"),
            keystore::SigningContext {
                chain_id: network.chain_id(),
                genesis: network.genesis_hash(),
            },
            *seed,
        )
        .map_err(io_error)?;
        drop(seed);
        NetworkNode::open(
            network,
            &options.config.data_dir,
            signer,
            Duration::from_millis(options.round_timeout_ms),
        )
        .map(Box::new)
        .map(Self::Validator)
        .map_err(io_error)
    }

    pub(super) fn storage(&self) -> &ChainStorage {
        match self {
            Self::Validator(node) => node.storage(),
            Self::Observer(node) => node.storage(),
        }
    }

    pub(super) fn request(&self) -> SyncRequest {
        match self {
            Self::Validator(node) => node.request(),
            Self::Observer(node) => node.request(),
        }
    }

    pub(super) fn prepare_response(
        &self,
        request: SyncRequest,
    ) -> Result<PreparedResponse, NetworkNodeError> {
        match self {
            Self::Validator(node) => node.prepare_response(request),
            Self::Observer(node) => node.prepare_response(request),
        }
    }

    pub(super) fn receive_prepared(
        &mut self,
        exchange: PreparedExchange,
    ) -> Result<usize, NetworkNodeError> {
        match self {
            Self::Validator(node) => node.receive_prepared(exchange),
            Self::Observer(node) => node.receive_prepared(exchange),
        }
    }

    pub(super) fn submit_transaction(
        &mut self,
        tx: Transaction,
    ) -> Result<Hash256, NetworkNodeError> {
        match self {
            Self::Validator(node) => node.submit_transaction(tx),
            Self::Observer(node) => node.submit_transaction(tx),
        }
    }

    pub(super) fn tick(&mut self, now: Instant) -> Result<(), NetworkNodeError> {
        match self {
            Self::Validator(node) => node.tick(now),
            Self::Observer(_) => Ok(()),
        }
    }
}
