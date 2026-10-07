// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Local demonstration service with execution and storage integration.
//!
//! This module provides [`FullNodeService`], a concrete implementation
//! of the node service trait that wires together the mempool, simulated finality,
//! execution pipeline, and persistent storage into a cohesive block
//! production and finalization workflow.

use consensus::{Committee, CommitteeMember};
use storage::{FileBackedStorage, InMemoryStorage, NodeStorage};
use types::{Hash256, Resources};

use crate::capacity::{
    AdaptiveCapacityController, CapacityController, CapacityObservation, DEFAULT_CAPACITY,
    LATENCY_WINDOW, NodeError,
};
use crate::producer::{BlockProducer, BlockProposal, ProducerConfig, ProducerError};

/// Current high-level state of the full node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FullNodeState {
    /// Node is idle, waiting for the next block production cycle.
    Idle,
    /// Node is synchronizing with the network.
    Syncing,
    /// Node is selecting transactions and assembling a block proposal.
    Proposing {
        /// Height being proposed.
        height: u64,
    },
    /// Node is participating in consensus voting.
    Voting {
        /// Block height being voted on.
        height: u64,
        /// Consensus round number.
        round: u32,
    },
    /// Node is executing the finalized transaction order.
    Executing {
        /// Block height being executed.
        height: u64,
    },
    /// Node is committing finalized state to durable storage.
    Committing {
        /// Block height being committed.
        height: u64,
    },
}

/// Full node service that coordinates block production, consensus, and storage.
///
/// Integrates:
/// - [`BlockProducer`] for transaction selection and block assembly
/// - Demonstration committee metadata; finality is simulated
/// - [`NodeStorage`] for atomic block and state publication
/// - [`AdaptiveCapacityController`] for dynamic block sizing
pub struct FullNodeService<S = InMemoryStorage> {
    /// Current pipeline state.
    state: FullNodeState,
    /// Block production pipeline.
    producer: BlockProducer,
    /// Current committee for the active height.
    committee: Option<Committee>,
    /// Persistent storage backend.
    storage: S,
    /// Adaptive capacity controller.
    capacity_controller: AdaptiveCapacityController,
    /// Recorded observations from completed blocks.
    observations: Vec<CapacityObservation>,
    /// Current adaptive block capacity.
    block_capacity: Resources,
    /// Pending block proposal awaiting consensus.
    pending_proposal: Option<BlockProposal>,
    /// Finalized block hash from consensus.
    finalized_block: Option<Hash256>,
}

impl FullNodeService {
    /// Creates a new full node service with the given producer configuration.
    #[must_use]
    pub fn new(config: ProducerConfig) -> Self {
        let capacity = config.block_capacity;
        Self::with_producer(BlockProducer::new(config), InMemoryStorage::new(), capacity)
    }
}

impl FullNodeService<FileBackedStorage> {
    /// Opens a local demonstration chain and resumes after its last durable block.
    ///
    /// The directory must exist. Corrupt archives, concurrent writers, and exhausted
    /// heights fail before production starts. This does not authenticate finality or
    /// restore consensus keys or pending transactions. Genesis-backed archives
    /// must be opened with `open_with_genesis`.
    pub fn open(
        config: ProducerConfig,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, ProducerError> {
        let storage = FileBackedStorage::open(path)?;
        if storage.state().get(&genesis::genesis_key()).is_some() {
            return Err(ProducerError::Assembly(
                "this archive requires its genesis configuration".into(),
            ));
        }
        Self::resume(config, storage)
    }

    /// Opens or initializes a chain using an independently trusted genesis.
    ///
    /// Genesis is a height-zero anchor; the first produced block has height one.
    /// Restarts verify the committed genesis identity, and never reset accounts.
    /// Legacy archives cannot be converted implicitly. The demonstration committee
    /// uses the first configured seats in canonical order; this is not `PoTB` selection.
    /// Native payments use signed account execution; finality authentication remains pending.
    pub fn open_with_genesis(
        config: ProducerConfig,
        path: impl AsRef<std::path::Path>,
        genesis: &genesis::Genesis,
    ) -> Result<Self, ProducerError> {
        if genesis.version == genesis::ROTATING_GENESIS_VERSION {
            return Err(ProducerError::Assembly(
                "rotating genesis requires the certified network driver".into(),
            ));
        }
        let initial = genesis
            .materialize()
            .map_err(|error| ProducerError::Assembly(error.to_string()))?;
        if config.chain_id != genesis.chain_id || config.block_capacity != genesis.capacity {
            return Err(ProducerError::Assembly(
                "producer configuration differs from genesis".into(),
            ));
        }
        let hash = genesis
            .commitment()
            .map_err(|error| ProducerError::Assembly(error.to_string()))?;
        let mut storage = FileBackedStorage::open(path)?;
        if let Some(checkpoint) = storage.checkpoint() {
            if storage.state().get(&genesis::genesis_key()) != Some(hash.as_bytes().as_slice())
                || (checkpoint.height == 0
                    && (checkpoint.block != hash || checkpoint.state_root != initial.root()))
            {
                return Err(ProducerError::Assembly("archive genesis mismatch".into()));
            }
        } else {
            storage.initialize_genesis(hash, initial)?;
        }
        let mut service = Self::resume(config, storage)?;
        service.setup_committee(
            genesis
                .validators
                .iter()
                .take(genesis.committee_size)
                .map(|validator| CommitteeMember {
                    id: validator.id,
                    power: consensus::PotbWeight(validator.weight),
                })
                .collect(),
        );
        Ok(service)
    }

    fn resume(
        config: ProducerConfig,
        mut storage: FileBackedStorage,
    ) -> Result<Self, ProducerError> {
        let checkpoint = storage.recover()?;
        if checkpoint.is_some_and(|head| {
            storage
                .get_certificate(&head.block)
                .is_some_and(|bytes| consensus::FinalityCertificate::decode(bytes).is_ok())
        }) {
            return Err(ProducerError::Assembly(
                "certified history cannot be resumed by the demonstration service".into(),
            ));
        }
        let capacity = config.block_capacity;
        let producer = BlockProducer::from_checkpoint(config, checkpoint, storage.state().clone())?;
        let mut service = Self::with_producer(producer, storage, capacity);
        service.finalized_block = checkpoint.map(|value| value.block);
        Ok(service)
    }
}

impl<S: NodeStorage> FullNodeService<S> {
    fn with_producer(producer: BlockProducer, storage: S, block_capacity: Resources) -> Self {
        Self {
            state: FullNodeState::Idle,
            producer,
            committee: None,
            storage,
            capacity_controller: AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW),
            observations: Vec::new(),
            block_capacity,
            pending_proposal: None,
            finalized_block: None,
        }
    }

    /// Returns the current pipeline state.
    #[must_use]
    pub fn current_state(&self) -> &FullNodeState {
        &self.state
    }

    /// Returns the current block height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.producer.height()
    }

    /// Returns the number of pending transactions.
    #[must_use]
    pub fn pending_transactions(&self) -> usize {
        self.producer.pending_count()
    }

    /// Returns the current adaptive block capacity.
    #[must_use]
    pub fn block_capacity(&self) -> Resources {
        self.block_capacity
    }

    /// Returns a reference to the storage backend.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Submits a transaction to the mempool.
    pub fn submit_transaction(
        &mut self,
        tx: types::Transaction,
    ) -> Result<Hash256, crate::producer::ProducerError> {
        self.producer.submit_transaction(tx)
    }

    /// Sets up the committee for the current height.
    ///
    /// Stores demonstration metadata only. Authenticated membership must be
    /// derived from trusted finalized state before using the certified producer API.
    pub fn setup_committee(&mut self, members: Vec<CommitteeMember>) {
        let height = self.producer.height();
        let committee = Committee { height, members };
        self.committee = Some(committee);
    }

    /// Returns the current committee, if set.
    #[must_use]
    pub fn committee(&self) -> Option<&Committee> {
        self.committee.as_ref()
    }

    /// Returns the finalized block hash from consensus, if any.
    #[must_use]
    pub fn finalized_block(&self) -> Option<Hash256> {
        self.finalized_block
    }

    /// Drives the pipeline through one state transition.
    ///
    /// The state machine follows the finalization path:
    /// Idle -> Proposing -> Voting -> Executing -> Committing -> Idle
    fn advance_pipeline(&mut self) -> Result<(), NodeError> {
        self.state = match &self.state {
            FullNodeState::Idle => FullNodeState::Proposing {
                height: self.producer.height(),
            },
            FullNodeState::Syncing => {
                // In a real node, this would sync with the network.
                // For now, transition to idle.
                FullNodeState::Idle
            }
            FullNodeState::Proposing { height } => {
                // Assemble and execute the block
                match self.producer.produce_block() {
                    Ok(proposal) => {
                        self.pending_proposal = Some(proposal);
                        FullNodeState::Voting {
                            height: *height,
                            round: 0,
                        }
                    }
                    Err(_) => return Err(NodeError::CommitmentMismatch),
                }
            }
            FullNodeState::Voting { height, .. } => {
                // In single-validator mode, simulate immediate finalization
                if self.pending_proposal.is_some() {
                    FullNodeState::Executing { height: *height }
                } else {
                    FullNodeState::Idle
                }
            }
            FullNodeState::Executing { height } => {
                // Execution is already done during block assembly
                FullNodeState::Committing { height: *height }
            }
            FullNodeState::Committing { height: _ } => {
                // Commit to storage
                if let Some(proposal) = self.pending_proposal.as_ref() {
                    let checkpoint = self
                        .producer
                        .commit_block(
                            proposal,
                            vec![0xAA; 32], // Placeholder certificate
                            &mut self.storage,
                        )
                        .map_err(|error| match error {
                            crate::producer::ProducerError::Storage(error) => {
                                NodeError::Storage(error)
                            }
                            _ => NodeError::CommitmentMismatch,
                        })?;
                    self.finalized_block = Some(checkpoint.block);

                    // Record capacity observation
                    if self.observations.len() == LATENCY_WINDOW {
                        self.observations.remove(0);
                    }
                    self.observations.push(CapacityObservation {
                        used: proposal.resources_used,
                        within_latency_target: true,
                    });

                    // Update adaptive capacity
                    self.block_capacity = self
                        .capacity_controller
                        .next_capacity(self.block_capacity, &self.observations);
                    self.pending_proposal = None;
                    if let Some(committee) = self.committee.as_ref() {
                        self.setup_committee(committee.members.clone());
                    }
                } else {
                    return Err(NodeError::NotReady);
                }
                FullNodeState::Idle
            }
        };
        Ok(())
    }
}

impl<S: NodeStorage> crate::service::NodeService for FullNodeService<S> {
    fn advance(&mut self) -> Result<(), NodeError> {
        self.advance_pipeline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::producer::ProducerConfig;
    use crate::service::NodeService;
    use consensus::CommitteeMember;
    use mempool::PoolLimits;
    use types::{Address, Resources};

    #[test]
    fn commit_failure_remains_visible_and_keeps_pending_work() {
        let mut service = FullNodeService::new(test_config());
        let proposal = service.producer.produce_block().unwrap();
        let mut invalid = proposal.clone();
        invalid.block.header.state_root = Hash256::ZERO;
        service.pending_proposal = Some(invalid);
        service.state = FullNodeState::Committing { height: 0 };
        assert_eq!(service.advance(), Err(NodeError::CommitmentMismatch));
        assert_eq!(service.state, FullNodeState::Committing { height: 0 });
        assert!(service.pending_proposal.is_some());
        assert_eq!(service.observations.len(), 0);
        assert_eq!(service.height(), 0);
        assert_eq!(service.finalized_block(), None);
        service.pending_proposal = Some(proposal);
        service.advance().unwrap();
        assert_eq!(service.height(), 1);
        assert!(service.pending_proposal.is_none());
        assert_eq!(service.observations.len(), 1);
        assert_eq!(
            service.finalized_block(),
            Some(service.storage().checkpoint().unwrap().block)
        );
    }

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            chain_id: 7,
            max_block_transactions: 10,
            max_transaction_bytes: 1024,
            pool_limits: PoolLimits {
                max_transactions: 100,
                max_bytes: 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: types::ValidatorId::from_bytes([id; 32]),
            power: consensus::PotbWeight(power),
        }
    }

    #[test]
    fn service_starts_idle() {
        let service = FullNodeService::new(test_config());
        assert_eq!(*service.current_state(), FullNodeState::Idle);
        assert_eq!(service.height(), 0);
    }

    #[test]
    fn advance_through_full_cycle() {
        let mut service = FullNodeService::new(test_config());

        // Idle -> Proposing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Proposing { height: 0 }
        );

        // Proposing -> Voting
        service.advance().unwrap();
        assert!(matches!(
            *service.current_state(),
            FullNodeState::Voting {
                height: 0,
                round: 0
            }
        ));

        // Voting -> Executing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Executing { height: 0 }
        );

        // Executing -> Committing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Committing { height: 0 }
        );

        // Committing -> Idle
        service.advance().unwrap();
        assert_eq!(*service.current_state(), FullNodeState::Idle);
    }

    #[test]
    fn submit_transaction_increases_pending() {
        let mut service = FullNodeService::new(test_config());
        let tx = types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: sender(),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };
        service.submit_transaction(tx).unwrap();
        assert_eq!(service.pending_transactions(), 1);
    }

    #[test]
    fn full_cycle_produces_block_in_storage() {
        let mut service = FullNodeService::new(test_config());

        // Run one full cycle
        for _ in 0..5 {
            service.advance().unwrap();
        }

        assert_eq!(*service.current_state(), FullNodeState::Idle);
        assert_eq!(service.height(), 1);
        assert!(service.storage().checkpoint().is_some());
    }

    #[test]
    fn multiple_full_cycles() {
        let mut service = FullNodeService::new(test_config());

        for _ in 0..3 {
            for _ in 0..5 {
                service.advance().unwrap();
            }
        }

        assert_eq!(service.height(), 3);
        assert_eq!(service.observations.len(), 3);
    }

    #[test]
    fn committee_setup() {
        let mut service = FullNodeService::new(test_config());
        let members = vec![make_member(1, 10), make_member(2, 20)];
        service.setup_committee(members);

        assert!(service.committee().is_some());
        assert_eq!(service.committee().unwrap().members.len(), 2);
    }

    #[test]
    fn block_capacity_updates() {
        let mut service = FullNodeService::new(test_config());

        // Run several cycles to trigger capacity adaptation
        for _ in 0..20 {
            for _ in 0..5 {
                service.advance().unwrap();
            }
        }

        // Capacity should have been adjusted
        assert_eq!(service.observations.len(), LATENCY_WINDOW);
    }

    #[test]
    fn state_clone_and_eq() {
        let s1 = FullNodeState::Voting {
            height: 10,
            round: 2,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn state_debug() {
        let s = FullNodeState::Executing { height: 42 };
        let debug = format!("{s:?}");
        assert!(debug.contains("Executing"));
        assert!(debug.contains("42"));
    }
}
