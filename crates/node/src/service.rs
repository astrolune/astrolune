// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Node service trait and basic pipeline state machine.

use crate::capacity::{
    AdaptiveCapacityController, CapacityController, CapacityObservation, DEFAULT_CAPACITY,
    LATENCY_WINDOW, NodeError,
};
use types::Resources;

/// Top-level node service boundary.
pub trait NodeService {
    /// Advances available stages without coupling finality to execution threads.
    fn advance(&mut self) -> Result<(), NodeError>;
}

/// Current high-level state of the node pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeState {
    /// No active block processing.
    Idle,
    /// Synchronizing with the network.
    Syncing,
    /// Participating in consensus voting.
    Voting {
        /// Block height being voted on.
        height: u64,
        /// Consensus round number.
        round: u32,
    },
    /// Executing a block's transaction order.
    Executing {
        /// Block height being executed.
        height: u64,
    },
    /// Committing finalized state changes.
    Committing {
        /// Block height being committed.
        height: u64,
    },
}

/// Concrete [`NodeService`] implementation that drives the pipeline state machine
/// and records capacity observations for adaptive sizing.
#[derive(Clone, Debug)]
pub struct BasicNodeService {
    /// Current pipeline state.
    pub state: NodeState,
    /// Adaptive capacity controller.
    pub capacity_controller: AdaptiveCapacityController,
    /// Recorded observations from completed blocks.
    pub observations: Vec<CapacityObservation>,
}

impl BasicNodeService {
    /// Creates a new service with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: NodeState::Idle,
            capacity_controller: AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW),
            observations: Vec::new(),
        }
    }

    /// Returns the current pipeline state.
    #[must_use]
    pub fn current_state(&self) -> &NodeState {
        &self.state
    }

    /// Returns the current adaptive capacity.
    #[must_use]
    pub fn current_capacity(&self) -> Resources {
        self.capacity_controller
            .next_capacity(DEFAULT_CAPACITY, &self.observations)
    }
}

impl Default for BasicNodeService {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeService for BasicNodeService {
    fn advance(&mut self) -> Result<(), NodeError> {
        self.state = match &self.state {
            NodeState::Idle => NodeState::Syncing,
            NodeState::Syncing => NodeState::Voting {
                height: 1,
                round: 0,
            },
            NodeState::Voting { height, .. } => NodeState::Executing { height: *height },
            NodeState::Executing { height } => NodeState::Committing { height: *height },
            NodeState::Committing { height: _ } => {
                self.observations.push(CapacityObservation {
                    used: Resources {
                        compute: 100,
                        memory: 128,
                        io: 32,
                        bandwidth: 64,
                    },
                    within_latency_target: true,
                });
                NodeState::Idle
            }
        };
        Ok(())
    }
}
