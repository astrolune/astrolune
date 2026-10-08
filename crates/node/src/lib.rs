// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Node pipeline coordination across propagation, consensus, execution, and commit.
//!
//! This crate provides the core node service layer that coordinates:
//! - Block production via [`BlockProducer`]
//! - Pipeline state machine via [`BasicNodeService`]
//! - Adaptive capacity management via [`AdaptiveCapacityController`]

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
mod evidence;

pub mod capacity;
pub mod compact_wire;
pub mod execution_pipeline;
pub mod full_service;
pub mod handoff;
pub mod network;
mod network_background;
pub mod network_wire;
pub mod observer;
pub mod pipeline;
pub mod producer;
pub mod service;
pub mod validator;

pub use capacity::{
    AdaptiveCapacityController, CapacityController, CapacityObservation, DEFAULT_CAPACITY,
    LATENCY_WINDOW, MIN_CAPACITY, NodeError,
};
pub use full_service::{FullNodeService, FullNodeState};
pub use pipeline::PipelineStage;
pub use producer::{
    BlockProducer, BlockProposal, ProducerConfig, ProducerError, compute_receipts_root,
    compute_transactions_root, hash_transaction,
};
pub use service::{BasicNodeService, NodeService, NodeState};
pub use validator::{RoundRobinValidator, SignedBlockProposal, TimeoutEvent, ValidatorError};

#[cfg(test)]
mod tests {
    use super::*;
    use types::Resources;

    #[test]
    fn node_error_display() {
        assert_eq!(
            NodeError::NotReady.to_string(),
            "required subsystem not ready"
        );
        assert_eq!(
            NodeError::CommitmentMismatch.to_string(),
            "finalized commitment disagrees with deterministic execution"
        );
        assert_eq!(
            NodeError::CapacityExceeded.to_string(),
            "bounded queue or configured resource ceiling was reached"
        );
    }

    #[test]
    fn node_error_is_error() {
        let e: &dyn std::error::Error = &NodeError::NotReady;
        assert!(e.source().is_none());
    }

    #[test]
    fn default_capacity_values() {
        assert_eq!(DEFAULT_CAPACITY.compute, 1000);
        assert_eq!(DEFAULT_CAPACITY.memory, 1024);
        assert_eq!(DEFAULT_CAPACITY.io, 256);
        assert_eq!(DEFAULT_CAPACITY.bandwidth, 1024);
    }

    #[test]
    fn min_capacity_values() {
        assert_eq!(MIN_CAPACITY.compute, 1);
        assert_eq!(MIN_CAPACITY.memory, 1);
        assert_eq!(MIN_CAPACITY.io, 1);
        assert_eq!(MIN_CAPACITY.bandwidth, 1);
    }

    #[test]
    fn latency_window_value() {
        assert_eq!(LATENCY_WINDOW, 16);
    }

    #[test]
    fn controller_returns_current_when_no_observations() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &[]);
        assert_eq!(result, DEFAULT_CAPACITY);
    }

    #[test]
    fn controller_scales_up_when_within_target() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 500,
                memory: 512,
                io: 100,
                bandwidth: 500,
            },
            within_latency_target: true,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 1100);
        assert_eq!(result.memory, 1126);
        assert_eq!(result.io, 281);
        assert_eq!(result.bandwidth, 1126);
    }

    #[test]
    fn controller_scales_down_when_exceeds() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 1500,
                memory: 1100,
                io: 300,
                bandwidth: 1100,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 900);
        assert_eq!(result.memory, 921);
        assert_eq!(result.io, 230);
        assert_eq!(result.bandwidth, 921);
    }

    #[test]
    fn controller_clamps_to_min_capacity() {
        let ctrl = AdaptiveCapacityController::new(
            Resources {
                compute: 10,
                memory: 10,
                io: 10,
                bandwidth: 10,
            },
            LATENCY_WINDOW,
        );
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(
            Resources {
                compute: 10,
                memory: 10,
                io: 10,
                bandwidth: 10,
            },
            &obs,
        );
        assert_eq!(result.compute, 9);
        assert_eq!(result.memory, 9);
        assert_eq!(result.io, 9);
        assert_eq!(result.bandwidth, 9);
    }

    #[test]
    fn controller_clamps_to_min_after_repeated_scaling_down() {
        let ctrl = AdaptiveCapacityController::new(
            Resources {
                compute: 2,
                memory: 2,
                io: 2,
                bandwidth: 2,
            },
            LATENCY_WINDOW,
        );
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(
            Resources {
                compute: 2,
                memory: 2,
                io: 2,
                bandwidth: 2,
            },
            &obs,
        );
        assert_eq!(result, MIN_CAPACITY);
    }

    #[test]
    fn controller_uses_rolling_window() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, 4);
        let obs = vec![
            CapacityObservation {
                used: Resources {
                    compute: 500,
                    memory: 500,
                    io: 50,
                    bandwidth: 500,
                },
                within_latency_target: true,
            },
            CapacityObservation {
                used: Resources {
                    compute: 500,
                    memory: 500,
                    io: 50,
                    bandwidth: 500,
                },
                within_latency_target: true,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
        ];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 900);
    }

    #[test]
    fn controller_ignores_observations_beyond_window() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, 2);
        let mut obs = vec![
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
        ];
        obs.push(CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 10,
                bandwidth: 100,
            },
            within_latency_target: true,
        });
        obs.push(CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 10,
                bandwidth: 100,
            },
            within_latency_target: true,
        });
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 1100);
    }

    #[test]
    fn controller_scales_up_correctly() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: true,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 1100);
        assert_eq!(result.memory, 1126);
        assert_eq!(result.io, 281);
        assert_eq!(result.bandwidth, 1126);
    }

    #[test]
    fn controller_scales_down_correctly() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 1000,
                memory: 1000,
                io: 1000,
                bandwidth: 1000,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        assert_eq!(result.compute, 900);
        assert_eq!(result.memory, 921);
        assert_eq!(result.io, 230);
        assert_eq!(result.bandwidth, 921);
    }

    #[test]
    fn node_state_clone_and_eq() {
        let s1 = NodeState::Voting {
            height: 10,
            round: 2,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn node_state_debug() {
        let s = NodeState::Executing { height: 42 };
        let debug = format!("{s:?}");
        assert!(debug.contains("Executing"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn service_starts_idle() {
        let svc = BasicNodeService::new();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_default_capacity() {
        let svc = BasicNodeService::new();
        assert_eq!(svc.current_capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn service_transitions_through_pipeline() {
        let mut svc = BasicNodeService::new();
        assert_eq!(*svc.current_state(), NodeState::Idle);

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Syncing);

        svc.advance().unwrap();
        assert!(matches!(
            *svc.current_state(),
            NodeState::Voting {
                height: 1,
                round: 0
            }
        ));

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Executing { height: 1 });

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Committing { height: 1 });

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_records_observation_on_commit() {
        let mut svc = BasicNodeService::new();
        for _ in 0..5 {
            svc.advance().unwrap();
        }
        assert_eq!(svc.observations.len(), 1);
        assert!(svc.observations[0].within_latency_target);
    }

    #[test]
    fn service_capacity_updates_with_observations() {
        let mut svc = BasicNodeService::new();
        for _ in 0..20 {
            svc.advance().unwrap();
        }
        assert_ne!(svc.observations.len(), 0);
        let cap = svc.current_capacity();
        assert!(cap.compute >= DEFAULT_CAPACITY.compute);
    }

    #[test]
    fn service_multiple_full_cycles() {
        let mut svc = BasicNodeService::new();
        for cycle in 0..3 {
            for _ in 0..5 {
                svc.advance().unwrap();
            }
            assert_eq!(*svc.current_state(), NodeState::Idle);
            assert_eq!(svc.observations.len(), cycle + 1);
        }
    }

    #[test]
    fn service_default_trait() {
        let svc = BasicNodeService::default();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_observation_recording() {
        let mut svc = BasicNodeService::new();
        assert_eq!(svc.observations.len(), 0);
        for _ in 0..5 {
            svc.advance().unwrap();
        }
        assert_eq!(svc.observations.len(), 1);
        let obs = svc.observations[0];
        assert_eq!(
            obs.used,
            Resources {
                compute: 100,
                memory: 128,
                io: 32,
                bandwidth: 64,
            }
        );
        assert!(obs.within_latency_target);
    }
}
