// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Execution waves, plans, and lane definitions.

use transaction::TransactionLane;

/// A conflict-free set of transactions that may execute concurrently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionWave {
    /// Original transaction indexes in deterministic order.
    pub transaction_indexes: Vec<usize>,
}

/// A deterministic execution plan containing one or more lanes and waves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    /// Waves execute sequentially; transactions inside a wave may run in parallel.
    pub waves: Vec<ExecutionWave>,
}

/// Workload lane used for admission and resource isolation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionLane {
    /// Ordinary account transfers.
    Payments,
    /// Rust smart-contract calls.
    Contracts,
    /// Consensus-governed system operations.
    System,
}

impl From<TransactionLane> for ExecutionLane {
    fn from(lane: TransactionLane) -> Self {
        match lane {
            TransactionLane::Payments => Self::Payments,
            TransactionLane::Contracts => Self::Contracts,
            TransactionLane::System => Self::System,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_conversion() {
        assert_eq!(
            ExecutionLane::from(TransactionLane::Payments),
            ExecutionLane::Payments
        );
        assert_eq!(
            ExecutionLane::from(TransactionLane::Contracts),
            ExecutionLane::Contracts
        );
        assert_eq!(
            ExecutionLane::from(TransactionLane::System),
            ExecutionLane::System
        );
    }
}
