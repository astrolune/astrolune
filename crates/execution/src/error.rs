// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Execution and scheduling error types.

use state::StateError;
use transaction::TransactionError;

/// Execution and scheduling failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Contract code or its artifact is invalid.
    InvalidContract,
    /// Actual access exceeded the declared lease.
    UndeclaredStateAccess,
    /// Resource metering stopped execution.
    ResourceLimit,
    /// Optimistic outputs conflict and require canonical replay.
    Conflict,
    /// Arithmetic, memory, or host behavior trapped deterministically.
    Trap,
    /// Transaction validation failed.
    TransactionValidation(TransactionError),
    /// State database error.
    State(StateError),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContract => write!(f, "invalid contract"),
            Self::UndeclaredStateAccess => write!(f, "undeclared state access"),
            Self::ResourceLimit => write!(f, "resource limit exceeded"),
            Self::Conflict => write!(f, "execution conflict"),
            Self::Trap => write!(f, "deterministic trap"),
            Self::TransactionValidation(e) => write!(f, "transaction validation: {e}"),
            Self::State(e) => write!(f, "state error: {e}"),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<TransactionError> for ExecutionError {
    fn from(e: TransactionError) -> Self {
        Self::TransactionValidation(e)
    }
}

impl From<StateError> for ExecutionError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_error_display() {
        let errors = [
            ExecutionError::InvalidContract,
            ExecutionError::UndeclaredStateAccess,
            ExecutionError::ResourceLimit,
            ExecutionError::Conflict,
            ExecutionError::Trap,
        ];
        for e in &errors {
            assert_ne!(e.to_string().len(), 0);
        }
    }

    #[test]
    fn execution_error_from_transaction_error() {
        let e = ExecutionError::from(TransactionError::WrongChain);
        assert!(matches!(e, ExecutionError::TransactionValidation(_)));
    }

    #[test]
    fn execution_error_from_state_error() {
        let e = ExecutionError::from(StateError::StaleSnapshot);
        assert!(matches!(e, ExecutionError::State(_)));
    }
}
