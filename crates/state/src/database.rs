// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State database boundary for batching, snapshots, and sequential commits.

use types::{Hash256, StateKey};

use crate::diff::StateDiff;
use crate::{StateAbsenceProof, StateProof};

/// An immutable state view at a finalized or speculative root.
pub trait StateSnapshot: Send + Sync {
    /// Root identifying this snapshot.
    fn root(&self) -> Hash256;

    /// Reads a value without mutating shared state.
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError>;

    /// Proves membership of an existing key; absence is not an authenticated proof.
    fn prove(&self, key: &StateKey) -> Result<Option<StateProof>, StateError>;

    /// Proves absence using authenticated neighboring entries; returns `None` for
    /// an existing key. Queries exceeding the state key limit are rejected.
    fn prove_absence(&self, key: &StateKey) -> Result<Option<StateAbsenceProof>, StateError>;
}

/// State database boundary for batching, snapshots, and sequential commits.
pub trait StateDatabase {
    /// Creates an immutable snapshot without a global execution lock.
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError>;

    /// Prefetches likely keys into a non-consensus cache.
    fn prefetch(&self, keys: &[StateKey]) -> Result<(), StateError>;

    /// Applies canonically ordered diffs in one sequential commit stage.
    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError>;
}

/// State access and commit failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    /// Persistent data is missing or malformed.
    Corrupt,
    /// A lease omitted an accessed key or used the wrong mode.
    LeaseViolation,
    /// The expected parent root changed before commit.
    StaleSnapshot,
    /// Configured state or resource limits were exceeded.
    LimitExceeded,
    /// A proposed or imported state does not match the trusted commitment.
    RootMismatch,
    /// The database is already open by another writer.
    Locked,
    /// A filesystem operation failed before publication.
    Io,
    /// Publication completed, but directory synchronization failed; reopen to recover.
    DurabilityUnknown,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt => write!(f, "state data is corrupt"),
            Self::LeaseViolation => write!(f, "lease violation"),
            Self::StaleSnapshot => write!(f, "stale snapshot"),
            Self::LimitExceeded => write!(f, "state limit exceeded"),
            Self::RootMismatch => write!(f, "state root mismatch"),
            Self::Locked => write!(f, "state database is locked"),
            Self::Io => write!(f, "state I/O error"),
            Self::DurabilityUnknown => write!(f, "state durability is unknown; reopen database"),
        }
    }
}

impl std::error::Error for StateError {}
