// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Contract-visible deterministic failures.

/// Contract-visible deterministic failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Caller supplied malformed data.
    InvalidInput,
    /// Contract attempted access outside its declared state lease.
    AccessDenied,
    /// The transaction exhausted a resource class.
    ResourceLimit,
    /// A host operation failed deterministically.
    HostFailure,
    /// Insufficient balance for the requested operation.
    InsufficientBalance,
}

impl core::fmt::Display for ContractError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid input"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::ResourceLimit => write!(f, "resource limit exceeded"),
            Self::HostFailure => write!(f, "host failure"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
        }
    }
}
