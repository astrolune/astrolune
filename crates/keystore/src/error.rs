// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Signer and key isolation failure types.

use std::fmt;

/// Signer and key isolation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystoreError {
    /// The journal mode or safety metadata cannot protect this operation.
    InvalidSafety,
    /// Another signer owns the journal's exclusive file lock.
    Locked,
    /// Explicit creation would overwrite an existing journal.
    AlreadyExists,
    /// Journal bytes are malformed, incomplete, or inconsistent.
    InvalidJournal,
    /// The chain, genesis, key, or voter differs from the signing context.
    ContextMismatch,
    /// A phase tag is unsupported.
    InvalidPosition,
    /// The requested position precedes the durable signing watermark.
    StalePosition,
    /// The raw journal or protected decision sequence has reached its limit.
    LimitExceeded,
    /// A write or synchronization failed; reopen and verify before signing again.
    DurabilityUnknown,
    /// Key handle does not exist.
    UnknownKey,
    /// Requested operation does not match the key purpose.
    WrongPurpose,
    /// Position already contains a different signing decision.
    ConflictingSign,
    /// Durable decision journal failed before signing.
    JournalFailure,
    /// Signing provider rejected the operation.
    ProviderFailure,
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSafety => write!(f, "invalid or missing signing safety state"),
            Self::Locked => write!(f, "signing journal is locked"),
            Self::AlreadyExists => write!(f, "signing journal already exists"),
            Self::InvalidJournal => write!(f, "invalid signing journal"),
            Self::ContextMismatch => write!(f, "signing context mismatch"),
            Self::InvalidPosition => write!(f, "invalid signing phase"),
            Self::StalePosition => write!(f, "signing position precedes durable watermark"),
            Self::LimitExceeded => write!(f, "signing journal limit exceeded"),
            Self::DurabilityUnknown => write!(f, "signing durability unknown; reopen required"),
            Self::UnknownKey => write!(f, "unknown key"),
            Self::WrongPurpose => write!(f, "wrong purpose"),
            Self::ConflictingSign => write!(f, "conflicting sign"),
            Self::JournalFailure => write!(f, "journal failure"),
            Self::ProviderFailure => write!(f, "provider failure"),
        }
    }
}

impl std::error::Error for KeystoreError {}
