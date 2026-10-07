// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Error types produced by the contract runtime.

use std::fmt;

/// Contract validation and execution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// Canonical module bytes are malformed.
    InvalidModule,
    /// Module requests an unsupported feature or version.
    Unsupported,
    /// Module or call exceeds a configured bound.
    LimitExceeded,
    /// Deterministic contract execution trapped.
    Trap,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModule => write!(f, "invalid module"),
            Self::Unsupported => write!(f, "unsupported feature or version"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
            Self::Trap => write!(f, "deterministic trap"),
        }
    }
}

impl std::error::Error for RuntimeError {}
