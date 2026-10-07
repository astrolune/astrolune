// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! P2P network error types.

use std::fmt;

/// P2P protocol failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    /// Frame bytes are malformed or non-canonical.
    InvalidFrame,
    /// Peer protocol or chain identity is incompatible.
    IncompatiblePeer,
    /// Configured queue, frame, or rate limit was exceeded.
    LimitExceeded,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrame => write!(f, "invalid frame"),
            Self::IncompatiblePeer => write!(f, "incompatible peer"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
        }
    }
}

impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_error_display() {
        assert_eq!(format!("{}", NetworkError::InvalidFrame), "invalid frame");
        assert_eq!(
            format!("{}", NetworkError::IncompatiblePeer),
            "incompatible peer"
        );
        assert_eq!(format!("{}", NetworkError::LimitExceeded), "limit exceeded");
    }

    #[test]
    fn network_error_is_error() {
        let err: &dyn std::error::Error = &NetworkError::InvalidFrame;
        assert_eq!(err.to_string(), "invalid frame");
    }
}
