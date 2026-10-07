// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Cryptographic operation error types.

use std::fmt;

/// Errors produced by cryptographic operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The requested key does not exist in the keystore.
    KeyNotFound,
    /// A key with the same ID is already registered.
    DuplicateKey,
    /// The key has a different purpose than requested.
    WrongPurpose,
    /// Equivocation detected: signing conflicting messages at the same position.
    EquivocationDetected,
    /// Signature verification failed.
    InvalidSignature,
    /// VRF proof, encoding, or claimed output is invalid.
    InvalidVrfProof,
    /// Public key is malformed or has weak order.
    InvalidPublicKey,
    /// Key derivation failed due to invalid seed material.
    InvalidSeed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "key not found"),
            Self::DuplicateKey => write!(f, "duplicate key"),
            Self::WrongPurpose => write!(f, "wrong purpose"),
            Self::EquivocationDetected => write!(f, "equivocation detected"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidVrfProof => write!(f, "invalid VRF proof"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSeed => write!(f, "invalid seed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(CryptoError::KeyNotFound.to_string(), "key not found");
        assert_eq!(CryptoError::DuplicateKey.to_string(), "duplicate key");
        assert_eq!(CryptoError::WrongPurpose.to_string(), "wrong purpose");
        assert_eq!(
            CryptoError::EquivocationDetected.to_string(),
            "equivocation detected"
        );
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "invalid signature"
        );
        assert_eq!(CryptoError::InvalidSeed.to_string(), "invalid seed");
    }

    #[test]
    fn error_is_std_error() {
        let err: &dyn std::error::Error = &CryptoError::KeyNotFound;
        assert_eq!(err.to_string(), "key not found");
    }
}
