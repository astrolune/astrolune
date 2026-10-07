// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Layered, validated configuration without embedded secret values.

#![forbid(unsafe_code)]

use core::fmt;
use std::path::PathBuf;

/// A reference to a secret managed outside ordinary configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretRef(String);

impl SecretRef {
    /// Creates a non-empty secret reference such as a keystore handle.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidSecretReference`] for an empty or whitespace value.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ConfigError::InvalidSecretReference);
        }
        Ok(Self(value))
    }

    /// Exposes the reference identifier, never secret key bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRef([REDACTED])")
    }
}

/// Node network listener configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Binary peer listener address.
    pub p2p_listen: String,
    /// External `RPC` listener address.
    pub rpc_listen: String,
    /// Maximum simultaneous peers.
    pub max_peers: usize,
}

/// Top-level daemon configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    /// Expected chain identifier.
    pub chain_id: u32,
    /// Directory for validator-local chain state.
    pub data_dir: PathBuf,
    /// Consensus signer reference.
    pub validator_key: Option<SecretRef>,
    /// Listener and peer bounds.
    pub network: NetworkConfig,
}

impl NodeConfig {
    /// Checks safe structural bounds before any listener or storage is opened.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when an identifier, path, listener, or peer bound is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.chain_id == 0 {
            return Err(ConfigError::InvalidChainId);
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::InvalidDataDirectory);
        }
        if self.network.p2p_listen.trim().is_empty() || self.network.rpc_listen.trim().is_empty() {
            return Err(ConfigError::InvalidListener);
        }
        if self.network.p2p_listen == self.network.rpc_listen {
            return Err(ConfigError::ListenerConflict);
        }
        if self.network.max_peers == 0 {
            return Err(ConfigError::InvalidPeerLimit);
        }
        Ok(())
    }
}

/// Configuration validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Chain identifier is reserved or missing.
    InvalidChainId,
    /// Persistent state directory is missing.
    InvalidDataDirectory,
    /// Listener address is empty.
    InvalidListener,
    /// Peer and external `RPC` listeners collide.
    ListenerConflict,
    /// Peer limit is zero.
    InvalidPeerLimit,
    /// Secret reference is empty.
    InvalidSecretReference,
}

#[cfg(test)]
mod tests {
    use super::SecretRef;

    #[test]
    fn debug_never_displays_secret_reference() {
        let secret = SecretRef::new("validator-primary").expect("valid reference");
        assert_eq!(format!("{secret:?}"), "SecretRef([REDACTED])");
    }
}
