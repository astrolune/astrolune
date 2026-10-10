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

/// Smallest finalized suffix an enabled retention policy may retain.
pub const MIN_RETAINED_BLOCKS: u64 = 8;
/// Largest finalized suffix an enabled retention policy may retain.
pub const MAX_RETAINED_BLOCKS: u64 = 64;
/// Finalized blocks retained by the default enabled retention policy.
pub const DEFAULT_RETAINED_BLOCKS: u64 = 32;
/// Smallest excess above the retained suffix that may trigger one compaction.
pub const MIN_RETENTION_INTERVAL_BLOCKS: u64 = 1;
/// Excess above the retained suffix used by the default retention policy.
pub const DEFAULT_RETENTION_INTERVAL_BLOCKS: u64 = 16;
/// Largest configurable excess above the retained suffix before one compaction.
pub const MAX_RETENTION_INTERVAL_BLOCKS: u64 = 65_536;
/// Smallest configurable byte budget for one compaction (16 MiB).
pub const MIN_COMPACTION_BYTES: u64 = 16_777_216;
/// Byte budget for one compaction used by the default retention policy (512 MiB).
pub const DEFAULT_COMPACTION_BYTES: u64 = 536_870_912;
/// Largest configurable byte budget for one compaction (8 GiB).
pub const MAX_COMPACTION_BYTES: u64 = 8_589_934_592;

/// Automated local history retention, disabled by default.
///
/// The defaults below are the numbers an enabled policy uses when the operator
/// states nothing else; `enabled` stays false, so a node that never configures
/// retention keeps every finalized block exactly as before. These bounds mirror
/// the storage engine's own retention bounds, which this crate cannot reference
/// because configuration deliberately depends on no other crate. This type
/// configures local disk occupancy only: it grants no authority to discard
/// history and it is not an independently held recovery pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRetentionConfig {
    /// Whether the node compacts its own finalized history after a commit.
    pub enabled: bool,
    /// Finalized blocks kept above the retained anchor.
    pub retained_blocks: u64,
    /// Excess finalized blocks required before one compaction runs.
    pub interval_blocks: u64,
    /// Maximum bytes one compaction may rewrite.
    pub max_compaction_bytes: u64,
}

impl Default for HistoryRetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retained_blocks: DEFAULT_RETAINED_BLOCKS,
            interval_blocks: DEFAULT_RETENTION_INTERVAL_BLOCKS,
            max_compaction_bytes: DEFAULT_COMPACTION_BYTES,
        }
    }
}

impl HistoryRetentionConfig {
    /// Checks every retention bound before any storage directory is opened.
    ///
    /// Bounds are checked whether or not retention is enabled, so a disabled
    /// policy carrying impossible numbers is still reported rather than ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidRetentionPolicy`] when a retained-block
    /// count, compaction interval or byte budget is outside its documented range.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.retained_blocks < MIN_RETAINED_BLOCKS || self.retained_blocks > MAX_RETAINED_BLOCKS
        {
            return Err(ConfigError::InvalidRetentionPolicy);
        }
        if self.interval_blocks < MIN_RETENTION_INTERVAL_BLOCKS
            || self.interval_blocks > MAX_RETENTION_INTERVAL_BLOCKS
        {
            return Err(ConfigError::InvalidRetentionPolicy);
        }
        if self.max_compaction_bytes < MIN_COMPACTION_BYTES
            || self.max_compaction_bytes > MAX_COMPACTION_BYTES
        {
            return Err(ConfigError::InvalidRetentionPolicy);
        }
        Ok(())
    }
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
        self.validate_with_retention(&HistoryRetentionConfig::default())
    }

    /// Checks structural bounds together with an explicit retention policy.
    ///
    /// Retention is validated separately from the four long-standing fields so
    /// that existing exhaustive `NodeConfig` literals keep compiling unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when an identifier, path, listener, peer bound or
    /// retention bound is invalid.
    pub fn validate_with_retention(
        &self,
        retention: &HistoryRetentionConfig,
    ) -> Result<(), ConfigError> {
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
        retention.validate()
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
    /// Retained-block count, compaction interval or byte budget is out of range.
    InvalidRetentionPolicy,
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigError, DEFAULT_COMPACTION_BYTES, DEFAULT_RETAINED_BLOCKS,
        DEFAULT_RETENTION_INTERVAL_BLOCKS, HistoryRetentionConfig, MAX_COMPACTION_BYTES,
        MAX_RETAINED_BLOCKS, MAX_RETENTION_INTERVAL_BLOCKS, MIN_COMPACTION_BYTES,
        MIN_RETAINED_BLOCKS, MIN_RETENTION_INTERVAL_BLOCKS, SecretRef,
    };

    #[test]
    fn debug_never_displays_secret_reference() {
        let secret = SecretRef::new("validator-primary").expect("valid reference");
        assert_eq!(format!("{secret:?}"), "SecretRef([REDACTED])");
    }

    #[test]
    fn default_retention_is_disabled_and_carries_every_documented_default() {
        let retention = HistoryRetentionConfig::default();
        assert!(!retention.enabled);
        assert_eq!(retention.retained_blocks, DEFAULT_RETAINED_BLOCKS);
        assert_eq!(retention.interval_blocks, DEFAULT_RETENTION_INTERVAL_BLOCKS);
        assert_eq!(retention.max_compaction_bytes, DEFAULT_COMPACTION_BYTES);
        assert_eq!(retention.validate(), Ok(()));
        const { assert!(DEFAULT_RETAINED_BLOCKS >= MIN_RETAINED_BLOCKS) };
        const { assert!(DEFAULT_RETAINED_BLOCKS <= MAX_RETAINED_BLOCKS) };
    }

    #[test]
    fn retention_validation_rejects_every_value_outside_its_documented_range() {
        for retained in [
            0,
            MIN_RETAINED_BLOCKS - 1,
            MAX_RETAINED_BLOCKS + 1,
            u64::MAX,
        ] {
            let retention = HistoryRetentionConfig {
                enabled: true,
                retained_blocks: retained,
                ..HistoryRetentionConfig::default()
            };
            assert_eq!(
                retention.validate(),
                Err(ConfigError::InvalidRetentionPolicy),
                "accepted retained_blocks {retained}"
            );
        }
        for interval in [
            MIN_RETENTION_INTERVAL_BLOCKS - 1,
            MAX_RETENTION_INTERVAL_BLOCKS + 1,
            u64::MAX,
        ] {
            let retention = HistoryRetentionConfig {
                enabled: true,
                interval_blocks: interval,
                ..HistoryRetentionConfig::default()
            };
            assert_eq!(
                retention.validate(),
                Err(ConfigError::InvalidRetentionPolicy),
                "accepted interval_blocks {interval}"
            );
        }
        for budget in [0, MIN_COMPACTION_BYTES - 1, MAX_COMPACTION_BYTES + 1] {
            let retention = HistoryRetentionConfig {
                enabled: true,
                max_compaction_bytes: budget,
                ..HistoryRetentionConfig::default()
            };
            assert_eq!(
                retention.validate(),
                Err(ConfigError::InvalidRetentionPolicy),
                "accepted max_compaction_bytes {budget}"
            );
        }
        // A disabled policy is still bounds-checked rather than silently ignored.
        let disabled = HistoryRetentionConfig {
            retained_blocks: 0,
            ..HistoryRetentionConfig::default()
        };
        assert_eq!(
            disabled.validate(),
            Err(ConfigError::InvalidRetentionPolicy)
        );
    }

    #[test]
    fn node_validation_reports_an_invalid_retention_policy() {
        let config = super::NodeConfig {
            chain_id: 7,
            data_dir: std::path::PathBuf::from("node-data"),
            validator_key: None,
            network: super::NetworkConfig {
                p2p_listen: "127.0.0.1:17330".into(),
                rpc_listen: "127.0.0.1:17331".into(),
                max_peers: 32,
            },
        };
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            config.validate_with_retention(&HistoryRetentionConfig {
                enabled: true,
                retained_blocks: MAX_RETAINED_BLOCKS + 1,
                ..HistoryRetentionConfig::default()
            }),
            Err(ConfigError::InvalidRetentionPolicy)
        );
        assert_eq!(
            config.validate_with_retention(&HistoryRetentionConfig {
                enabled: true,
                ..HistoryRetentionConfig::default()
            }),
            Ok(())
        );
    }
}
