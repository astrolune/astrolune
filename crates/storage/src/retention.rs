// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded automated retention policy and its durable local compaction record.
//!
//! A policy chooses only which locally authenticated suffix stays on disk. It
//! never authenticates finality, never establishes an independent trust pin, and
//! never authorizes importing a shortened history produced by another writer.

use crate::StorageError;
use types::{Hash256, hash::domain_hash};

/// Smallest finalized suffix an enabled policy may retain above its anchor.
pub const MIN_RETAINED_BLOCKS: u64 = 8;
/// Largest finalized suffix an enabled policy may retain; the recent state index bound.
pub const MAX_RETAINED_BLOCKS: u64 = crate::MAX_STATE_HISTORY_BLOCKS as u64;
/// Finalized suffix retained by [`RetentionPolicy::default_bounded`].
pub const DEFAULT_RETAINED_BLOCKS: u64 = 32;
/// Smallest excess above the retained suffix that triggers one compaction.
pub const MIN_COMPACTION_INTERVAL_BLOCKS: u64 = 1;
/// Excess above the retained suffix used by [`RetentionPolicy::default_bounded`].
pub const DEFAULT_COMPACTION_INTERVAL_BLOCKS: u64 = 16;
/// Largest configurable excess above the retained suffix before one compaction.
pub const MAX_COMPACTION_INTERVAL_BLOCKS: u64 = 65_536;
/// Smallest configurable byte budget for one compaction (16 MiB).
pub const MIN_COMPACTION_BYTES: u64 = 16 * 1024 * 1024;
/// Byte budget for one compaction used by [`RetentionPolicy::default_bounded`] (512 MiB).
pub const DEFAULT_COMPACTION_BYTES: u64 = 512 * 1024 * 1024;
/// Largest configurable byte budget for one compaction (8 GiB).
pub const MAX_COMPACTION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Exact bytes of one durable retention record.
pub(crate) const RETENTION_RECORD_BYTES: usize = 120;
const RETENTION_MAGIC: &[u8; 8] = b"ASTRET01";
const RETENTION_DOMAIN: &[u8] = b"astrolune.storage.retention.v1";

/// Automated in-place retention policy.
///
/// The default retains every finalized block, which is the behaviour of a node
/// that never configures retention. An enabled policy states how many finalized
/// blocks stay above the anchor, how much excess must accumulate before one
/// compaction runs, and how many bytes one compaction may rewrite. A policy
/// establishes no trust: it cannot authorize discarding history that this writer
/// did not itself authenticate and publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    retained_blocks: u64,
    interval_blocks: u64,
    max_compaction_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RetentionPolicy {
    /// Retains every finalized block and never compacts.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            retained_blocks: 0,
            interval_blocks: 0,
            max_compaction_bytes: 0,
        }
    }

    /// Enabled policy using every documented default.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self {
            retained_blocks: DEFAULT_RETAINED_BLOCKS,
            interval_blocks: DEFAULT_COMPACTION_INTERVAL_BLOCKS,
            max_compaction_bytes: DEFAULT_COMPACTION_BYTES,
        }
    }

    /// Enabled policy checked against every documented bound.
    pub const fn bounded(
        retained_blocks: u64,
        interval_blocks: u64,
        max_compaction_bytes: u64,
    ) -> Result<Self, StorageError> {
        if retained_blocks < MIN_RETAINED_BLOCKS
            || retained_blocks > MAX_RETAINED_BLOCKS
            || interval_blocks < MIN_COMPACTION_INTERVAL_BLOCKS
            || interval_blocks > MAX_COMPACTION_INTERVAL_BLOCKS
            || max_compaction_bytes < MIN_COMPACTION_BYTES
            || max_compaction_bytes > MAX_COMPACTION_BYTES
        {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            retained_blocks,
            interval_blocks,
            max_compaction_bytes,
        })
    }

    /// Whether automatic compaction runs after a commit.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.retained_blocks != 0
    }

    /// Finalized blocks retained above the anchor; zero when disabled.
    #[must_use]
    pub const fn retained_blocks(&self) -> u64 {
        self.retained_blocks
    }

    /// Excess finalized blocks required before one compaction runs.
    #[must_use]
    pub const fn interval_blocks(&self) -> u64 {
        self.interval_blocks
    }

    /// Bytes one compaction may rewrite before refusing.
    #[must_use]
    pub const fn max_compaction_bytes(&self) -> u64 {
        self.max_compaction_bytes
    }

    /// Anchor height one compaction would move to, or `None` when none is due.
    ///
    /// A returned floor is strictly above `floor` and strictly below `head`, so a
    /// due compaction always advances and always keeps `retained_blocks` bodies.
    #[must_use]
    pub const fn target_floor(&self, floor: u64, head: u64) -> Option<u64> {
        if self.retained_blocks == 0 {
            return None;
        }
        let Some(span) = head.checked_sub(floor) else {
            return None;
        };
        let Some(excess) = span.checked_sub(self.retained_blocks) else {
            return None;
        };
        if excess < self.interval_blocks {
            return None;
        }
        let target = head - self.retained_blocks;
        if target == 0 { None } else { Some(target) }
    }
}

/// Observed retention position and the result of the last automatic evaluation.
///
/// These numbers describe local disk occupancy only. They are not a finality
/// claim and never state that an absent height was never finalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionState {
    /// Policy currently installed on this backend.
    pub policy: RetentionPolicy,
    /// Height of the oldest retained checkpoint; bodies start one height above it.
    pub retained_floor: Option<u64>,
    /// Lowest height whose exact state the bounded reverse index can still rebuild.
    pub history_floor: Option<u64>,
    /// Whether this directory carries a durable record of its own compaction.
    pub self_compacted: bool,
    /// Completed in-place compactions recorded in this directory.
    pub compactions: u64,
    /// Last automatic evaluation failure; the commit that preceded it still published.
    pub last_error: Option<StorageError>,
}

/// Durable local record that this writer shortened its own history.
///
/// The record is a local continuity marker, not an authority. It proves nothing
/// to another party and replaces no independently held recovery pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetentionRecord {
    /// Highest anchor height this directory has ever compacted to.
    pub(crate) floor: u64,
    /// Completed compactions, used only for operator reporting.
    pub(crate) compactions: u64,
    /// Block identifier of the anchor written by the latest compaction.
    pub(crate) block: Hash256,
    /// State root of the anchor written by the latest compaction.
    pub(crate) state_root: Hash256,
}

impl RetentionRecord {
    /// Exact canonical bytes; contains no snapshot data and no secret material.
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut bytes = RETENTION_MAGIC.to_vec();
        bytes.extend_from_slice(&self.floor.to_le_bytes());
        bytes.extend_from_slice(&self.compactions.to_le_bytes());
        bytes.extend_from_slice(self.block.as_bytes());
        bytes.extend_from_slice(self.state_root.as_bytes());
        let checksum = domain_hash(RETENTION_DOMAIN, &bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        bytes
    }

    /// Parses a complete self-checksummed record; a torn record is rejected.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != RETENTION_RECORD_BYTES
            || &bytes[..8] != RETENTION_MAGIC
            || domain_hash(RETENTION_DOMAIN, &bytes[..88]).as_bytes() != &bytes[88..]
        {
            return Err(StorageError::Corrupt);
        }
        let number = |at: usize| -> Result<u64, StorageError> {
            bytes[at..at + 8]
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| StorageError::Corrupt)
        };
        let hash = |at: usize| -> Result<Hash256, StorageError> {
            bytes[at..at + 32]
                .try_into()
                .map(Hash256)
                .map_err(|_| StorageError::Corrupt)
        };
        let record = Self {
            floor: number(8)?,
            compactions: number(16)?,
            block: hash(24)?,
            state_root: hash(56)?,
        };
        if record.floor == 0 || record.compactions == 0 || record.block.is_zero() {
            return Err(StorageError::Corrupt);
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_policy_never_selects_a_floor_at_any_head_height() {
        let policy = RetentionPolicy::disabled();
        assert!(!policy.is_enabled());
        for head in 0..512u64 {
            assert_eq!(
                policy.target_floor(0, head),
                None,
                "disabled policy selected a floor at head {head}"
            );
        }
    }

    #[test]
    fn a_bounded_policy_rejects_every_value_outside_its_documented_range() {
        for retained in [0, MIN_RETAINED_BLOCKS - 1, MAX_RETAINED_BLOCKS + 1] {
            assert_eq!(
                RetentionPolicy::bounded(
                    retained,
                    DEFAULT_COMPACTION_INTERVAL_BLOCKS,
                    DEFAULT_COMPACTION_BYTES
                ),
                Err(StorageError::LimitExceeded),
                "accepted retained_blocks {retained}"
            );
        }
        for interval in [0, MAX_COMPACTION_INTERVAL_BLOCKS + 1] {
            assert_eq!(
                RetentionPolicy::bounded(
                    DEFAULT_RETAINED_BLOCKS,
                    interval,
                    DEFAULT_COMPACTION_BYTES
                ),
                Err(StorageError::LimitExceeded),
                "accepted interval_blocks {interval}"
            );
        }
        for budget in [0, MIN_COMPACTION_BYTES - 1, MAX_COMPACTION_BYTES + 1] {
            assert_eq!(
                RetentionPolicy::bounded(
                    DEFAULT_RETAINED_BLOCKS,
                    DEFAULT_COMPACTION_INTERVAL_BLOCKS,
                    budget
                ),
                Err(StorageError::LimitExceeded),
                "accepted max_compaction_bytes {budget}"
            );
        }
        assert_eq!(
            RetentionPolicy::bounded(
                DEFAULT_RETAINED_BLOCKS,
                DEFAULT_COMPACTION_INTERVAL_BLOCKS,
                DEFAULT_COMPACTION_BYTES
            ),
            Ok(RetentionPolicy::default_bounded())
        );
        assert_eq!(RetentionPolicy::default(), RetentionPolicy::disabled());
    }

    #[test]
    fn a_due_floor_always_advances_and_always_keeps_the_retained_suffix() {
        let policy = RetentionPolicy::bounded(MIN_RETAINED_BLOCKS, 1, MIN_COMPACTION_BYTES)
            .expect("bounded policy");
        for head in 0..=MIN_RETAINED_BLOCKS {
            assert_eq!(
                policy.target_floor(0, head),
                None,
                "compacted below the retained suffix at head {head}"
            );
        }
        for head in MIN_RETAINED_BLOCKS + 1..256 {
            let floor = policy
                .target_floor(0, head)
                .unwrap_or_else(|| panic!("no floor selected at head {head}"));
            assert_eq!(
                floor,
                head - MIN_RETAINED_BLOCKS,
                "wrong floor at head {head}"
            );
            assert!(
                floor > 0 && floor < head,
                "floor out of range at head {head}"
            );
            assert_eq!(
                policy.target_floor(floor, head),
                None,
                "repeated evaluation at head {head} compacted twice"
            );
        }
    }

    #[test]
    fn an_interval_defers_compaction_until_the_excess_accumulates() {
        let policy = RetentionPolicy::bounded(MIN_RETAINED_BLOCKS, 4, MIN_COMPACTION_BYTES)
            .expect("bounded policy");
        let floor = 100;
        for excess in 0..4 {
            assert_eq!(
                policy.target_floor(floor, floor + MIN_RETAINED_BLOCKS + excess),
                None,
                "compacted with excess {excess} below the configured interval"
            );
        }
        assert_eq!(
            policy.target_floor(floor, floor + MIN_RETAINED_BLOCKS + 4),
            Some(floor + 4)
        );
    }

    #[test]
    fn a_retention_record_rejects_truncation_and_every_single_byte_mutation() {
        let record = RetentionRecord {
            floor: 97,
            compactions: 3,
            block: Hash256([5; 32]),
            state_root: Hash256([6; 32]),
        };
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), RETENTION_RECORD_BYTES);
        assert_eq!(RetentionRecord::from_bytes(&bytes), Ok(record));
        for at in 0..bytes.len() {
            assert_eq!(
                RetentionRecord::from_bytes(&bytes[..at]),
                Err(StorageError::Corrupt),
                "accepted a record truncated at {at}"
            );
            for mask in [1u8, 128, 255] {
                let mut mutated = bytes.clone();
                mutated[at] ^= mask;
                assert_eq!(
                    RetentionRecord::from_bytes(&mutated),
                    Err(StorageError::Corrupt),
                    "accepted byte {at} mutated by {mask}"
                );
            }
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            RetentionRecord::from_bytes(&trailing),
            Err(StorageError::Corrupt)
        );
    }
}
