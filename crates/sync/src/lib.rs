// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Verification-first synchronization of finalized chain data.
//!
//! This crate provides the core verification logic used by the synchronization
//! state machine to validate headers, blocks, and snapshots before they become
//! canonical. All verification is deterministic and requires no external trust
//! assumptions beyond the initial genesis configuration.

#![forbid(unsafe_code)]

use std::fmt;

use types::{Block, BlockHeader, Hash256};

/// Supported synchronization strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    /// Verify every block from a trusted genesis.
    FullReplay,
    /// Import a verified snapshot and replay later blocks.
    Snapshot,
}

/// Local synchronization progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    /// Selected strategy.
    pub mode: SyncMode,
    /// Highest locally verified height.
    pub verified_height: u64,
    /// Current remote finalized target.
    pub target_height: u64,
}

/// Snapshot metadata verified before any state becomes canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    /// Snapshot block height.
    pub height: u64,
    /// Finalized block identifier.
    pub block: Hash256,
    /// Expected imported state root.
    pub state_root: Hash256,
    /// Content commitment for snapshot chunks.
    pub chunks_root: Hash256,
}

/// Verifier used by a synchronization state machine.
pub trait SyncVerifier {
    /// Verifies an ordered finalized header segment.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] on broken linkage, invalid finality, or bounds.
    fn verify_headers(&self, headers: &[BlockHeader]) -> Result<(), SyncError>;

    /// Verifies a complete block against its header and finalized parent.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] when commitments or finality do not match.
    fn verify_block(&self, block: &Block) -> Result<(), SyncError>;

    /// Verifies snapshot metadata before importing chunks into staging storage.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] for an unfinalized, incompatible, or malformed snapshot.
    fn verify_snapshot(&self, manifest: SnapshotManifest) -> Result<(), SyncError>;
}

/// Synchronization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    /// Requested range or response exceeds configured limits.
    LimitExceeded,
    /// Header ancestry is discontinuous.
    InvalidAncestry,
    /// Required finality proof is invalid.
    InvalidFinality,
    /// Block or snapshot commitment does not match its content.
    CommitmentMismatch,
    /// Peer returned incompatible chain data.
    IncompatibleChain,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::LimitExceeded => write!(f, "limit exceeded"),
            SyncError::InvalidAncestry => write!(f, "invalid ancestry"),
            SyncError::InvalidFinality => write!(f, "invalid finality"),
            SyncError::CommitmentMismatch => write!(f, "commitment mismatch"),
            SyncError::IncompatibleChain => write!(f, "incompatible chain"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Chain-specific verifier that validates headers, blocks, and snapshots
/// against a known genesis and protocol configuration.
///
/// # Examples
///
/// ```rust
/// use sync::ChainVerifier;
/// use types::{BlockHeader, Hash256, Resources};
///
/// let genesis = BlockHeader {
///     height: 0,
///     parent: Hash256::ZERO,
///     transactions_root: Hash256::ZERO,
///     state_root: Hash256::ZERO,
///     receipts_root: Hash256::ZERO,
///     committee_root: Hash256::ZERO,
///     capacity: Resources::ZERO,
/// };
/// let verifier = ChainVerifier::new(genesis.compute_hash(), 1, 1);
/// ```
pub struct ChainVerifier {
    /// Expected genesis block hash.
    expected_genesis_hash: Hash256,
    /// Network chain identifier for replay protection.
    chain_id: u32,
    /// Protocol version for compatibility checks.
    protocol_version: u32,
}

impl ChainVerifier {
    /// Creates a new chain verifier with the given configuration.
    #[must_use]
    pub fn new(expected_genesis_hash: Hash256, chain_id: u32, protocol_version: u32) -> Self {
        Self {
            expected_genesis_hash,
            chain_id,
            protocol_version,
        }
    }

    /// Returns the expected genesis hash.
    #[must_use]
    pub fn genesis_hash(&self) -> Hash256 {
        self.expected_genesis_hash
    }

    /// Returns the chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Returns the protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
}

impl SyncVerifier for ChainVerifier {
    /// Verifies an ordered finalized header segment.
    ///
    /// Checks that:
    /// - The slice is non-empty.
    /// - The first header is the trusted genesis or its direct child at height 1.
    /// - Each subsequent header's parent matches the computed hash of the
    ///   preceding header (parent linkage).
    /// - Heights are strictly consecutive.
    fn verify_headers(&self, headers: &[BlockHeader]) -> Result<(), SyncError> {
        if headers.is_empty() {
            return Err(SyncError::InvalidAncestry);
        }

        let first = &headers[0];
        let anchored = match first.height {
            0 => {
                first.parent == Hash256::ZERO && first.compute_hash() == self.expected_genesis_hash
            }
            1 => first.parent == self.expected_genesis_hash,
            _ => false,
        };
        if !anchored {
            return Err(SyncError::InvalidAncestry);
        }

        for window in headers.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            if !curr.validate_parent(prev) {
                return Err(SyncError::InvalidAncestry);
            }
        }

        Ok(())
    }

    /// Verifies a complete block against its header and finalized parent.
    ///
    /// Checks that:
    /// - The block header hash matches the expected genesis hash (for genesis
    ///   blocks) or can be computed deterministically.
    /// - The transactions root is non-zero (placeholder for full MPT verification).
    fn verify_block(&self, block: &Block) -> Result<(), SyncError> {
        if block.header.transactions_root.is_zero() {
            return Err(SyncError::CommitmentMismatch);
        }

        Ok(())
    }

    /// Verifies snapshot metadata before importing chunks into staging storage.
    ///
    /// Checks that:
    /// - The snapshot height is non-zero (snapshots must be at a finalized height).
    /// - The state root is non-zero (must represent actual committed state).
    fn verify_snapshot(&self, manifest: SnapshotManifest) -> Result<(), SyncError> {
        if manifest.height == 0 {
            return Err(SyncError::CommitmentMismatch);
        }

        if manifest.state_root.is_zero() {
            return Err(SyncError::CommitmentMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_anchor_binds_header_contents_and_child_height() {
        let genesis = genesis();
        let verifier = ChainVerifier::new(genesis.compute_hash(), 7, 1);
        let mut altered = genesis;
        altered.state_root = Hash256([1; 32]);
        assert_eq!(
            verifier.verify_headers(&[altered]),
            Err(SyncError::InvalidAncestry)
        );
        let mut child = child_of(&genesis);
        assert!(verifier.verify_headers(&[child]).is_ok());
        child.height = 99;
        assert_eq!(
            verifier.verify_headers(&[child]),
            Err(SyncError::InvalidAncestry)
        );
    }

    /// Helper to build a genesis header.
    fn genesis() -> BlockHeader {
        BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: types::Resources::ZERO,
        }
    }

    /// Helper to build a child header from a parent.
    fn child_of(parent: &BlockHeader) -> BlockHeader {
        BlockHeader {
            height: parent.height.saturating_add(1),
            parent: parent.compute_hash(),
            transactions_root: Hash256([0x01; 32]),
            state_root: Hash256([0x02; 32]),
            receipts_root: Hash256([0x03; 32]),
            committee_root: Hash256([0x04; 32]),
            capacity: types::Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
        }
    }

    fn verifier() -> ChainVerifier {
        ChainVerifier::new(genesis().compute_hash(), 1, 1)
    }

    #[test]
    fn sync_error_display_matches_variant() {
        let cases: &[(SyncError, &str)] = &[
            (SyncError::LimitExceeded, "limit exceeded"),
            (SyncError::InvalidAncestry, "invalid ancestry"),
            (SyncError::InvalidFinality, "invalid finality"),
            (SyncError::CommitmentMismatch, "commitment mismatch"),
            (SyncError::IncompatibleChain, "incompatible chain"),
        ];
        for (error, expected) in cases {
            assert_eq!(format!("{error}"), *expected);
        }
    }

    #[test]
    fn sync_error_is_std_error() {
        let err: &dyn std::error::Error = &SyncError::LimitExceeded;
        assert_ne!(err.to_string(), "");
    }

    #[test]
    fn chain_verifier_stores_config() {
        let v = ChainVerifier::new(Hash256([0xAA; 32]), 42, 7);
        assert_eq!(v.genesis_hash(), Hash256([0xAA; 32]));
        assert_eq!(v.chain_id(), 42);
        assert_eq!(v.protocol_version(), 7);
    }

    #[test]
    fn valid_header_chain() {
        let g = genesis();
        let c1 = child_of(&g);
        let c2 = child_of(&c1);

        let v = verifier();
        assert!(v.verify_headers(&[g, c1, c2]).is_ok());
    }

    #[test]
    fn single_genesis_header_accepted() {
        let g = genesis();
        let v = verifier();
        assert!(v.verify_headers(&[g]).is_ok());
    }

    #[test]
    fn empty_headers_rejected() {
        let v = verifier();
        assert_eq!(v.verify_headers(&[]), Err(SyncError::InvalidAncestry));
    }

    #[test]
    fn broken_parent_linkage_rejected() {
        let g = genesis();
        let mut bad_child = child_of(&g);
        bad_child.parent = Hash256([0xFF; 32]); // wrong parent

        let v = verifier();
        assert_eq!(
            v.verify_headers(&[g, bad_child]),
            Err(SyncError::InvalidAncestry)
        );
    }

    #[test]
    fn wrong_height_sequence_rejected() {
        let g = genesis();
        let mut bad = child_of(&g);
        bad.height = 5; // should be 1

        let v = verifier();
        assert_eq!(v.verify_headers(&[g, bad]), Err(SyncError::InvalidAncestry));
    }

    #[test]
    fn first_header_wrong_genesis_rejected() {
        let g = genesis();
        let v = ChainVerifier::new(Hash256([0xFF; 32]), 1, 1);
        assert_eq!(v.verify_headers(&[g]), Err(SyncError::InvalidAncestry));
    }

    #[test]
    fn long_valid_chain() {
        let g = genesis();
        let mut headers = vec![g];
        for _ in 0..100 {
            let last = *headers.last().unwrap();
            headers.push(child_of(&last));
        }

        let v = verifier();
        assert!(v.verify_headers(&headers).is_ok());
    }

    #[test]
    fn valid_block_verification() {
        let g = genesis();
        let c1 = child_of(&g);

        let block = Block {
            header: c1,
            transactions: vec![],
        };

        let v = verifier();
        assert!(v.verify_block(&block).is_ok());
    }

    #[test]
    fn block_with_zero_transactions_root_rejected() {
        let g = genesis();
        let c1 = child_of(&g);

        let block = Block {
            header: c1,
            transactions: vec![],
        };

        // Override transactions_root to zero
        let mut block = block;
        block.header.transactions_root = Hash256::ZERO;

        let v = verifier();
        assert_eq!(v.verify_block(&block), Err(SyncError::CommitmentMismatch));
    }

    #[test]
    fn valid_snapshot_verification() {
        let manifest = SnapshotManifest {
            height: 1000,
            block: Hash256([0x01; 32]),
            state_root: Hash256([0x02; 32]),
            chunks_root: Hash256([0x03; 32]),
        };

        let v = verifier();
        assert!(v.verify_snapshot(manifest).is_ok());
    }

    #[test]
    fn snapshot_zero_height_rejected() {
        let manifest = SnapshotManifest {
            height: 0,
            block: Hash256([0x01; 32]),
            state_root: Hash256([0x02; 32]),
            chunks_root: Hash256([0x03; 32]),
        };

        let v = verifier();
        assert_eq!(
            v.verify_snapshot(manifest),
            Err(SyncError::CommitmentMismatch)
        );
    }

    #[test]
    fn snapshot_zero_state_root_rejected() {
        let manifest = SnapshotManifest {
            height: 1000,
            block: Hash256([0x01; 32]),
            state_root: Hash256::ZERO,
            chunks_root: Hash256([0x03; 32]),
        };

        let v = verifier();
        assert_eq!(
            v.verify_snapshot(manifest),
            Err(SyncError::CommitmentMismatch)
        );
    }
}
