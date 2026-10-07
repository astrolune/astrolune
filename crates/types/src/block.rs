// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical block header, block, and execution receipt types.

use crate::hash::Hash256;
use crate::resources::Resources;
use crate::transaction::Transaction;

/// A canonical block header independent of the execution implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    /// Monotonic chain height.
    pub height: u64,
    /// Previous finalized block.
    pub parent: Hash256,
    /// Ordered transaction commitment.
    pub transactions_root: Hash256,
    /// Post-execution state commitment.
    pub state_root: Hash256,
    /// Receipts commitment.
    pub receipts_root: Hash256,
    /// Committee selected for this height.
    pub committee_root: Hash256,
    /// Finalized adaptive capacity applicable to this block.
    pub capacity: Resources,
}

impl BlockHeader {
    /// Validates structural invariants of this header against its parent.
    ///
    /// Checks:
    /// - Height is exactly one greater than the parent's
    /// - Parent hash is not zero (except for genesis at height 0)
    /// - Capacity resources are non-negative (always true for u64)
    ///
    /// This does **not** verify signatures or state roots; those require
    /// access to the validator set and state database.
    #[must_use]
    pub fn validate_parent(&self, parent: &BlockHeader) -> bool {
        parent.height.checked_add(1) == Some(self.height)
            && self.parent == Self::compute_hash(parent)
    }

    /// Computes a deterministic hash of this block header.
    ///
    /// The hash covers height, parent, transaction/state/receipts/committee
    /// roots, and capacity. This is used for parent linkage checks and
    /// lightweight identification.
    #[must_use]
    pub fn compute_hash(&self) -> Hash256 {
        crate::hash::domain_hash(crate::domain::BLOCK_HEADER, &self.canonical_bytes())
    }

    /// Returns the fixed-width canonical header representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 200] {
        let mut data = [0u8; 200];
        data[0..8].copy_from_slice(&self.height.to_le_bytes());
        data[8..40].copy_from_slice(&self.parent.0);
        data[40..72].copy_from_slice(&self.transactions_root.0);
        data[72..104].copy_from_slice(&self.state_root.0);
        data[104..136].copy_from_slice(&self.receipts_root.0);
        data[136..168].copy_from_slice(&self.committee_root.0);
        data[168..176].copy_from_slice(&self.capacity.compute.to_le_bytes());
        data[176..184].copy_from_slice(&self.capacity.memory.to_le_bytes());
        data[184..192].copy_from_slice(&self.capacity.io.to_le_bytes());
        data[192..200].copy_from_slice(&self.capacity.bandwidth.to_le_bytes());
        data
    }
}

/// An ordered block proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Consensus and execution commitments.
    pub header: BlockHeader,
    /// Transactions in the exact order fixed by consensus.
    pub transactions: Vec<Transaction>,
}

/// A state transition result that can be checked without trusting an optimizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    /// Transaction identifier.
    pub transaction: Hash256,
    /// Whether contract execution committed its changes.
    pub succeeded: bool,
    /// Actual metered resources.
    pub resources: Resources,
    /// Hash of emitted events and return data.
    pub output_root: Hash256,
}

impl ExecutionReceipt {
    /// Computes a deterministic commitment hash for this receipt.
    ///
    /// The commitment binds the transaction ID, success flag, resource
    /// consumption, and output root into a single hash suitable for
    /// inclusion in the block header receipts root.
    #[must_use]
    pub fn commitment(&self) -> Hash256 {
        crate::hash::domain_hash(crate::domain::RECEIPT, &self.canonical_bytes())
    }

    /// Returns the fixed-width canonical receipt representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 97] {
        let mut data = [0u8; 97];
        data[0..32].copy_from_slice(&self.transaction.0);
        data[32] = u8::from(self.succeeded);
        data[33..41].copy_from_slice(&self.resources.compute.to_le_bytes());
        data[41..49].copy_from_slice(&self.resources.memory.to_le_bytes());
        data[49..57].copy_from_slice(&self.resources.io.to_le_bytes());
        data[57..65].copy_from_slice(&self.resources.bandwidth.to_le_bytes());
        data[65..97].copy_from_slice(&self.output_root.0);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::Resources;

    #[test]
    fn block_header_hash_deterministic() {
        let header = BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
        };
        let h1 = header.compute_hash();
        let h2 = header.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn block_header_validate_parent_passes() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let genesis_hash = genesis.compute_hash();

        let child = BlockHeader {
            height: 1,
            parent: genesis_hash,
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: Resources {
                compute: 100,
                memory: 0,
                io: 0,
                bandwidth: 0,
            },
        };

        assert!(child.validate_parent(&genesis));
    }

    #[test]
    fn block_header_validate_parent_rejects_wrong_height() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let genesis_hash = genesis.compute_hash();

        let bad = BlockHeader {
            height: 5,
            parent: genesis_hash,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        assert!(!bad.validate_parent(&genesis));
    }

    #[test]
    fn block_header_validate_parent_rejects_wrong_parent_hash() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        let bad_child = BlockHeader {
            height: 1,
            parent: Hash256([0xFF; 32]),
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        assert!(!bad_child.validate_parent(&genesis));
    }

    #[test]
    fn block_header_hash_deterministic_across_many_values() {
        for h in [0, 1, 42, 1000, u64::MAX] {
            let header = BlockHeader {
                height: h,
                parent: Hash256([0xAA; 32]),
                transactions_root: Hash256([1u8; 32]),
                state_root: Hash256([2u8; 32]),
                receipts_root: Hash256([3u8; 32]),
                committee_root: Hash256([4u8; 32]),
                capacity: Resources {
                    compute: 100,
                    memory: 200,
                    io: 300,
                    bandwidth: 400,
                },
            };
            let h1 = header.compute_hash();
            let h2 = header.compute_hash();
            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn block_header_hash_differs_by_height() {
        let make = |height| BlockHeader {
            height,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        assert_ne!(make(0).compute_hash(), make(1).compute_hash());
    }

    #[test]
    fn block_header_hash_differs_by_parent() {
        let make = |parent| BlockHeader {
            height: 1,
            parent,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        assert_ne!(
            make(Hash256([0; 32])).compute_hash(),
            make(Hash256([1; 32])).compute_hash()
        );
    }

    #[test]
    fn receipt_commitment_deterministic() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources {
                compute: 10,
                memory: 20,
                io: 30,
                bandwidth: 40,
            },
            output_root: Hash256([2u8; 32]),
        };
        let c1 = receipt.commitment();
        let c2 = receipt.commitment();
        assert_eq!(c1, c2);
    }

    #[test]
    fn receipt_commitment_differs_on_success() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.succeeded = false;
        assert_ne!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn receipt_commitment_differs_on_resources() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources {
                compute: 10,
                memory: 0,
                io: 0,
                bandwidth: 0,
            },
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.resources.compute = 20;
        assert_ne!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn receipt_commitment_deterministic_across_variations() {
        for succeeded in [true, false] {
            for compute in [0, 1, u64::MAX] {
                let receipt = ExecutionReceipt {
                    transaction: Hash256([1u8; 32]),
                    succeeded,
                    resources: Resources {
                        compute,
                        memory: 0,
                        io: 0,
                        bandwidth: 0,
                    },
                    output_root: Hash256::ZERO,
                };
                let c1 = receipt.commitment();
                let c2 = receipt.commitment();
                assert_eq!(c1, c2);
            }
        }
    }

    #[test]
    fn receipt_commitment_differs_on_success_flag() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.succeeded = false;
        assert_ne!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn receipt_commitment_differs_on_transaction() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.transaction = Hash256([2u8; 32]);
        assert_ne!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn receipt_commitment_differs_on_output_root() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.output_root = Hash256([0xFF; 32]);
        assert_ne!(r1.commitment(), r2.commitment());
    }
}
