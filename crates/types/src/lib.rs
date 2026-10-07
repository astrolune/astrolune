// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical, dependency-light protocol types shared by `AstroLune` components.

#![forbid(unsafe_code)]

pub mod account;
pub mod block;
pub mod domain;
pub mod hash;
pub mod resources;
pub mod state_key;
pub mod transaction;

pub use account::AccountState;
pub use block::{Block, BlockHeader, ExecutionReceipt};
pub use hash::Hash256;
pub use resources::Resources;
pub use state_key::StateKey;
pub use transaction::{TRANSACTION_VERSION, Transaction, TransactionLane};

/// A wallet or contract address.
pub use crate::address::Address;

/// A validator identity key.
pub use crate::address::ValidatorId;

pub mod address;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_unique() {
        let tags: &[&[u8]] = &[
            domain::TRANSACTION,
            domain::BLOCK_HEADER,
            domain::POTB_WEIGHT,
            domain::COMMITTEE,
            domain::FINALITY,
            domain::VRF_COMMITTEE,
            domain::VRF_PRODUCER,
            domain::GENESIS,
            domain::STATE_ROOT,
            domain::RECEIPT,
        ];

        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domain tags at indices {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn domain_tags_pairwise_unique() {
        let tags: &[&[u8]] = &[
            domain::TRANSACTION,
            domain::BLOCK_HEADER,
            domain::POTB_WEIGHT,
            domain::COMMITTEE,
            domain::FINALITY,
            domain::VRF_COMMITTEE,
            domain::VRF_PRODUCER,
            domain::GENESIS,
            domain::STATE_ROOT,
            domain::RECEIPT,
        ];
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "tags at {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn domain_tags_are_non_empty() {
        let tags: &[&[u8]] = &[
            domain::TRANSACTION,
            domain::BLOCK_HEADER,
            domain::POTB_WEIGHT,
            domain::COMMITTEE,
            domain::FINALITY,
            domain::VRF_COMMITTEE,
            domain::VRF_PRODUCER,
            domain::GENESIS,
            domain::STATE_ROOT,
            domain::RECEIPT,
        ];
        for tag in tags {
            assert_ne!(tag.len(), 0);
        }
    }

    #[test]
    fn domain_tags_start_with_protocol_name() {
        let tags: &[&[u8]] = &[
            domain::TRANSACTION,
            domain::BLOCK_HEADER,
            domain::POTB_WEIGHT,
            domain::COMMITTEE,
            domain::FINALITY,
            domain::VRF_COMMITTEE,
            domain::VRF_PRODUCER,
            domain::GENESIS,
            domain::STATE_ROOT,
            domain::RECEIPT,
        ];
        for tag in tags {
            assert!(
                tag.starts_with(b"astrolune."),
                "tag doesn't start with 'astrolune.': {tag:?}"
            );
        }
    }
}
