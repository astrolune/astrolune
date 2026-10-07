// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Binary protocol message kinds and compact-block reconstruction.

use std::collections::BTreeMap;

use types::{BlockHeader, Hash256, Transaction};

/// Binary protocol message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    /// Negotiates chain, protocol version, and capabilities.
    Hello = 0,
    /// Announces transaction identifiers.
    Transactions = 1,
    /// Announces a compact block.
    CompactBlock = 2,
    /// Carries a consensus proposal.
    Proposal = 3,
    /// Carries a prevote or precommit.
    Vote = 4,
    /// Carries a finality certificate.
    Finality = 5,
}

impl MessageKind {
    /// Attempts to convert a raw discriminant byte into a [`MessageKind`].
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Hello),
            1 => Some(Self::Transactions),
            2 => Some(Self::CompactBlock),
            3 => Some(Self::Proposal),
            4 => Some(Self::Vote),
            5 => Some(Self::Finality),
            _ => None,
        }
    }
}

/// Compact block reconstructed from transactions likely present in the mempool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    /// Full header required before reconstruction.
    pub header: BlockHeader,
    /// Short identifiers in committed transaction order.
    pub short_ids: Vec<u64>,
    /// Transactions the sender predicts the receiver does not have.
    pub prefilled: Vec<(usize, Transaction)>,
}

impl CompactBlock {
    /// Attempts to reconstruct the full transaction list from `known_txs`.
    ///
    /// Prefilled transactions are placed at their declared indices. Remaining
    /// indices are matched against `known_txs` by short-id lookup. If any
    /// short-id has no matching transaction the result is
    /// [`Reconstruction::Missing`] listing the unresolved identifiers.
    ///
    /// # Panics
    ///
    /// Panics if the total number of slots exceeds `usize::MAX` (practically
    /// unreachable).
    #[must_use]
    pub fn reconstruct(&self, known_txs: &BTreeMap<u64, Transaction>) -> Reconstruction {
        let total = self.short_ids.len() + self.prefilled.len();
        let mut txs: Vec<Option<Transaction>> = vec![None; total];

        for &(idx, ref tx) in &self.prefilled {
            if idx < total {
                txs[idx] = Some(tx.clone());
            }
        }

        let mut missing = Vec::new();
        let mut short_idx = 0;
        for slot in &mut txs {
            if slot.is_some() {
                continue;
            }
            if short_idx >= self.short_ids.len() {
                break;
            }
            let short_id = self.short_ids[short_idx];
            short_idx += 1;

            if let Some(tx) = known_txs.get(&short_id) {
                *slot = Some(tx.clone());
            } else {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&short_id.to_le_bytes());
                missing.push(Hash256(h));
            }
        }

        if missing.is_empty() {
            Reconstruction::Complete(
                txs.into_iter()
                    .map(|opt| opt.expect("all slots filled"))
                    .collect(),
            )
        } else {
            Reconstruction::Missing(missing)
        }
    }
}

/// Result of compact-block reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reconstruction {
    /// The complete ordered transaction list is available.
    Complete(Vec<Transaction>),
    /// Missing identifiers must be requested from the announcing peer.
    Missing(Vec<Hash256>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: types::Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
        }
    }

    fn sample_tx(nonce: u64) -> Transaction {
        Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: types::Address([0x10; 32]),
            nonce,
            access_list: Vec::new(),
            resource_limit: types::Resources::ZERO,
            payload: vec![0xDE, 0xAD],
            signature: [0xAB; 64],
        }
    }

    #[test]
    fn compact_block_reconstruct_complete() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);
        let tx2 = sample_tx(2);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 300],
            prefilled: vec![(1, tx1.clone())],
        };

        let mut known = BTreeMap::new();
        known.insert(100, tx0.clone());
        known.insert(300, tx2.clone());

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs.len(), 3);
                assert_eq!(txs[0], tx0);
                assert_eq!(txs[1], tx1);
                assert_eq!(txs[2], tx2);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn compact_block_reconstruct_missing() {
        let tx0 = sample_tx(0);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 200, 300],
            prefilled: vec![],
        };

        let mut known = BTreeMap::new();
        known.insert(100, tx0);

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(_) => panic!("expected Missing"),
            Reconstruction::Missing(missing) => {
                assert_eq!(missing.len(), 2);
                let mut h0 = [0u8; 32];
                h0[..8].copy_from_slice(&200u64.to_le_bytes());
                assert_eq!(missing[0], Hash256(h0));
                let mut h1 = [0u8; 32];
                h1[..8].copy_from_slice(&300u64.to_le_bytes());
                assert_eq!(missing[1], Hash256(h1));
            }
        }
    }

    #[test]
    fn compact_block_reconstruct_all_prefilled() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![(0, tx0.clone()), (1, tx1.clone())],
        };

        let known = BTreeMap::new();
        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs, vec![tx0, tx1]);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn compact_block_reconstruct_empty() {
        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![],
        };
        let known = BTreeMap::new();
        let result = block.reconstruct(&known);
        assert_eq!(result, Reconstruction::Complete(vec![]));
    }

    #[test]
    fn message_kind_from_u8_roundtrips() {
        let kinds = [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ];
        for kind in kinds {
            assert_eq!(MessageKind::from_u8(kind as u8), Some(kind));
        }
        assert_eq!(MessageKind::from_u8(6), None);
        assert_eq!(MessageKind::from_u8(255), None);
    }
}
