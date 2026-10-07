// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded explorer projection of already finalized block data.

use crate::json::{JsonValue, hash_to_hex};
use codec::CanonicalEncode;

#[allow(clippy::needless_pass_by_value)]
fn text(value: impl ToString) -> JsonValue {
    JsonValue::String(value.to_string())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

pub(crate) fn to_json(block: &types::Block) -> Option<JsonValue> {
    // Conservative upper bound before allocating/serializing bounded history.
    let mut bound = 2048_usize;
    for tx in &block.transactions {
        bound = bound
            .checked_add(1024)?
            .checked_add(tx.payload.len().checked_mul(2)?)?;
        if bound > 4 * 1024 * 1024 {
            return None;
        }
    }
    let header = &block.header;
    let transactions = block
        .transactions
        .iter()
        .map(|tx| {
            let id = types::hash::domain_hash(types::domain::TRANSACTION_ID, &tx.to_bytes());
            JsonValue::Object(vec![
                ("id".into(), text(hash_to_hex(id))),
                ("sender".into(), text(tx.sender)),
                ("nonce".into(), text(tx.nonce)),
                ("expires_at".into(), text(tx.expires_at)),
                ("chain_id".into(), JsonValue::Number(i64::from(tx.chain_id))),
                ("payload".into(), text(hex(&tx.payload))),
            ])
        })
        .collect();
    Some(JsonValue::Object(vec![
        ("height".into(), text(header.height)),
        ("hash".into(), text(hash_to_hex(header.compute_hash()))),
        ("parent".into(), text(hash_to_hex(header.parent))),
        ("state_root".into(), text(hash_to_hex(header.state_root))),
        (
            "transactions_root".into(),
            text(hash_to_hex(header.transactions_root)),
        ),
        (
            "receipts_root".into(),
            text(hash_to_hex(header.receipts_root)),
        ),
        (
            "committee_root".into(),
            text(hash_to_hex(header.committee_root)),
        ),
        ("transactions".into(), JsonValue::Array(transactions)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Address, Block, BlockHeader, Hash256, Resources, Transaction, TransactionLane};

    #[test]
    fn explorer_numbers_are_lossless_and_ids_match_canonical_domains() {
        let tx = Transaction {
            version: 1,
            chain_id: 42,
            sender: Address([1; 32]),
            nonce: u64::MAX,
            expires_at: u64::MAX,
            lane: TransactionLane::Payments,
            resource_prices: Resources::ZERO,
            resource_limit: Resources::ZERO,
            access_list: vec![],
            payload: vec![1, 2, 3],
            signature: [0; 64],
        };
        let block = Block {
            header: BlockHeader {
                height: u64::MAX,
                parent: Hash256([1; 32]),
                transactions_root: Hash256([2; 32]),
                state_root: Hash256([3; 32]),
                receipts_root: Hash256([4; 32]),
                committee_root: Hash256([5; 32]),
                capacity: Resources::ZERO,
            },
            transactions: vec![tx.clone()],
        };
        let value = to_json(&block).unwrap();
        assert_eq!(
            value.get("height").unwrap().as_str(),
            Some("18446744073709551615")
        );
        let projected = &value.get("transactions").unwrap().as_array().unwrap()[0];
        assert_eq!(
            projected.get("nonce").unwrap().as_str(),
            Some("18446744073709551615")
        );
        let expected = types::hash::domain_hash(types::domain::TRANSACTION_ID, &tx.to_bytes());
        assert_eq!(
            projected.get("id").unwrap().as_str(),
            Some(hash_to_hex(expected).as_str())
        );
        assert_eq!(projected.get("payload").unwrap().as_str(), Some("010203"));
        assert_eq!(
            projected.get("sender").unwrap().as_str(),
            Some(tx.sender.to_string().as_str())
        );
        let mut too_large = block;
        too_large.transactions[0].payload = vec![0; 2 * 1024 * 1024];
        assert!(to_json(&too_large).is_none());
    }
}
