// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical transaction signing and identity commitments.

use codec::{CanonicalEncode, protocol::encode_unsigned_transaction};
use crypto::blake2s::domain_hash;
use types::{Address, Hash256, Transaction, domain};

/// Derives a wallet address from its Ed25519 public key.
#[must_use]
pub fn address_from_public_key(public_key: &[u8; 32]) -> Address {
    Address(domain_hash(domain::ACCOUNT_ADDRESS, public_key).0)
}

/// Returns the domain-separated digest signed by the transaction sender.
///
/// All canonical fields except the signature are included in their wire order.
#[must_use]
pub fn signing_hash(transaction: &Transaction) -> Hash256 {
    let mut bytes = Vec::new();
    encode_unsigned_transaction(transaction, &mut bytes);
    domain_hash(domain::TRANSACTION, &bytes)
}

/// Returns an identifier binding every canonical field, including the signature.
#[must_use]
pub fn compute_tx_id(transaction: &Transaction) -> Hash256 {
    domain_hash(domain::TRANSACTION_ID, &transaction.to_bytes())
}
