// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Signed transaction envelope with domain-separated signature binding.

use types::{Address, Hash256, Resources, StateKey, Transaction};

/// A signed transaction envelope binding all fields into a single verifiable unit.
///
/// The envelope contains the canonical transaction and its signature. The
/// signature covers a domain-separated hash of every preceding field to
/// prevent cross-domain replay and field mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// The canonical transaction payload.
    pub transaction: Transaction,
    /// Domain-separated signature over all transaction fields.
    pub signature: [u8; 64],
}

impl Envelope {
    /// Creates a new envelope from a transaction and signature.
    #[must_use]
    pub fn new(mut transaction: Transaction, signature: [u8; 64]) -> Self {
        transaction.signature = signature;
        Self {
            transaction,
            signature,
        }
    }

    /// Returns the sender address.
    #[must_use]
    pub fn sender(&self) -> Address {
        self.transaction.sender
    }

    /// Returns the nonce.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.transaction.nonce
    }

    /// Returns the chain ID.
    #[must_use]
    pub fn chain_id(&self) -> u32 {
        self.transaction.chain_id
    }

    /// Returns the declared resource limit.
    #[must_use]
    pub fn resource_limit(&self) -> Resources {
        self.transaction.resource_limit
    }

    /// Returns the access list.
    #[must_use]
    pub fn access_list(&self) -> &[StateKey] {
        &self.transaction.access_list
    }

    /// Returns the payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.transaction.payload
    }

    /// Computes a deterministic identifier for this envelope.
    ///
    /// The identifier binds the chain ID, sender, nonce, and a hash of the
    /// canonical transaction encoding. This is suitable for deduplication
    /// and indexing.
    #[must_use]
    pub fn id(&self) -> Hash256 {
        let mut transaction = self.transaction.clone();
        transaction.signature = self.signature;
        crate::compute_tx_id(&transaction)
    }

    /// Validates the envelope shape without verifying the signature.
    ///
    /// Checks:
    /// - Signature is not all zeros
    /// - Chain ID is non-zero
    /// - Sender is not zero
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.transaction.version == types::TRANSACTION_VERSION
            && self.signature != [0u8; 64]
            && self.signature == self.transaction.signature
            && self.transaction.chain_id != 0
            && !self.transaction.sender.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_envelope(nonce: u64) -> Envelope {
        Envelope::new(
            Transaction {
                version: types::TRANSACTION_VERSION,
                expires_at: u64::MAX,
                lane: types::TransactionLane::Payments,
                resource_prices: types::Resources {
                    compute: 1,
                    ..types::Resources::ZERO
                },
                chain_id: 7,
                sender: sender(),
                nonce,
                access_list: Vec::new(),
                resource_limit: Resources {
                    compute: 10,
                    memory: 20,
                    io: 30,
                    bandwidth: 40,
                },
                payload: vec![0xDE, 0xAD],
                signature: [0xFF; 64],
            },
            [0xBE; 64],
        )
    }

    #[test]
    fn envelope_id_deterministic() {
        let env = make_envelope(42);
        let id1 = env.id();
        let id2 = env.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn envelope_id_differs_by_nonce() {
        let env0 = make_envelope(0);
        let env1 = make_envelope(1);
        assert_ne!(env0.id(), env1.id());
    }

    #[test]
    fn envelope_id_differs_by_sender() {
        let env_a = Envelope::new(
            Transaction {
                version: types::TRANSACTION_VERSION,
                expires_at: u64::MAX,
                lane: types::TransactionLane::Payments,
                resource_prices: types::Resources {
                    compute: 1,
                    ..types::Resources::ZERO
                },
                chain_id: 7,
                sender: Address([1u8; 32]),
                nonce: 0,
                access_list: Vec::new(),
                resource_limit: Resources::ZERO,
                payload: Vec::new(),
                signature: [0xFF; 64],
            },
            [0xBE; 64],
        );
        let env_b = Envelope::new(
            Transaction {
                version: types::TRANSACTION_VERSION,
                expires_at: u64::MAX,
                lane: types::TransactionLane::Payments,
                resource_prices: types::Resources {
                    compute: 1,
                    ..types::Resources::ZERO
                },
                chain_id: 7,
                sender: Address([2u8; 32]),
                nonce: 0,
                access_list: Vec::new(),
                resource_limit: Resources::ZERO,
                payload: Vec::new(),
                signature: [0xFF; 64],
            },
            [0xBE; 64],
        );
        assert_ne!(env_a.id(), env_b.id());
    }

    #[test]
    fn well_formed_envelope() {
        let env = make_envelope(0);
        assert!(env.is_well_formed());
    }

    #[test]
    fn rejects_zero_signature() {
        let mut env = make_envelope(0);
        env.signature = [0u8; 64];
        assert!(!env.is_well_formed());
    }

    #[test]
    fn rejects_zero_chain_id() {
        let mut env = make_envelope(0);
        env.transaction.chain_id = 0;
        assert!(!env.is_well_formed());
    }

    #[test]
    fn rejects_zero_sender() {
        let mut env = make_envelope(0);
        env.transaction.sender = Address::ZERO;
        assert!(!env.is_well_formed());
    }

    #[test]
    fn accessors_return_correct_values() {
        let env = make_envelope(42);
        assert_eq!(env.sender(), sender());
        assert_eq!(env.nonce(), 42);
        assert_eq!(env.chain_id(), 7);
        assert_eq!(env.resource_limit().compute, 10);
        assert_eq!(env.access_list(), []);
        assert_eq!(env.payload(), &[0xDE, 0xAD]);
    }
}
