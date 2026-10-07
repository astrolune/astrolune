// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Staged transaction validation and classification.
//!
//! Transactions follow a fixed validation order:
//! 1. Shape and bounds (encoding, size)
//! 2. Chain and expiry (chain ID match, height validity)
//! 3. Sender and nonce (account existence, exact nonce match)
//! 4. Declared resources and balance (sufficient limits)
//! 5. Signature (cryptographic verification)
//! 6. Lane-specific payload (payload matches declared lane)
//!
//! Invalid pre-admission transactions do not enter execution.

#![forbid(unsafe_code)]

pub mod contract;
pub mod envelope;
pub mod error;
pub mod lane;
pub mod payment;
pub mod signed_validator;
pub mod signing;
pub mod validator;

pub use contract::{
    ContractAction, ContractPayload, contract_address, contract_code_key, contract_state_key,
};
pub use envelope::Envelope;
pub use error::TransactionError;
pub use lane::TransactionLane;
pub use payment::Payment;
pub use signed_validator::{RegisteredAccount, SignedValidator};
pub use signing::{address_from_public_key, compute_tx_id, signing_hash};
pub use validator::{
    AccountState, BasicValidator, TransactionValidator, ValidatedTransaction, ValidationContext,
    estimate_encoded_len,
};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use types::{Resources, StateKey};

    fn sender() -> types::Address {
        types::Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>, resources: Resources) -> types::Transaction {
        types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::from_payload(&payload),
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: resources,
            payload,
            signature: [0xFF; 64],
        }
    }

    fn simple_context() -> ValidationContext {
        ValidationContext {
            chain_id: 7,
            next_height: 100,
            max_transaction_bytes: 1024,
        }
    }

    fn resources_with(compute: u64) -> Resources {
        Resources {
            compute,
            memory: 1,
            io: 1,
            bandwidth: 1,
        }
    }

    #[test]
    fn lane_system_for_empty_payload() {
        assert_eq!(TransactionLane::from_payload(&[]), TransactionLane::System);
    }

    #[test]
    fn lane_payments_for_short_payload() {
        assert_eq!(
            TransactionLane::from_payload(&[0; 64]),
            TransactionLane::Payments
        );
    }

    #[test]
    fn lane_contracts_for_long_payload() {
        assert_eq!(
            TransactionLane::from_payload(&[0; 256]),
            TransactionLane::Contracts
        );
    }

    #[test]
    fn valid_transaction_passes() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(0, vec![1, 2, 3], resources_with(10));
        let result = validator.validate(tx, simple_context());
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.lane, TransactionLane::Payments);
        assert_eq!(validated.transaction.chain_id, 7);
    }

    #[test]
    fn rejects_wrong_chain() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![], Resources::default());
        tx.chain_id = 99;

        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::WrongChain));
    }

    #[test]
    fn rejects_zero_signature() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![], Resources::default());
        tx.signature = [0; 64];

        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidSignature));
    }

    #[test]
    fn rejects_invalid_nonce() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 5,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(0, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidNonce));
    }

    #[test]
    fn accepts_zero_nonce_for_unknown_account() {
        let validator = BasicValidator::empty();
        let tx = make_tx(0, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_nonzero_nonce_for_unknown_account() {
        let validator = BasicValidator::empty();
        let tx = make_tx(1, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidNonce));
    }

    #[test]
    fn rejects_insufficient_resources() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 5,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(
            0,
            vec![],
            Resources {
                compute: 100,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
        );
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InsufficientResources));
    }

    #[test]
    fn rejects_oversized_transaction() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![0; 2048], Resources::default());
        tx.signature = [0xFF; 64];

        let context = ValidationContext {
            chain_id: 7,
            next_height: 100,
            max_transaction_bytes: 1024,
        };
        let result = validator.validate(tx, context);
        assert_eq!(result, Err(TransactionError::InvalidEnvelope));
    }

    #[test]
    fn assigned_lane_matches_payload() {
        let validator = BasicValidator::empty();

        let tx = make_tx(0, vec![], Resources::default());
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::System);

        let tx = make_tx(0, vec![0; 64], resources_with(1));
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::Payments);

        let tx = make_tx(0, vec![0; 256], resources_with(1));
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::Contracts);
    }

    #[test]
    fn transaction_id_is_deterministic() {
        let validator = BasicValidator::empty();
        let tx = make_tx(0, vec![1, 2, 3], resources_with(1));

        let v1 = validator.validate(tx.clone(), simple_context()).unwrap();
        let v2 = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(v1.id, v2.id);
    }

    #[test]
    fn different_nonces_produce_different_ids() {
        let validator = BasicValidator::empty();

        let tx0 = types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: types::Address([1u8; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };
        let tx1 = types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: types::Address([2u8; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };

        let v0 = validator.validate(tx0, simple_context()).unwrap();
        let v1 = validator.validate(tx1, simple_context()).unwrap();
        assert_ne!(v0.id, v1.id);
    }

    #[test]
    fn error_display() {
        assert_ne!(TransactionError::InvalidEnvelope.to_string(), "");
        assert_ne!(TransactionError::WrongChain.to_string(), "");
        assert_ne!(TransactionError::Expired.to_string(), "");
        assert_ne!(TransactionError::InvalidNonce.to_string(), "");
        assert_ne!(TransactionError::InsufficientResources.to_string(), "");
        assert_ne!(TransactionError::InvalidSignature.to_string(), "");
        assert_ne!(TransactionError::UnsupportedPayload.to_string(), "");
    }

    #[test]
    fn estimate_encoded_len_basic() {
        let tx = types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: types::Address([0; 32]),
            nonce: 0,
            access_list: vec![StateKey(vec![1, 2, 3])],
            resource_limit: Resources {
                compute: 1,
                memory: 2,
                io: 3,
                bandwidth: 4,
            },
            payload: vec![0; 10],
            signature: [0; 64],
        };
        let len = estimate_encoded_len(&tx);
        assert_eq!(len, 205);
    }
}
