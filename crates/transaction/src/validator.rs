// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Transaction validation logic and types.

use std::collections::BTreeMap;

use types::{Address, Hash256, Transaction};

use crate::error::TransactionError;
use crate::lane::TransactionLane;
pub use crate::signing::compute_tx_id;
pub use types::AccountState;

/// Context needed for deterministic pre-execution validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationContext {
    /// Expected chain identifier.
    pub chain_id: u32,
    /// Height for expiry checks.
    pub next_height: u64,
    /// Maximum canonical transaction bytes.
    pub max_transaction_bytes: usize,
}

/// Transaction accepted by every pre-execution validation stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTransaction {
    /// Canonical transaction identifier.
    pub id: Hash256,
    /// Assigned execution lane.
    pub lane: TransactionLane,
    /// Original canonical transaction.
    pub transaction: Transaction,
}

/// Provider for hashing and state-aware transaction checks.
pub trait TransactionValidator {
    /// Validates one transaction without mutating state.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError`] at the first failed validation stage.
    fn validate(
        &self,
        transaction: Transaction,
        context: ValidationContext,
    ) -> Result<ValidatedTransaction, TransactionError>;
}

/// Local demonstration validator with no cryptographic authentication.
///
/// Use [`crate::SignedValidator`] for signed transaction admission. This helper
/// accepts nonzero signature placeholders and permits unknown zero-nonce accounts.
#[derive(Clone)]
pub struct BasicValidator {
    /// Known account states keyed by address.
    accounts: BTreeMap<Address, AccountState>,
}

impl BasicValidator {
    /// Creates a new validator with the given account states.
    #[must_use]
    pub fn new(accounts: BTreeMap<Address, AccountState>) -> Self {
        Self { accounts }
    }

    /// Creates a validator with no accounts (useful for testing envelope checks).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            accounts: BTreeMap::new(),
        }
    }

    /// Creates a permissive validator that skips account-level nonce and
    /// balance checks. Only validates envelope shape and chain ID.
    #[must_use]
    pub fn permissive() -> Self {
        Self::empty()
    }

    /// Advances a known account's nonce without wrapping at `u64::MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::InvalidNonce`] on nonce exhaustion.
    pub fn advance_nonce(&mut self, address: &Address) -> Result<(), TransactionError> {
        if let Some(acc) = self.accounts.get_mut(address) {
            acc.nonce = acc
                .nonce
                .checked_add(1)
                .ok_or(TransactionError::InvalidNonce)?;
        }
        Ok(())
    }
}

impl Default for BasicValidator {
    fn default() -> Self {
        Self::empty()
    }
}

impl TransactionValidator for BasicValidator {
    fn validate(
        &self,
        transaction: Transaction,
        context: ValidationContext,
    ) -> Result<ValidatedTransaction, TransactionError> {
        validate_shape(&transaction, context.max_transaction_bytes)?;

        if transaction.chain_id != context.chain_id {
            return Err(TransactionError::WrongChain);
        }
        if context.next_height > transaction.expires_at {
            return Err(TransactionError::Expired);
        }
        if transaction.nonce == u64::MAX {
            return Err(TransactionError::InvalidNonce);
        }

        let account = self.accounts.get(&transaction.sender);
        match account {
            None => {
                if transaction.nonce != 0 {
                    return Err(TransactionError::InvalidNonce);
                }
            }
            Some(acc) => {
                if transaction.nonce != acc.nonce {
                    return Err(TransactionError::InvalidNonce);
                }
                let cost = transaction
                    .resource_limit
                    .checked_cost(transaction.resource_prices)
                    .ok_or(TransactionError::InsufficientResources)?;
                if cost > acc.balance {
                    return Err(TransactionError::InsufficientResources);
                }
            }
        }

        if transaction.signature == [0; 64] {
            return Err(TransactionError::InvalidSignature);
        }

        let lane = transaction.lane;
        let id = compute_tx_id(&transaction);

        Ok(ValidatedTransaction {
            id,
            lane,
            transaction,
        })
    }
}

/// Returns the canonical encoded size, or `usize::MAX` on length overflow.
#[must_use]
pub fn estimate_encoded_len(tx: &Transaction) -> usize {
    encoded_len(tx).unwrap_or(usize::MAX)
}

fn encoded_len(tx: &Transaction) -> Option<usize> {
    fn prefix_len(length: usize) -> Option<usize> {
        u32::try_from(length).ok()?;
        Some(if length < 128 { 1 } else { 5 })
    }

    let mut size = 8usize + 4 + 32 + 8 + 8 + 1 + 32 + 32 + 64;
    size = size.checked_add(prefix_len(tx.access_list.len())?)?;
    for key in &tx.access_list {
        size = size
            .checked_add(prefix_len(key.len())?)?
            .checked_add(key.len())?;
    }
    size.checked_add(prefix_len(tx.payload.len())?)?
        .checked_add(tx.payload.len())
}

pub(crate) fn validate_shape(tx: &Transaction, max_bytes: usize) -> Result<(), TransactionError> {
    if tx.version != types::TRANSACTION_VERSION
        || tx.access_list.len() > codec::MAX_LIST_LEN
        || tx
            .access_list
            .iter()
            .any(|key| key.len() > codec::MAX_STATE_KEY_LEN)
        || tx.payload.len() > codec::MAX_PAYLOAD
        || encoded_len(tx).is_none_or(|length| length > max_bytes)
    {
        return Err(TransactionError::InvalidEnvelope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransactionError;
    use types::{Resources, StateKey};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>, resources: Resources) -> Transaction {
        Transaction {
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
    fn valid_transaction_passes() {
        let mut accounts = BTreeMap::new();
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
        let mut accounts = BTreeMap::new();
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
        let mut accounts = BTreeMap::new();
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

        let tx0 = Transaction {
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
            resource_limit: Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };
        let tx1 = Transaction {
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
    fn estimate_encoded_len_basic() {
        let tx = Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: Address([0; 32]),
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
