// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State-aware admission with strict Ed25519 verification.

use std::collections::BTreeMap;

use crypto::blake2s::ed25519_verify;
use types::{Address, Resources, Transaction};

use crate::validator::validate_shape;
use crate::{
    AccountState, TransactionError, TransactionLane, TransactionValidator, ValidatedTransaction,
    ValidationContext, address_from_public_key, compute_tx_id, signing_hash,
};

/// Finalized account state and its authorized Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredAccount {
    /// Expected nonce and available balance.
    pub state: AccountState,
    /// Public key whose derived address must match the sender.
    pub public_key: [u8; 32],
}

/// Validates signed transactions against an immutable account view.
///
/// Resource limits and unit prices must come from finalized chain parameters.
/// Signed expiry, lane, and prices are enforced against this finalized policy.
pub struct SignedValidator {
    accounts: BTreeMap<Address, RegisteredAccount>,
    resource_limits: Resources,
    resource_prices: Resources,
}

impl SignedValidator {
    /// Creates a validator over one finalized account view and resource policy.
    #[must_use]
    pub fn new(
        accounts: BTreeMap<Address, RegisteredAccount>,
        resource_limits: Resources,
        resource_prices: Resources,
    ) -> Self {
        Self {
            accounts,
            resource_limits,
            resource_prices,
        }
    }
}

impl TransactionValidator for SignedValidator {
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

        let account = self
            .accounts
            .get(&transaction.sender)
            .ok_or(TransactionError::UnknownSender)?;
        if address_from_public_key(&account.public_key) != transaction.sender {
            return Err(TransactionError::UnknownSender);
        }
        if transaction.nonce != account.state.nonce || transaction.nonce == u64::MAX {
            return Err(TransactionError::InvalidNonce);
        }

        if transaction.resource_prices != self.resource_prices {
            return Err(TransactionError::InsufficientResources);
        }
        let cost = transaction
            .resource_limit
            .checked_cost(self.resource_prices)
            .ok_or(TransactionError::InsufficientResources)?;
        if !transaction.resource_limit.fits_in(self.resource_limits) || cost > account.state.balance
        {
            return Err(TransactionError::InsufficientResources);
        }

        if !ed25519_verify(
            &account.public_key,
            signing_hash(&transaction).as_bytes(),
            &transaction.signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }

        let public_key = match transaction.lane {
            TransactionLane::Payments => crate::Payment::decode(&transaction.payload)?.public_key,
            TransactionLane::Contracts => {
                crate::ContractPayload::decode(&transaction.payload)?.public_key
            }
            TransactionLane::System => return Err(TransactionError::UnsupportedPayload),
        };
        if public_key != account.public_key {
            return Err(TransactionError::UnsupportedPayload);
        }

        Ok(ValidatedTransaction {
            id: compute_tx_id(&transaction),
            lane: transaction.lane,
            transaction,
        })
    }
}
