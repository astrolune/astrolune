// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Sequential signed payments with a private account overlay and atomic publication.

use std::collections::BTreeMap;

use codec::CanonicalEncode;
use state::{
    AccessMode, AccessRequest, StateDatabase, StateDiff, StateError, StateLease, StateSnapshot,
    account_key, read_account,
};
use transaction::{
    Payment, RegisteredAccount, SignedValidator, TransactionError, TransactionValidator,
    ValidationContext,
};
use types::{AccountState, Address, ExecutionReceipt, Hash256, Resources, Transaction};

use crate::{ExecutionError, TransactionOutput};

/// Version-1 transfer prices. One compute unit is burned per successful transfer.
pub const PAYMENT_PRICES: Resources = Resources {
    compute: 1,
    memory: 0,
    io: 0,
    bandwidth: 0,
};

/// Deterministic version-1 usage: one compute, 32 account-value bytes, four IO
/// operations, and the complete canonical transaction byte count (also for self-transfers).
pub fn payment_resources(tx: &Transaction) -> Result<Resources, ExecutionError> {
    Ok(Resources {
        compute: 1,
        memory: 32,
        io: 4,
        bandwidth: u64::try_from(transaction::estimate_encoded_len(tx))
            .map_err(|_| ExecutionError::ResourceLimit)?,
    })
}

/// Private, sequential account view. Rejected transactions never change this overlay.
/// The caller authenticates the parent snapshot and publishes returned diffs atomically.
pub struct PaymentSession<'a> {
    snapshot: &'a dyn StateSnapshot,
    accounts: BTreeMap<Address, AccountState>,
    context: ValidationContext,
    capacity: Resources,
    used: Resources,
    prices: Resources,
}

impl<'a> PaymentSession<'a> {
    /// Starts execution against one immutable parent with version-1 payment rules.
    #[must_use]
    pub fn new(
        snapshot: &'a dyn StateSnapshot,
        context: ValidationContext,
        capacity: Resources,
    ) -> Self {
        Self {
            snapshot,
            accounts: BTreeMap::new(),
            context,
            capacity,
            used: Resources::ZERO,
            prices: PAYMENT_PRICES,
        }
    }

    /// Uses prices authenticated by the caller for this execution height.
    #[must_use]
    pub fn with_prices(mut self, prices: Resources) -> Self {
        self.prices = prices;
        self
    }

    fn account(&self, address: Address) -> Result<Option<AccountState>, ExecutionError> {
        if let Some(account) = self.accounts.get(&address) {
            return Ok(Some(account.clone()));
        }
        Ok(read_account(self.snapshot, address)?)
    }

    /// Authenticates a payment, checks declared access/resources, then updates the
    /// private view. Invalid transactions invalidate a received block, not just a receipt.
    pub fn execute(&mut self, tx: &Transaction) -> Result<TransactionOutput, ExecutionError> {
        let payment = Payment::decode(&tx.payload)?;
        let sender = self
            .account(tx.sender)?
            .ok_or(TransactionError::UnknownSender)?;
        let validator = SignedValidator::new(
            BTreeMap::from([(
                tx.sender,
                RegisteredAccount {
                    state: sender.clone(),
                    public_key: payment.public_key,
                },
            )]),
            self.capacity,
            self.prices,
        );
        let validated = validator.validate(tx.clone(), self.context)?;
        let resources = payment_resources(tx)?;
        let used = self
            .used
            .checked_add(resources)
            .ok_or(ExecutionError::ResourceLimit)?;
        if !resources.fits_in(tx.resource_limit) || !used.fits_in(self.capacity) {
            return Err(ExecutionError::ResourceLimit);
        }
        let sender_key = account_key(tx.sender);
        let recipient_key = account_key(payment.recipient);
        if !tx.access_list.contains(&sender_key) || !tx.access_list.contains(&recipient_key) {
            return Err(ExecutionError::UndeclaredStateAccess);
        }
        let reserve = tx
            .resource_limit
            .checked_cost(self.prices)
            .and_then(|fee| fee.checked_add(payment.amount))
            .ok_or(TransactionError::InsufficientResources)?;
        if sender.balance < reserve {
            return Err(TransactionError::InsufficientResources.into());
        }
        let fee = resources
            .checked_cost(self.prices)
            .ok_or(ExecutionError::ResourceLimit)?;
        let mut next_sender = AccountState {
            nonce: sender
                .nonce
                .checked_add(1)
                .ok_or(TransactionError::InvalidNonce)?,
            balance: sender
                .balance
                .checked_sub(fee)
                .ok_or(TransactionError::InsufficientResources)?,
        };
        let next_recipient = if tx.sender == payment.recipient {
            None
        } else {
            next_sender.balance = next_sender
                .balance
                .checked_sub(payment.amount)
                .ok_or(TransactionError::InsufficientResources)?;
            let recipient = self.account(payment.recipient)?.unwrap_or(AccountState {
                nonce: 0,
                balance: 0,
            });
            Some(AccountState {
                nonce: recipient.nonce,
                balance: recipient
                    .balance
                    .checked_add(payment.amount)
                    .ok_or(ExecutionError::Trap)?,
            })
        };
        let mut diff = StateDiff::new();
        diff.put(sender_key.clone(), next_sender.to_bytes());
        if let Some(ref recipient) = next_recipient {
            diff.put(recipient_key.clone(), recipient.to_bytes());
        }
        diff.sort_canonical();
        let receipt = ExecutionReceipt {
            transaction: validated.id,
            succeeded: true,
            resources,
            output_root: diff.commitment(),
        };
        let observed_lease =
            StateLease::new([sender_key, recipient_key].map(|key| AccessRequest {
                key,
                mode: AccessMode::Write,
            }));
        // Publish to the overlay only after every fallible check succeeds.
        self.accounts.insert(tx.sender, next_sender);
        if let Some(recipient) = next_recipient {
            self.accounts.insert(payment.recipient, recipient);
        }
        self.used = used;
        Ok(TransactionOutput {
            diff,
            receipt,
            observed_lease,
        })
    }
}

/// Revalidates ordered signed payments against a private overlay and commits all
/// diffs once. A bad transaction, stale root, or storage failure publishes no prefix.
pub fn execute_payments(
    database: &mut impl StateDatabase,
    transactions: &[Transaction],
    parent: Hash256,
    context: ValidationContext,
    capacity: Resources,
) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
    let snapshot = database.snapshot()?;
    if snapshot.root() != parent {
        return Err(StateError::StaleSnapshot.into());
    }
    crate::prefetch::declared_keys(database, transactions);
    let mut session = PaymentSession::new(snapshot.as_ref(), context, capacity);
    let outputs: Vec<_> = transactions
        .iter()
        .map(|tx| session.execute(tx))
        .collect::<Result<_, _>>()?;
    let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
    let root = database.commit(parent, &diffs)?;
    Ok((outputs, root))
}
