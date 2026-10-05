// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Mixed payment/contract sessions with atomic private overlays.

use crate::{ExecutionError, PaymentSession, TransactionOutput, parallel_payment::Overlay};
use state::{StateDatabase, StateError, StateSnapshot};
use std::collections::BTreeMap;
use transaction::{TransactionError, ValidationContext};
use types::{Hash256, Resources, Transaction, TransactionLane};

/// Signed execution session. The caller obtains `contracts` from committed genesis policy.
pub struct SignedSession<'a> {
    overlay: Overlay<'a>,
    context: ValidationContext,
    capacity: Resources,
    used: Resources,
    contracts: bool,
    prices: Resources,
}

impl<'a> SignedSession<'a> {
    /// Starts a private session; legacy chains pass `false` for contract activation.
    #[must_use]
    pub fn new(
        snapshot: &'a dyn StateSnapshot,
        context: ValidationContext,
        capacity: Resources,
        contracts: bool,
    ) -> Self {
        Self {
            overlay: Overlay {
                parent: snapshot,
                values: BTreeMap::new(),
            },
            context,
            capacity,
            used: Resources::ZERO,
            contracts,
            prices: crate::PAYMENT_PRICES,
        }
    }

    /// Sets authenticated prices before executing any transaction in this session.
    #[must_use]
    pub fn with_prices(mut self, prices: Resources) -> Self {
        self.prices = prices;
        self
    }

    /// Executes in canonical order. An error leaves every session field unchanged.
    pub fn execute(&mut self, tx: &Transaction) -> Result<TransactionOutput, ExecutionError> {
        let output = match tx.lane {
            TransactionLane::Payments => {
                PaymentSession::new(&self.overlay, self.context, self.capacity)
                    .with_prices(self.prices)
                    .execute(tx)?
            }
            TransactionLane::Contracts if self.contracts => crate::contract::execute_contract(
                &self.overlay,
                tx,
                self.context,
                self.capacity,
                self.prices,
            )?,
            _ => return Err(TransactionError::UnsupportedPayload.into()),
        };
        let used = self
            .used
            .checked_add(output.receipt.resources)
            .ok_or(ExecutionError::ResourceLimit)?;
        if !used.fits_in(self.capacity) {
            return Err(ExecutionError::ResourceLimit);
        }
        self.overlay.apply(&output.diff);
        self.used = used;
        Ok(output)
    }
}

/// Executes signed payments and ABI-v2 contracts, then publishes exactly one atomic commit.
pub fn execute_signed(
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
    let cached = crate::snapshot_cache::CachedSnapshot::new(snapshot.as_ref());
    let mut session = SignedSession::new(&cached, context, capacity, true);
    let outputs = transactions
        .iter()
        .map(|tx| session.execute(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
    let root = database.commit(parent, &diffs)?;
    Ok((outputs, root))
}
