// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Non-exporting signature provider trait.

use crate::error::KeystoreError;
use crate::key::{KeyHandle, SigningContext, SigningPosition};
use types::{Hash256, ValidatorId};

/// Non-exporting signature provider.
pub trait Signer: Send + Sync {
    /// Returns the public validator identity for a handle.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError`] for an unknown handle or wrong key purpose.
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError>;

    /// Persists the decision and signs only when it cannot equivocate.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::ConflictingSign`] if the position was previously
    /// signed for a different message, or another error if durable signing fails.
    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError>;
}

/// A signer bound to a single immutable chain and genesis namespace.
pub trait ChainSigner: Signer {
    /// Returns the namespace whose journal protects this key.
    fn signing_context(&self) -> SigningContext;
}
