// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! In-memory keystore for testing and simulation.

use std::collections::BTreeMap;

use types::{Hash256, ValidatorId};

use crate::error::KeystoreError;
use crate::key::{KeyHandle, KeyPurpose, SigningPosition};
use crate::signer::Signer;

/// In-memory keystore for testing and simulation.
///
/// Stores keys by string identifier, maps them to a [`ValidatorId`] and
/// [`KeyPurpose`], and tracks consensus signing positions to prevent
/// equivocation.
pub struct MockKeystore {
    keys: BTreeMap<String, (ValidatorId, KeyPurpose)>,
    signed: BTreeMap<(String, SigningPosition), Hash256>,
}

impl MockKeystore {
    /// Creates an empty mock keystore.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            signed: BTreeMap::new(),
        }
    }

    /// Registers a key with the given purpose and validator identity.
    pub fn insert(
        &mut self,
        id: impl Into<String>,
        validator_id: ValidatorId,
        purpose: KeyPurpose,
    ) {
        self.keys.insert(id.into(), (validator_id, purpose));
    }

    /// Returns `true` if at least one signing position has been recorded.
    #[must_use]
    pub fn has_conflict(&self) -> bool {
        !self.signed.is_empty()
    }
}

impl Default for MockKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for MockKeystore {
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError> {
        match self.keys.get(&handle.id) {
            Some(&(vid, purpose)) => {
                if purpose == handle.purpose {
                    Ok(vid)
                } else {
                    Err(KeystoreError::WrongPurpose)
                }
            }
            None => Err(KeystoreError::UnknownKey),
        }
    }

    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError> {
        let (vid, purpose) = self.keys.get(&handle.id).ok_or(KeystoreError::UnknownKey)?;

        if purpose != &KeyPurpose::Consensus || handle.purpose != KeyPurpose::Consensus {
            return Err(KeystoreError::WrongPurpose);
        }

        let key = (handle.id.clone(), position);
        if let Some(&prev) = self.signed.get(&key)
            && prev != message
        {
            return Err(KeystoreError::ConflictingSign);
        }

        self.signed.insert(key, message);

        Ok(deterministic_mock_signature(*vid, position, message))
    }
}

/// Generates a deterministic 64-byte mock signature from key material and
/// signing coordinates.
fn deterministic_mock_signature(
    validator_id: ValidatorId,
    position: SigningPosition,
    message: Hash256,
) -> [u8; 64] {
    let mut sig = [0u8; 64];

    sig[0..32].copy_from_slice(validator_id.as_bytes());
    sig[32..64].copy_from_slice(message.as_bytes());

    let height = position.height.to_le_bytes();
    let round = position.round.to_le_bytes();

    for (i, &b) in height.iter().enumerate() {
        sig[i] ^= b;
    }
    for (i, &b) in round.iter().enumerate() {
        sig[8 + i] ^= b;
    }

    sig[12] ^= position.phase;

    sig
}
