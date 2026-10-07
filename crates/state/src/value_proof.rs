// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical authenticated value-or-absence transport.

use crate::{StateAbsenceProof, StateError, StateSnapshot, StateWitness};
use types::{Hash256, StateKey};

/// Exactly one authenticated value or authenticated absence under an external root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateValueProof {
    /// Full key/value and membership path.
    Present(StateWitness),
    /// Adjacent witnesses proving no value exists for the queried key.
    Absent(StateAbsenceProof),
}

impl StateValueProof {
    /// Maximum proof bytes, including the tagged framing.
    pub const MAX_BYTES: usize = 1 + crate::MAX_ABSENCE_PROOF_BYTES;

    /// Constructs a proof against one immutable snapshot.
    pub fn create(snapshot: &dyn StateSnapshot, key: &StateKey) -> Result<Self, StateError> {
        if key.len() > crate::MAX_STATE_KEY_BYTES {
            return Err(StateError::LimitExceeded);
        }
        if let Some(value) = snapshot.get(key)? {
            let proof = snapshot.prove(key)?.ok_or(StateError::Corrupt)?;
            Ok(Self::Present(StateWitness {
                key: key.clone(),
                value,
                proof,
            }))
        } else {
            Ok(Self::Absent(
                snapshot.prove_absence(key)?.ok_or(StateError::Corrupt)?,
            ))
        }
    }

    /// Authenticates the exact requested key against an independently trusted root.
    pub fn verify<'a>(
        &'a self,
        root: Hash256,
        key: &StateKey,
    ) -> Result<Option<&'a [u8]>, StateError> {
        match self {
            Self::Present(witness)
                if witness.key == *key && witness.proof.verify(root, key, &witness.value) =>
            {
                Ok(Some(&witness.value))
            }
            Self::Absent(proof) if proof.verify(root, key) => Ok(None),
            _ => Err(StateError::Corrupt),
        }
    }

    /// Encodes a type tag followed by the bounded version-1 witness framing.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StateError> {
        let witnesses = match self {
            Self::Present(witness) => [Some(witness), None],
            Self::Absent(proof) => [proof.lower.as_ref(), proof.upper.as_ref()],
        };
        for witness in witnesses.into_iter().flatten() {
            if witness.key.len() > crate::MAX_STATE_KEY_BYTES
                || witness.value.len() > crate::MAX_STATE_VALUE_BYTES
                || witness.proof.siblings.len() > 20
                || witness.proof.leaf_count == 0
                || witness.proof.leaf_count > crate::MAX_STATE_ENTRIES as u64
                || witness.proof.index >= witness.proof.leaf_count
            {
                return Err(StateError::LimitExceeded);
            }
        }
        let (tag, proof) = match self {
            Self::Present(witness) => (
                1,
                StateAbsenceProof {
                    lower: Some(witness.clone()),
                    upper: None,
                },
            ),
            Self::Absent(proof) => (0, proof.clone()),
        };
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&proof.to_bytes()?);
        Ok(bytes)
    }

    /// Decodes bounded canonical framing; successful decoding alone authenticates nothing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return Err(StateError::LimitExceeded);
        }
        let proof = StateAbsenceProof::from_bytes(&bytes[1..])?;
        match (bytes[0], proof) {
            (0, proof) => Ok(Self::Absent(proof)),
            (
                1,
                StateAbsenceProof {
                    lower: Some(witness),
                    upper: None,
                },
            ) => Ok(Self::Present(witness)),
            _ => Err(StateError::Corrupt),
        }
    }
}
