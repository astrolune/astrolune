// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Versioned native payment payload within the existing signed transaction.

use types::Address;

use crate::TransactionError;

const TAG: &[u8; 8] = b"ALPAY001";

/// A version-1 native transfer. The enclosing signature authenticates all fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payment {
    /// Ed25519 key whose derived address must equal the transaction sender.
    pub public_key: [u8; 32],
    /// Nonzero destination address, created with nonce zero if absent.
    pub recipient: Address,
    /// Positive number of native balance units to transfer.
    pub amount: u64,
}

impl Payment {
    /// Exact payload size, including the versioned tag.
    pub const ENCODED_LEN: usize = 80;

    /// Encodes the payload. Decoding rejects zero recipients and amounts.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(self.recipient.as_bytes());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes
    }

    /// Decodes the exact version-1 payload without accepting trailing bytes.
    ///
    /// # Errors
    /// Returns `UnsupportedPayload` for unknown, malformed, or zero-value payments.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() != Self::ENCODED_LEN || &bytes[..8] != TAG {
            return Err(TransactionError::UnsupportedPayload);
        }
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&bytes[8..40]);
        let mut recipient = [0; 32];
        recipient.copy_from_slice(&bytes[40..72]);
        let mut amount = [0; 8];
        amount.copy_from_slice(&bytes[72..80]);
        let amount = u64::from_le_bytes(amount);
        if recipient == [0; 32] || amount == 0 {
            return Err(TransactionError::UnsupportedPayload);
        }
        Ok(Self {
            public_key,
            recipient: Address(recipient),
            amount,
        })
    }
}
