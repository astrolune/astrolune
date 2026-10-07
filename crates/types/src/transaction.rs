// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical signed transaction envelope.

use crate::address::Address;
use crate::resources::Resources;
use crate::state_key::StateKey;

/// Current canonical transaction wire version.
pub const TRANSACTION_VERSION: u32 = 1;

/// Signed execution lane; discriminants are part of the canonical wire format.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TransactionLane {
    /// Native account transfers.
    Payments = 0,
    /// Reserved for contract deployment and calls.
    Contracts = 1,
    /// Reserved for consensus-governed operations.
    System = 2,
}

impl TransactionLane {
    /// Legacy demonstration classification; authenticated execution uses the signed lane.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Self {
        match payload.len() {
            0 => Self::System,
            1..=128 => Self::Payments,
            _ => Self::Contracts,
        }
    }
}

/// A canonical signed transaction envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Wire version; unsupported versions are rejected before admission.
    pub version: u32,
    /// Last block height at which inclusion is authorized, inclusive.
    pub expires_at: u64,
    /// Signed execution lane.
    pub lane: TransactionLane,
    /// Exact per-resource prices authorized by the sender.
    pub resource_prices: Resources,
    /// Network replay-protection identifier.
    pub chain_id: u32,
    /// Sender account.
    pub sender: Address,
    /// Sender sequence number.
    pub nonce: u64,
    /// Declared state keys needed by execution.
    pub access_list: Vec<StateKey>,
    /// Maximum resources the sender authorizes.
    pub resource_limit: Resources,
    /// Canonical transaction payload.
    pub payload: Vec<u8>,
    /// Signature over every preceding canonical field.
    pub signature: [u8; 64],
}
