// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Key types: purpose classification, opaque handles, and signing coordinates.

use types::Hash256;

/// Durable journal phase for a proposal (not a vote wire tag).
pub const PROPOSAL_PHASE: u8 = 0;
/// Durable journal phase for a prevote (wire phase 0).
pub const PREVOTE_PHASE: u8 = 1;
/// Durable journal phase for a precommit (wire phase 1).
pub const PRECOMMIT_PHASE: u8 = 2;

/// Immutable namespace for one validator's signing journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningContext {
    /// Chain ID covered by consensus vote digests.
    pub chain_id: u32,
    /// Independently trusted genesis commitment; must be nonzero.
    pub genesis: Hash256,
}

/// Block retained by the local BFT lock across later rounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningLock {
    /// Round whose prevote quorum justified this lock.
    pub round: u32,
    /// Locked block header hash.
    pub block: Hash256,
}

/// Safety metadata atomically reserved with a protected vote digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningSafety {
    /// Immutable committee commitment for this signing height.
    pub committee_root: Hash256,
    /// Latest lock, retained even when signing nil votes.
    pub locked: Option<SigningLock>,
}

/// Allowed key purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    /// Consensus proposals and votes.
    Consensus,
    /// Peer transport authentication.
    Network,
    /// Ecosystem service identity.
    Service,
    /// End-user wallet operations.
    Wallet,
}

/// Opaque key reference. Secret bytes are never returned by this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyHandle {
    /// Provider-specific non-secret identifier.
    pub id: String,
    /// Operation family allowed for the key.
    pub purpose: KeyPurpose,
}

/// Consensus signing coordinates protected against equivocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SigningPosition {
    /// Consensus height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Journal phase: proposal 0, prevote 1, or precommit 2; distinct from wire tags.
    pub phase: u8,
}
