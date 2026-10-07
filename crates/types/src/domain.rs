// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Protocol domain separators used for domain hashing and signing.
//!
//! Each tag is a unique ASCII string that prevents cross-domain signature or
//! hash reuse. Tags are prefixed with the protocol name and version to avoid
//! collisions with other systems.

/// Transaction signing domain.
pub const TRANSACTION: &[u8] = b"astrolune.tx.v1";

/// Signed transaction identifier domain.
pub const TRANSACTION_ID: &[u8] = b"astrolune.tx.id.v1";

/// Ed25519 wallet address derivation domain.
pub const ACCOUNT_ADDRESS: &[u8] = b"astrolune.account.ed25519.v1";

/// Block header signing domain.
pub const BLOCK_HEADER: &[u8] = b"astrolune.block.v1";

/// `PoTB` weight commitment domain.
pub const POTB_WEIGHT: &[u8] = b"astrolune.potb.weight.v1";

/// Committee root commitment domain.
pub const COMMITTEE: &[u8] = b"astrolune.committee.v1";

/// Genesis activation marker for the explicit rotating consensus profile.
pub const ROTATING_PROFILE_KEY: &[u8] = b"astrolune/consensus/profile/v2";

/// Reserved finalized state key for the next rotating committee.
pub const COMMITTEE_STATE_KEY: &[u8] = b"astrolune/consensus/committee/v1";

/// Reserved finalized authority for the explicit `PoTB` configuration namespace.
pub const POTB_STATE_KEY: &[u8] = b"astrolune.potb.state.v1";

/// Finality certificate domain.
pub const FINALITY: &[u8] = b"astrolune.finality.v1";

/// Consensus vote signing digest domain.
pub const CONSENSUS_VOTE: &[u8] = b"astrolune.vote.v1";

/// Consensus proposal signing digest domain.
pub const CONSENSUS_PROPOSAL: &[u8] = b"astrolune.proposal.v1";

/// VRF evaluation domain for committee selection.
pub const VRF_COMMITTEE: &[u8] = b"astrolune.vrf.committee.v1";

/// VRF evaluation domain for producer selection.
pub const VRF_PRODUCER: &[u8] = b"astrolune.vrf.producer.v1";

/// Genesis hash domain.
pub const GENESIS: &[u8] = b"astrolune.genesis.v1";

/// State root commitment domain.
pub const STATE_ROOT: &[u8] = b"astrolune.state.v1";

/// Length-framed state key/value leaf.
pub const STATE_LEAF: &[u8] = b"astrolune.state.leaf.v1";

/// Ordered pair of state Merkle children.
pub const STATE_NODE: &[u8] = b"astrolune.state.node.v1";

/// Ordered execution diff commitment.
pub const STATE_DIFF: &[u8] = b"astrolune.state.diff.v1";

/// Execution receipt commitment domain.
pub const RECEIPT: &[u8] = b"astrolune.receipt.v1";
