// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Committee types and selection trait.

use crate::weight::PotbWeight;
use crypto::VrfOutput;
use types::ValidatorId;

/// A validator eligible for committee selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Stable validator identity.
    pub id: ValidatorId,
    /// Effective `PoTB` weight after protocol caps and penalties.
    pub weight: PotbWeight,
    /// `VRF` result for the target height.
    pub vrf: VrfOutput,
}

/// A selected committee member and their voting power.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitteeMember {
    /// Validator identity.
    pub id: ValidatorId,
    /// Voting power used for quorum accounting.
    pub power: PotbWeight,
}

/// Ordered committee for one consensus height.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Committee {
    /// Height at which this membership becomes active.
    pub height: u64,
    /// Ordered unique membership.
    pub members: Vec<CommitteeMember>,
}

/// Legacy infallible selection interface used only by demonstration fixtures.
/// Authenticated weighted selection uses [`crate::VerifiedVrfSampler`].
pub trait CommitteeSelector {
    /// Builds the next committee while retaining the configured fraction of
    /// current members. Implementations must be deterministic after `VRF` proof
    /// verification and canonical tie-breaking by validator identity.
    fn rotate(
        &self,
        current: &Committee,
        candidates: &[Candidate],
        replacement_count: usize,
    ) -> Committee;
}
