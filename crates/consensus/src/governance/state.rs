// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Immutable bounds and the single next-epoch update slot.

use super::{GovernanceCertificate, GovernanceIntent};
use crate::{ConsensusError, rotation::CommitteeState};
use types::{Hash256, Resources};

/// Conservative floor allowing a full 32-key system transition and parameter approval.
pub const GOVERNANCE_CAPACITY_FLOOR: Resources = Resources {
    compute: 500_000,
    memory: 131_072,
    io: 16_384,
    bandwidth: 65_536,
};

/// Parameters applied to every application transaction at one finalized height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkParameters {
    /// Block resource ceilings.
    pub capacity: Resources,
    /// Integer fee prices for actual consumed resources.
    pub prices: Resources,
}

/// Independently configured, immutable bounds on quorum-authorized changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernancePolicy {
    /// Epoch length; the first epoch contains heights 1 through this value.
    pub epoch_blocks: u64,
    /// Per-resource capacity floor, keeping system work possible.
    pub minimum_capacity: Resources,
    /// Per-resource capacity ceiling.
    pub maximum_capacity: Resources,
    /// Per-resource fee ceiling. Zero prices are permitted within these limits.
    pub maximum_prices: Resources,
}
impl GovernancePolicy {
    /// Checks positive epochs and capacity dimensions, and componentwise bounds.
    pub fn validate(self) -> Result<(), ConsensusError> {
        if self.epoch_blocks == 0
            || self.minimum_capacity.compute == 0
            || self.minimum_capacity.memory == 0
            || self.minimum_capacity.io == 0
            || self.minimum_capacity.bandwidth == 0
            || !GOVERNANCE_CAPACITY_FLOOR.fits_in(self.minimum_capacity)
            || !self.minimum_capacity.fits_in(self.maximum_capacity)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(())
    }
    /// Validates both current and proposed parameters against the immutable policy.
    pub fn permits(self, value: NetworkParameters) -> Result<(), ConsensusError> {
        self.validate()?;
        if !self.minimum_capacity.fits_in(value.capacity)
            || !value.capacity.fits_in(self.maximum_capacity)
            || !value.prices.fits_in(self.maximum_prices)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(())
    }
    fn next_epoch(self, height: u64) -> Result<u64, ConsensusError> {
        height
            .checked_sub(1)
            .and_then(|h| h.checked_div(self.epoch_blocks))
            .and_then(|epoch| epoch.checked_add(1))
            .and_then(|epoch| epoch.checked_mul(self.epoch_blocks))
            .and_then(|height| height.checked_add(1))
            .ok_or(ConsensusError::InvalidTransition)
    }
}

/// Authenticated active parameters plus at most one finalized future update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceState {
    pub(super) policy: GovernancePolicy,
    pub(super) active: NetworkParameters,
    pub(super) pending: Option<(u64, NetworkParameters)>,
}
impl GovernanceState {
    /// Establishes initial policy from independently supplied configuration.
    pub fn new(
        policy: GovernancePolicy,
        active: NetworkParameters,
    ) -> Result<Self, ConsensusError> {
        policy.permits(active)?;
        Ok(Self {
            policy,
            active,
            pending: None,
        })
    }
    /// Immutable policy.
    #[must_use]
    pub const fn policy(&self) -> GovernancePolicy {
        self.policy
    }
    /// Parameters used by the current height, before its system transition.
    #[must_use]
    pub const fn active(&self) -> NetworkParameters {
        self.active
    }
    /// Finalized update waiting for its first eligible height.
    #[must_use]
    pub const fn pending(&self) -> Option<(u64, NetworkParameters)> {
        self.pending
    }

    /// Prepares the exact request for the next epoch boundary.
    pub fn request(
        &self,
        current: &CommitteeState,
        parent: Hash256,
        value: NetworkParameters,
    ) -> Result<GovernanceIntent, ConsensusError> {
        let request = GovernanceIntent {
            chain_id: current.chain_id(),
            genesis: current.genesis(),
            height: current.height(),
            parent,
            committee_root: current.context()?.root(),
            activate_at: self.policy.next_epoch(current.height())?,
            capacity: value.capacity,
            prices: value.prices,
        };
        self.verify_request(current, parent, &request)?;
        Ok(request)
    }

    pub(super) fn verify_request(
        &self,
        current: &CommitteeState,
        parent: Hash256,
        request: &GovernanceIntent,
    ) -> Result<(), ConsensusError> {
        self.validate(current.height())?;
        request
            .validate()
            .map_err(|_| ConsensusError::InvalidTransition)?;
        if self.pending.is_some()
            || request.chain_id != current.chain_id()
            || request.genesis != current.genesis()
            || request.height != current.height()
            || request.parent != parent
            || request.committee_root != current.context()?.root()
            || request.activate_at != self.policy.next_epoch(current.height())?
        {
            return Err(ConsensusError::InvalidTransition);
        }
        self.policy.permits(NetworkParameters {
            capacity: request.capacity,
            prices: request.prices,
        })
    }

    /// Computes the next height's parameters after verifying any current-incumbent update.
    pub fn stage(
        &self,
        current: &CommitteeState,
        parent: Hash256,
        certificate: Option<&GovernanceCertificate>,
    ) -> Result<Self, ConsensusError> {
        self.validate(current.height())?;
        let next_height = current
            .height()
            .checked_add(1)
            .ok_or(ConsensusError::InvalidTransition)?;
        let mut next = self.clone();
        if let Some(certificate) = certificate {
            certificate.verify(current, parent, self)?;
            let request = certificate.request();
            next.pending = Some((
                request.activate_at,
                NetworkParameters {
                    capacity: request.capacity,
                    prices: request.prices,
                },
            ));
        }
        if let Some((height, parameters)) = next.pending
            && height == next_height
        {
            next.active = parameters;
            next.pending = None;
        }
        next.validate(next_height)?;
        Ok(next)
    }

    /// Checks bounds and pending activation coordinates without establishing authority.
    pub fn validate(&self, height: u64) -> Result<(), ConsensusError> {
        self.policy.permits(self.active)?;
        if height == 0 {
            return Err(ConsensusError::InvalidTransition);
        }
        if let Some((at, parameters)) = self.pending {
            self.policy.permits(parameters)?;
            if at <= height || at != self.policy.next_epoch(height)? {
                return Err(ConsensusError::InvalidTransition);
            }
        }
        Ok(())
    }
}
