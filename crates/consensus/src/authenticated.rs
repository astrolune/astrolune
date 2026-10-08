// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fixed-height committee authentication against independently trusted membership.

use crate::{
    Committee, ConsensusError, FinalityCertificate, Proposal, Vote, VotePhase, quorum_power,
};
use crypto::{Blake2sProvider, CryptoProvider, DigestRequest};
use std::collections::{BTreeMap, BTreeSet};
use types::{BlockHeader, Hash256, ValidatorId};

/// Version-1 bound on committee seats and certificate signatures.
pub const MAX_COMMITTEE_MEMBERS: usize = 4096;

impl Committee {
    /// Validates unique positive weights and returns their checked total.
    pub fn total_power(&self) -> Result<u128, ConsensusError> {
        if self.members.is_empty() || self.members.len() > MAX_COMMITTEE_MEMBERS {
            return Err(ConsensusError::InvalidCommittee);
        }
        let mut seen = BTreeSet::new();
        self.members.iter().try_fold(0u128, |total, member| {
            if member.power.0 == 0 || !seen.insert(member.id) {
                return Err(ConsensusError::InvalidCommittee);
            }
            total
                .checked_add(member.power.0)
                .ok_or(ConsensusError::InvalidCommittee)
        })
    }

    /// Commits version, chain, height, seat order, identities, and full-width weights.
    pub fn commitment(&self, chain_id: u32) -> Result<Hash256, ConsensusError> {
        self.total_power()?;
        let mut bytes = Vec::with_capacity(24 + 48 * self.members.len());
        bytes.extend_from_slice(b"ALCM");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        let count =
            u32::try_from(self.members.len()).map_err(|_| ConsensusError::InvalidCommittee)?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for member in &self.members {
            bytes.extend_from_slice(&member.id.0);
            bytes.extend_from_slice(&member.power.0.to_le_bytes());
        }
        Ok(types::hash::domain_hash(types::domain::COMMITTEE, &bytes))
    }
}

/// Immutable verification context for one chain and height.
///
/// The caller obtains membership and weights from trusted finalized state. Key
/// ownership is checked against validator IDs; this does not select a committee.
pub struct AuthenticatedCommittee {
    chain_id: u32,
    height: u64,
    root: Hash256,
    total: u128,
    powers: BTreeMap<ValidatorId, u128>,
    seats: Vec<ValidatorId>,
    crypto: Blake2sProvider,
}

impl AuthenticatedCommittee {
    /// Authenticated member identities in canonical identity order.
    pub fn members(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.powers.keys().copied()
    }
    /// Returns the trusted voting power of a registered committee member.
    #[must_use]
    pub fn voting_power(&self, validator: ValidatorId) -> Option<u128> {
        self.powers.get(&validator).copied()
    }
    /// Validates membership and an exact, complete set of strong registered keys.
    pub fn new(
        chain_id: u32,
        committee: &Committee,
        public_keys: &[[u8; 32]],
    ) -> Result<Self, ConsensusError> {
        let total = committee.total_power()?;
        let root = committee.commitment(chain_id)?;
        if public_keys.len() != committee.members.len() {
            return Err(ConsensusError::InvalidCommittee);
        }
        let powers: BTreeMap<_, _> = committee
            .members
            .iter()
            .map(|m| (m.id, m.power.0))
            .collect();
        let mut crypto = Blake2sProvider::new();
        let mut registered = BTreeSet::new();
        for key in public_keys {
            let id = crypto
                .register_validator(*key)
                .map_err(|_| ConsensusError::InvalidProof)?;
            if !powers.contains_key(&id) || !registered.insert(id) {
                return Err(ConsensusError::InvalidCommittee);
            }
        }
        Ok(Self {
            chain_id,
            height: committee.height,
            root,
            total,
            powers,
            seats: committee.members.iter().map(|member| member.id).collect(),
            crypto,
        })
    }

    /// Expected chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Exact height authenticated by this context.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Commitment used by votes and block headers.
    #[must_use]
    pub const fn root(&self) -> Hash256 {
        self.root
    }

    /// Strictly greater than two thirds of the checked total power.
    #[must_use]
    pub const fn quorum(&self) -> u128 {
        quorum_power(self.total)
    }

    /// Reference round-robin designation over committed seat order, ignoring weights.
    /// This explicit local policy is not the planned weighted VRF producer selection.
    #[must_use]
    pub fn round_robin_proposer(&self, round: u32) -> ValidatorId {
        let count = self.seats.len() as u64;
        let index = (self.height % count + u64::from(round) % count) % count;
        // Construction bounds count to 4096, so index fits even a 32-bit usize.
        #[allow(clippy::cast_possible_truncation)]
        let index = index as usize;
        self.seats[index]
    }

    /// Authenticates a proposal against trusted designation, genesis, and exact header.
    /// Designation is obtained from a shared trusted policy, never from the message.
    pub fn verify_proposal(
        &self,
        proposal: &Proposal,
        header: &BlockHeader,
        expected_proposer: ValidatorId,
        genesis: Hash256,
    ) -> Result<(), ConsensusError> {
        if genesis == Hash256::ZERO
            || proposal.genesis != genesis
            || proposal.chain_id != self.chain_id
            || proposal.height != self.height
            || proposal.committee_root != self.root
            || header.height != self.height
            || header.committee_root != self.root
            || proposal.block != header.compute_hash()
            || proposal.proposer != expected_proposer
            || proposal
                .valid_round
                .is_some_and(|round| round >= proposal.round)
        {
            return Err(ConsensusError::InvalidTransition);
        }
        if !self.powers.contains_key(&expected_proposer) {
            return Err(ConsensusError::UnknownVoter);
        }
        if !self.crypto.verify_signature(
            proposal.proposer,
            &proposal.signing_hash().0,
            &proposal.signature,
        ) {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(())
    }

    /// Verifies all signed context fields and returns this voter's trusted power.
    pub fn verify_vote(&self, vote: &Vote) -> Result<u128, ConsensusError> {
        let (power, request) = self.vote_credentials(vote)?;
        if !request.verify() {
            return Err(ConsensusError::InvalidProof);
        }
        Ok(power)
    }

    /// Resolves the non-cryptographic part of [`Self::verify_vote`] in its exact order.
    ///
    /// Returns this voter's trusted power together with a fully prepared strict
    /// verification request. A caller may run the cheap checks for an entire
    /// certificate before deciding any signature, then batch the signatures,
    /// and still report the error the serial order would have reported: a
    /// rejection here always sits at a lower position than any signature
    /// failure it stops the caller from reaching. A registered identity always
    /// has a registered key, so the `InvalidProof` below is unreachable; it
    /// mirrors what `verify_signature` returns for an unknown key.
    pub(crate) fn vote_credentials(
        &self,
        vote: &Vote,
    ) -> Result<(u128, DigestRequest), ConsensusError> {
        if vote.chain_id != self.chain_id
            || vote.height != self.height
            || vote.committee_root != self.root
        {
            return Err(ConsensusError::InvalidTransition);
        }
        let power = *self
            .powers
            .get(&vote.voter)
            .ok_or(ConsensusError::UnknownVoter)?;
        let public_key = self
            .crypto
            .registered_key(vote.voter)
            .ok_or(ConsensusError::InvalidProof)?;
        Ok((
            power,
            DigestRequest {
                public_key,
                digest: vote.signing_hash().0,
                signature: vote.signature,
            },
        ))
    }

    /// Independently authenticates a canonical precommit quorum for this exact header.
    pub fn verify_certificate(
        &self,
        certificate: &FinalityCertificate,
        header: &BlockHeader,
    ) -> Result<(), ConsensusError> {
        certificate
            .validate_shape()
            .map_err(|_| ConsensusError::InvalidCertificate)?;
        if header.height != self.height
            || header.committee_root != self.root
            || certificate.chain_id != self.chain_id
            || certificate.height != self.height
            || certificate.committee_root != self.root
            || certificate.block != header.compute_hash()
            || certificate.signatures.len() > self.powers.len()
        {
            return Err(ConsensusError::InvalidCertificate);
        }
        // Hoist every cheap check, keeping its serial order, and stop at the
        // first one that rejects. Only entries below that position were reached
        // serially, so they are exactly the signatures to decide as one batch.
        let mut batch = Vec::with_capacity(certificate.signatures.len());
        let mut weights = Vec::with_capacity(certificate.signatures.len());
        let mut rejected = None;
        for entry in &certificate.signatures {
            let vote = Vote {
                chain_id: certificate.chain_id,
                committee_root: certificate.committee_root,
                height: certificate.height,
                round: certificate.round,
                phase: VotePhase::Precommit,
                block: Some(certificate.block),
                voter: entry.voter,
                signature: entry.signature,
            };
            match self.vote_credentials(&vote) {
                Ok((power, request)) => {
                    weights.push(power);
                    batch.push(request);
                }
                Err(error) => {
                    rejected = Some(error);
                    break;
                }
            }
        }
        if crypto::batch::first_digest_failure(&batch).is_some() {
            return Err(ConsensusError::InvalidProof);
        }
        if let Some(error) = rejected {
            return Err(error);
        }
        let total = weights.into_iter().try_fold(0u128, |total, power| {
            total
                .checked_add(power)
                .ok_or(ConsensusError::InvalidCertificate)
        })?;
        if total < self.quorum() {
            return Err(ConsensusError::InvalidCertificate);
        }
        Ok(())
    }
}
