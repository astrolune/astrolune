// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Explicit height handoff, standby participation and full-roster proof collection.

use super::{
    BlockProducer, ChainSigner, ChainStorage, ContributionPool, DurableSigner, HandoffVerifier,
    LocalBft, NetworkNode, NetworkNodeError, RoundRobinValidator, Signer, StaticNetwork,
    ValidatorId, VrfContribution, input, local,
};

type HeightBinding = (
    Option<RoundRobinValidator>,
    Option<(BlockProducer, DurableSigner)>,
);

impl NetworkNode {
    pub(super) fn receive_contribution(
        &mut self,
        height: u64,
        contribution: VrfContribution,
    ) -> Result<(), NetworkNodeError> {
        if height != self.request().height {
            return Err(input("stale VRF contribution"));
        }
        let pool = self
            .contributions
            .as_mut()
            .ok_or_else(|| input("VRF is not activated"))?;
        if pool.insert(contribution).map_err(input)?
            && let Ok(batch) = pool.complete()
        {
            self.install_contributions(batch)?;
        }
        Ok(())
    }
    pub(super) fn receive_finalized(
        &mut self,
        block: types::Block,
        certificate: &consensus::FinalityCertificate,
    ) -> Result<(), NetworkNodeError> {
        if block.header.height != self.request().height {
            return Err(input("stale or nonsequential finalized block"));
        }
        let committee = self.network.current_committee(self.producer())?;
        committee
            .verify_certificate(certificate, &block.header)
            .map_err(input)?;
        self.producer_mut().prepare_received_vrf(&block)?;
        let proposal = self.producer().execute_received_block(block)?;
        if let Some(participant) = self.participant.as_mut() {
            participant.commit_finalized(&proposal, certificate, &mut self.storage)?;
        } else {
            self.standby
                .as_mut()
                .ok_or_else(|| local("missing standby state"))?
                .0
                .commit_certified_block(&proposal, certificate, &committee, &mut self.storage)?;
        }
        self.advance_height()?;
        Ok(())
    }

    pub(super) fn bind_height(
        network: &StaticNetwork,
        producer: BlockProducer,
        signer: DurableSigner,
    ) -> Result<HeightBinding, NetworkNodeError> {
        let id = signer.validator_id(&signer.key_handle()).map_err(local)?;
        if !signer.is_protected()
            || signer.signing_context().chain_id != network.chain_id()
            || signer.signing_context().genesis != network.hash
            || (!network.potb() && network.committee(1)?.voting_power(id).is_none())
            || signer
                .last_position()
                .is_some_and(|position| position.height > producer.height())
        {
            return Err(local(
                "signer is incompatible with finalized chain position",
            ));
        }
        let committee = network.current_committee(&producer)?;
        if committee.voting_power(id).is_none() {
            // Standby keeps its protected journal and contributes randomness, but cannot vote.
            return Ok((None, Some((producer, signer))));
        }
        let voter = LocalBft::new(network.current_committee(&producer)?, signer, network.hash)
            .map_err(local)?;
        Ok((
            Some(RoundRobinValidator::new(producer, voter, committee)?),
            None,
        ))
    }

    pub(super) fn producer(&self) -> &BlockProducer {
        self.participant.as_ref().map_or_else(
            || {
                &self
                    .standby
                    .as_ref()
                    .expect("height participant available")
                    .0
            },
            RoundRobinValidator::producer,
        )
    }

    pub(super) fn producer_mut(&mut self) -> &mut BlockProducer {
        match self.participant.as_mut() {
            Some(participant) => participant.producer_mut(),
            None => {
                &mut self
                    .standby
                    .as_mut()
                    .expect("height participant available")
                    .0
            }
        }
    }

    pub(super) fn start_contributions(&mut self) -> Result<(), NetworkNodeError> {
        let Some(current) = self.producer().active_committee_state().cloned() else {
            self.contributions = None;
            return Ok(());
        };
        if !current
            .roster()
            .iter()
            .any(|entry| ValidatorId(crypto::blake2s_hash(&entry.public_key).0) == self.voter)
        {
            self.contributions = Some(ContributionPool::new(current));
            return Ok(());
        }
        let prove = |role| {
            let input = current.input(role).map_err(local)?;
            match &self.participant {
                Some(participant) => participant.local().prove_vrf(input).map_err(local),
                None => self
                    .standby
                    .as_ref()
                    .ok_or_else(|| local("missing standby signer"))?
                    .1
                    .prove_vrf(input)
                    .map_err(local),
            }
        };
        let contribution = VrfContribution {
            validator: self.voter,
            committee: prove(crypto::VrfRole::Committee)?,
            producer: prove(crypto::VrfRole::Producer)?,
        };
        let mut pool = ContributionPool::new(current);
        pool.insert(contribution).map_err(local)?;
        if let Ok(batch) = pool.complete() {
            self.install_contributions(batch)?;
        }
        self.contributions = Some(pool);
        Ok(())
    }

    pub(super) fn install_contributions(
        &mut self,
        batch: consensus::rotation::VrfBatch,
    ) -> Result<(), NetworkNodeError> {
        if self.network.potb() {
            self.install_potb_inclusions(&batch)?;
        } else {
            self.producer_mut().set_vrf_batch(batch)?;
        }
        Ok(())
    }

    /// Registered identity remains online for randomness even when it has no voting seat.
    #[must_use]
    pub const fn is_standby(&self) -> bool {
        self.participant.is_none()
    }

    /// Missing proofs pause fresh block production; subsets never define a different lottery.
    #[must_use]
    pub fn missing_contributions(&self) -> Vec<ValidatorId> {
        self.contributions
            .as_ref()
            .map_or_else(Vec::new, ContributionPool::missing)
    }
}

impl StaticNetwork {
    /// Replays authority once for the bounded evidence outbox, rather than once per offender.
    pub(crate) fn verify_evidence_history(
        &self,
        storage: &ChainStorage,
        proofs: &std::collections::BTreeMap<ValidatorId, consensus::DoubleVoteEvidence>,
    ) -> Result<(), NetworkNodeError> {
        if proofs.len() > super::MAX_NETWORK_VALIDATORS {
            return Err(local("evidence roster exceeds its bound"));
        }
        let mut ordered: Vec<_> = proofs.values().collect();
        ordered.sort_by_key(|proof| (proof.height(), proof.voter()));
        let mut potb = self
            .potb
            .as_ref()
            .map(|profile| consensus::potb_transition::PotbVerifier::new(profile, &self.keys))
            .transpose()
            .map_err(local)?;
        let mut trusted = if self.rotating() && !self.potb() {
            Some(HandoffVerifier::new(&self.genesis, &self.keys).map_err(local)?)
        } else {
            None
        };
        let head = storage
            .checkpoint()
            .ok_or_else(|| local("missing checkpoint"))?;
        if self.checkpoint.is_some() {
            (potb, trusted) = self.pinned_authorities(storage)?;
        }
        for proof in ordered {
            if self
                .checkpoint
                .as_ref()
                .is_some_and(|point| proof.height() <= point.checkpoint().height)
            {
                return Err(local("evidence precedes the pinned retention boundary"));
            }
            if proof.height() == 0 || proof.height() > head.height.saturating_add(1) {
                return Err(local("evidence height is not authenticated"));
            }
            let committee = if let Some(trusted) = &mut potb {
                while trusted.current().committee().height() < proof.height() {
                    let handoff = crate::handoff::read_potb_handoff(
                        storage,
                        trusted.current().committee().height(),
                    )
                    .map_err(local)?
                    .ok_or_else(|| local("missing historical PoTB handoff"))?;
                    trusted.apply(&handoff).map_err(local)?;
                }
                trusted.current().committee().context().map_err(local)?
            } else if let Some(trusted) = &mut trusted {
                if proof.height() == 0 || proof.height() > head.height.saturating_add(1) {
                    return Err(local("evidence height is not authenticated"));
                }
                while trusted.current().height() < proof.height() {
                    let handoff = crate::handoff::read_handoff(storage, trusted.current().height())
                        .map_err(local)?
                        .ok_or_else(|| local("missing historical committee handoff"))?;
                    trusted.apply(&handoff).map_err(local)?;
                }
                trusted.current().context().map_err(local)?
            } else {
                self.committee(proof.height())?
            };
            proof.verify(&committee).map_err(local)?;
        }
        Ok(())
    }
}
