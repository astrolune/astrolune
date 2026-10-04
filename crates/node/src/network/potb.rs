// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded current-parent submissions. Quorum signing remains an explicit operator action.

use super::{NetworkNode, NetworkNodeError, input};
use consensus::{
    admission::AdmissionCertificate, history::HistoricalEvidence, potb_transition::PotbBatch,
    rotation::VrfBatch,
};
use types::Hash256;

impl NetworkNode {
    /// Queues authenticated consent/quorum for the current height and relays it to peers.
    /// Acceptance is pending inclusion, not a promise of finality. Resubmit for a new parent.
    pub fn submit_potb_admission(
        &mut self,
        certificate: AdmissionCertificate,
    ) -> Result<Hash256, NetworkNodeError> {
        let id = certificate.request().id();
        if self.queue_potb_admission(certificate)? {
            self.refresh_potb_inclusions()?;
            self.persist_cache()?;
        }
        Ok(id)
    }

    /// Queues authenticated historical evidence for this exact finalized frontier.
    pub fn submit_potb_evidence(
        &mut self,
        evidence: HistoricalEvidence,
    ) -> Result<Hash256, NetworkNodeError> {
        let id = evidence.evidence().offence_id();
        if self.queue_potb_evidence(evidence)? {
            self.refresh_potb_inclusions()?;
            self.persist_cache()?;
        }
        Ok(id)
    }

    pub(super) fn queue_potb_admission(
        &mut self,
        certificate: AdmissionCertificate,
    ) -> Result<bool, NetworkNodeError> {
        let current = self
            .producer()
            .potb_state()
            .ok_or_else(|| input("PoTB is not activated"))?;
        certificate
            .verify(current.committee(), self.producer().parent_hash())
            .map_err(input)?;
        let candidate = certificate.request().candidate();
        if current.records().any(|(id, _)| id == candidate)
            || current.records().count() + self.admissions.len() >= 32
                && !self.admissions.contains_key(&candidate)
        {
            return Err(input("candidate is registered or roster is full"));
        }
        if self.admissions.contains_key(&candidate) {
            return Ok(false);
        }
        self.admissions.insert(candidate, certificate);
        Ok(true)
    }

    pub(super) fn queue_potb_evidence(
        &mut self,
        evidence: HistoricalEvidence,
    ) -> Result<bool, NetworkNodeError> {
        let current = self
            .producer()
            .potb_state()
            .ok_or_else(|| input("PoTB is not activated"))?;
        evidence.verify(current.history()).map_err(input)?;
        let voter = evidence.evidence().voter();
        let record = current
            .records()
            .find(|(id, _)| *id == voter)
            .ok_or_else(|| input("unknown offender"))?
            .1;
        if record.disqualification.is_some() || evidence.evidence().height() <= record.admitted_at {
            return Err(input("offence already included or predates admission"));
        }
        if self.inclusions.contains_key(&voter) {
            return Ok(false);
        }
        self.inclusions.insert(voter, evidence);
        Ok(true)
    }

    fn refresh_potb_inclusions(&mut self) -> Result<(), NetworkNodeError> {
        if let Some(batch) = self
            .contributions
            .as_ref()
            .and_then(|pool| pool.complete().ok())
        {
            self.install_potb_inclusions(&batch)?;
        }
        Ok(())
    }

    pub(super) fn install_potb_inclusions(
        &mut self,
        contributions: &VrfBatch,
    ) -> Result<(), NetworkNodeError> {
        let mut evidence = Vec::new();
        let mut admissions = Vec::new();
        self.producer_mut().set_potb_batch(
            PotbBatch::new(contributions.clone(), vec![], vec![]).map_err(input)?,
        )?;
        // Canonical identity order and bounded incremental selection. Oversized or committee-
        // exhausting combinations cannot prevent a valid empty transition from being proposed.
        for item in self.inclusions.values().cloned().collect::<Vec<_>>() {
            evidence.push(item);
            let batch =
                PotbBatch::new(contributions.clone(), evidence.clone(), vec![]).map_err(input)?;
            if self.producer_mut().set_potb_batch(batch).is_err() {
                evidence.pop();
            }
        }
        for item in self.admissions.values().cloned().collect::<Vec<_>>() {
            admissions.push(item);
            let batch = PotbBatch::new(contributions.clone(), evidence.clone(), admissions.clone())
                .map_err(input)?;
            if self.producer_mut().set_potb_batch(batch).is_err() {
                admissions.pop();
            }
        }
        Ok(())
    }

    pub(super) fn restore_potb_inclusions(
        &mut self,
        messages: &[super::NetworkMessage],
    ) -> Result<(), NetworkNodeError> {
        for message in messages {
            match message {
                super::NetworkMessage::PotbAdmission(value) => {
                    let _ = self.queue_potb_admission(value.clone());
                }
                super::NetworkMessage::PotbEvidence(value) => {
                    let _ = self.queue_potb_evidence(value.clone());
                }
                _ => {}
            }
        }
        if self.network.potb() {
            self.refresh_potb_inclusions()?;
        }
        Ok(())
    }
}
