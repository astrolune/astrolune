// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Explicit `PoTB` transport. A peer never supplies the initial trust anchor.

use super::{ClientError, JsonValue, TcpRpcClient, proof_hex, remaining};
use consensus::{
    admission::AdmissionCertificate,
    history::HistoricalEvidence,
    potb_transition::{PotbHandoff, PotbVerifier},
};
use std::time::{Duration, Instant};
use types::Hash256;

impl TcpRpcClient {
    /// Fetches one bounded untrusted transition at the exact requested height.
    pub fn potb_handoff(&self, height: u64) -> Result<Option<PotbHandoff>, ClientError> {
        let value = self.call_bounded(
            "potb_handoff",
            JsonValue::Object(vec![(
                "height".into(),
                JsonValue::String(height.to_string()),
            )]),
            PotbHandoff::MAX_BYTES * 2 + 1024,
        )?;
        if value == JsonValue::Null {
            return Ok(None);
        }
        let bytes = proof_hex(
            value
                .as_str()
                .ok_or(ClientError::Protocol("invalid PoTB handoff response"))?,
            PotbHandoff::MAX_BYTES,
        )?;
        let handoff = PotbHandoff::from_bytes(&bytes)
            .map_err(|_| ClientError::Protocol("invalid canonical PoTB handoff"))?;
        if handoff.header.height != height {
            return Err(ClientError::Protocol("PoTB handoff height mismatch"));
        }
        Ok(Some(handoff))
    }

    /// Advances to the next header to verify under a bounded step count and total deadline.
    /// Failure retains only the authenticated prefix.
    pub fn advance_potb_handoffs(
        &self,
        trusted: &mut PotbVerifier,
        target_height: u64,
        max_steps: u64,
        timeout: Duration,
    ) -> Result<(), ClientError> {
        self.advance_potb_handoffs_with(trusted, target_height, max_steps, timeout, |_| Ok(()))
    }

    /// Delivers each verified transition before advancing authority; consumer failure is atomic.
    pub fn advance_potb_handoffs_with(
        &self,
        trusted: &mut PotbVerifier,
        target_height: u64,
        max_steps: u64,
        timeout: Duration,
        mut accept: impl FnMut(&PotbHandoff) -> Result<(), ClientError>,
    ) -> Result<(), ClientError> {
        let steps = target_height
            .checked_sub(trusted.current().committee().height())
            .ok_or(ClientError::Protocol(
                "PoTB target precedes trusted position",
            ))?;
        if steps > max_steps {
            return Err(ClientError::LimitExceeded);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(ClientError::Protocol("PoTB timeout must be in (0, 3600s]"));
        }
        let deadline = Instant::now() + timeout;
        for _ in 0..steps {
            let client = Self {
                address: self.address,
                timeout: self.timeout.min(remaining(deadline)?),
            };
            let handoff = client
                .potb_handoff(trusted.current().committee().height())?
                .ok_or(ClientError::Protocol("required PoTB handoff unavailable"))?;
            let mut next = trusted.clone();
            next.apply(&handoff)
                .map_err(|_| ClientError::Protocol("PoTB handoff authentication failed"))?;
            remaining(deadline)?;
            accept(&handoff)?;
            *trusted = next;
        }
        Ok(())
    }

    /// Submits an already signed quorum certificate. Acceptance is pending, not finality.
    pub fn submit_potb_admission(
        &self,
        certificate: &AdmissionCertificate,
    ) -> Result<Hash256, ClientError> {
        self.submit_potb(
            "submit_potb_admission",
            &certificate
                .to_bytes()
                .map_err(|_| ClientError::LimitExceeded)?,
            certificate.request().id(),
        )
    }

    /// Submits evidence against the current frontier; callers must refresh it after a height change.
    pub fn submit_potb_evidence(
        &self,
        evidence: &HistoricalEvidence,
    ) -> Result<Hash256, ClientError> {
        self.submit_potb(
            "submit_potb_evidence",
            &evidence
                .to_bytes()
                .map_err(|_| ClientError::LimitExceeded)?,
            evidence.evidence().offence_id(),
        )
    }

    /// Submits a canonical update; caller independently authenticates current authority first.
    pub fn submit_governance(
        &self,
        certificate: &consensus::governance::GovernanceCertificate,
    ) -> Result<Hash256, ClientError> {
        self.submit_potb(
            "submit_governance",
            &certificate
                .to_bytes()
                .map_err(|_| ClientError::Protocol("invalid governance certificate"))?,
            certificate.request().id(),
        )
    }

    fn submit_potb(
        &self,
        method: &str,
        bytes: &[u8],
        expected: Hash256,
    ) -> Result<Hash256, ClientError> {
        let value = self.call(
            method,
            JsonValue::Object(vec![(
                "data".into(),
                JsonValue::String(crate::proof::hex(bytes)),
            )]),
        )?;
        let received = super::hash_value(Some(&value))?;
        if received != expected {
            return Err(ClientError::Protocol("submission identifier mismatch"));
        }
        Ok(expected)
    }
}
