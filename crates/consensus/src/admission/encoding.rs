// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Exact, bounded admission envelopes; canonical decoding is not authorization.

use super::{
    AdmissionApproval, AdmissionCertificate, AdmissionIntent, AdmissionRequest, DecodeError,
    Decoder, Hash256, MAX_ROTATION_VALIDATORS, ValidatorId,
};

impl AdmissionRequest {
    /// Exact request size, including candidate consent.
    pub const BYTES: usize = 8 + AdmissionIntent::BYTES + 64;

    /// Encodes signed context without claiming that it matches trusted authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.intent.validate()?;
        let mut bytes = b"ALADRQ01".to_vec();
        bytes.extend_from_slice(&self.intent.to_bytes());
        bytes.extend_from_slice(&self.consent);
        Ok(bytes)
    }

    /// Decodes one exact, fixed-size request without verifying signatures.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::NonCanonical);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALADRQ01" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            intent: AdmissionIntent::from_bytes(decoder.read_exact(AdmissionIntent::BYTES)?)?,
            consent: decoder.read_fixed()?,
        };
        decoder.finish()?;
        Ok(result)
    }
}

impl AdmissionApproval {
    /// Exact detached approval envelope size.
    pub const BYTES: usize = 136;

    /// Serializes the signed request commitment and voter without normalization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALADAP01".to_vec();
        bytes.extend_from_slice(&self.request.0);
        bytes.extend_from_slice(&self.voter.0);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes exact structure; signatures require an independently trusted request.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::NonCanonical);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALADAP01" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            request: Hash256(decoder.read_fixed()?),
            voter: ValidatorId(decoder.read_fixed()?),
            signature: decoder.read_fixed()?,
        };
        decoder.finish()?;
        if result.request == Hash256::ZERO || result.voter == ValidatorId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(result)
    }
}

impl AdmissionCertificate {
    /// Maximum request plus at most 32 unique incumbent signatures.
    pub const MAX_BYTES: usize = 9 + AdmissionRequest::BYTES + 96 * MAX_ROTATION_VALIDATORS;

    pub(super) fn validate_shape(&self) -> Result<(), DecodeError> {
        self.request.intent.validate()?;
        if self.approvals.is_empty() || self.approvals.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        if self.approvals.windows(2).any(|p| p[0].voter >= p[1].voter)
            || self
                .approvals
                .iter()
                .any(|a| a.voter == ValidatorId::ZERO || a.request != self.request.id())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Encodes canonical order without discarding surplus signatures.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let mut bytes = b"ALADCT01".to_vec();
        bytes.extend_from_slice(&self.request.to_bytes()?);
        bytes.push(u8::try_from(self.approvals.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for approval in &self.approvals {
            bytes.extend_from_slice(&approval.voter.0);
            bytes.extend_from_slice(&approval.signature);
        }
        Ok(bytes)
    }

    /// Preflights the complete fixed-width body before allocating approvals.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALADCT01" {
            return Err(DecodeError::Unsupported);
        }
        let request_bytes = decoder.read_exact(AdmissionRequest::BYTES)?;
        let count = usize::from(decoder.read_u8()?);
        if count == 0 || count > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        if decoder.remaining() != count * 96 {
            return Err(DecodeError::NonCanonical);
        }
        let request = AdmissionRequest::from_bytes(request_bytes)?;
        let request_id = request.id();
        let mut approvals = Vec::with_capacity(count);
        for _ in 0..count {
            approvals.push(AdmissionApproval {
                request: request_id,
                voter: ValidatorId(decoder.read_fixed()?),
                signature: decoder.read_fixed()?,
            });
        }
        decoder.finish()?;
        let result = Self { request, approvals };
        result.validate_shape()?;
        Ok(result)
    }
}
