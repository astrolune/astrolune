// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded version-1 finality certificate envelopes.

use crate::MAX_COMMITTEE_MEMBERS;
use codec::{DecodeError, Decoder};
use types::{Hash256, ValidatorId};

/// One validator's precommit signature over the certificate context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSignature {
    /// Validator identity, strictly ascending in an encoded certificate.
    pub voter: ValidatorId,
    /// Ed25519 signature over the reconstructed vote digest.
    pub signature: [u8; 64],
}

/// Precommit quorum evidence; decoding alone does not authenticate it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalityCertificate {
    /// Chain identity.
    pub chain_id: u32,
    /// Finalized height.
    pub height: u64,
    /// One shared voting round.
    pub round: u32,
    /// Trusted weighted committee commitment.
    pub committee_root: Hash256,
    /// Finalized block header hash.
    pub block: Hash256,
    /// Nonempty, bounded signatures sorted by unique validator identity.
    pub signatures: Vec<CertificateSignature>,
}

impl FinalityCertificate {
    pub(crate) fn validate_shape(&self) -> Result<(), DecodeError> {
        if self.signatures.is_empty() || self.signatures.len() > MAX_COMMITTEE_MEMBERS {
            return Err(DecodeError::LimitExceeded);
        }
        if self
            .signatures
            .windows(2)
            .any(|pair| pair[0].voter >= pair[1].voter)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Encodes a structurally valid certificate without normalizing signer order.
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(92 + 96 * self.signatures.len());
        bytes.extend_from_slice(b"ALFC");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.round.to_le_bytes());
        bytes.extend_from_slice(&self.committee_root.0);
        bytes.extend_from_slice(&self.block.0);
        let count = u32::try_from(self.signatures.len()).map_err(|_| DecodeError::LimitExceeded)?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for entry in &self.signatures {
            bytes.extend_from_slice(&entry.voter.0);
            bytes.extend_from_slice(&entry.signature);
        }
        Ok(bytes)
    }

    /// Decodes exact bounded bytes; checks the complete length before allocating.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > 92 + 96 * MAX_COMMITTEE_MEMBERS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_fixed::<4>()? != *b"ALFC" || decoder.read_u32()? != 1 {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = decoder.read_u32()?;
        let height = decoder.read_u64()?;
        let round = decoder.read_u32()?;
        let committee_root = Hash256(decoder.read_fixed()?);
        let block = Hash256(decoder.read_fixed()?);
        let count =
            usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::LengthOverflow)?;
        if count == 0 || count > MAX_COMMITTEE_MEMBERS {
            return Err(DecodeError::LimitExceeded);
        }
        if decoder.remaining() != count * 96 {
            return Err(DecodeError::NonCanonical);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(CertificateSignature {
                voter: ValidatorId(decoder.read_fixed()?),
                signature: decoder.read_fixed()?,
            });
        }
        decoder.finish()?;
        let certificate = Self {
            chain_id,
            height,
            round,
            committee_root,
            block,
            signatures,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    /// Domain-separated commitment to the complete encoded certificate.
    pub fn commitment(&self) -> Result<Hash256, DecodeError> {
        Ok(types::hash::domain_hash(
            types::domain::FINALITY,
            &self.encode()?,
        ))
    }
}
