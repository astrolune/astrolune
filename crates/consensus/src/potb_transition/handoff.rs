// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Old-quorum-authenticated `PoTB` state transfer with atomic verifier publication.

use super::{
    PotbBatch, PotbConfiguration, PotbState,
    encoding::{read_field, write_field},
    potb_state_key,
};
use crate::{ConsensusError, FinalityCertificate, rotation::MAX_ROTATION_VALIDATORS};
use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use state::StateValueProof;
use types::{BlockHeader, Hash256};

const MAX_CERTIFICATE_BYTES: usize = 92 + 96 * MAX_ROTATION_VALIDATORS;
const MAX_WITNESS_BYTES: usize = PotbState::MAX_BYTES + 1024;

/// One fully bounded transfer, certified by the outgoing committee's current power.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbHandoff {
    /// Finalized block, including application state and the complete `PoTB` state value.
    pub header: BlockHeader,
    /// Outgoing quorum; newly admitted or reweighted validators cannot approve themselves.
    pub certificate: FinalityCertificate,
    /// Exact canonical system input committed by the new state.
    pub batch: PotbBatch,
    /// Membership witness for `potb_state_key` under the certified root.
    pub next_state: StateValueProof,
}

impl PotbHandoff {
    /// Maximum framed transition, independent of history length.
    pub const MAX_BYTES: usize =
        220 + MAX_CERTIFICATE_BYTES + PotbBatch::MAX_BYTES + MAX_WITNESS_BYTES;

    fn validate_shape(&self) -> Result<(), DecodeError> {
        if self.certificate.signatures.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        self.certificate.validate_shape()?;
        match &self.next_state {
            StateValueProof::Present(witness)
                if witness.key == potb_state_key()
                    && witness.value.len() <= PotbState::MAX_BYTES
                    && witness.proof.siblings.len() <= 20 =>
            {
                Ok(())
            }
            _ => Err(DecodeError::NonCanonical),
        }
    }

    /// Canonical bounded handoff envelope. Verification is a separate operation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let witness = self
            .next_state
            .to_bytes()
            .map_err(|_| DecodeError::NonCanonical)?;
        if witness.len() > MAX_WITNESS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut bytes = b"ALPTHF01".to_vec();
        self.header.encode(&mut bytes);
        write_field(&mut bytes, &self.certificate.encode()?)?;
        write_field(&mut bytes, &self.batch.to_bytes()?)?;
        write_field(&mut bytes, &witness)?;
        Ok(bytes)
    }

    /// Rejects all oversized/nested fields, trailing data and wrong witness locations.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALPTHF01" {
            return Err(DecodeError::Unsupported);
        }
        let header = BlockHeader::decode(decoder.read_exact(200)?)?;
        let certificate = read_field(&mut decoder, MAX_CERTIFICATE_BYTES)?;
        let batch = read_field(&mut decoder, PotbBatch::MAX_BYTES)?;
        let witness = read_field(&mut decoder, MAX_WITNESS_BYTES)?;
        decoder.finish()?;
        let result = Self {
            header,
            certificate: FinalityCertificate::decode(certificate)?,
            batch: PotbBatch::from_bytes(batch)?,
            next_state: StateValueProof::from_bytes(witness)
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        result.validate_shape()?;
        Ok(result)
    }
}

/// Sequential, bounded replay from a separately trusted `PoTB` configuration.
/// Authenticating system authority does not replace application re-execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbVerifier {
    current: PotbState,
    parent: Hash256,
}

impl PotbVerifier {
    /// Resumes from independently trusted checkpoint coordinates and a state witness.
    /// The caller pins the coordinates outside untrusted storage. Earlier ancestry is not verified.
    pub fn from_checkpoint(
        height: u64,
        parent: Hash256,
        root: Hash256,
        witness: &StateValueProof,
    ) -> Result<Self, ConsensusError> {
        if height == 0 || parent.is_zero() {
            return Err(ConsensusError::InvalidTransition);
        }
        let bytes = witness
            .verify(root, &potb_state_key())
            .map_err(|_| ConsensusError::InvalidProof)?
            .ok_or(ConsensusError::InvalidProof)?;
        let current = PotbState::from_bytes(bytes).map_err(|_| ConsensusError::InvalidProof)?;
        if height.checked_add(1) != Some(current.committee().height()) {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(Self { current, parent })
    }

    /// Validates bootstrap configuration and exact registered public keys.
    pub fn new(config: &PotbConfiguration, keys: &[[u8; 32]]) -> Result<Self, ConsensusError> {
        Ok(Self {
            current: PotbState::from_configuration(config, keys)?,
            parent: config.commitment(),
        })
    }

    /// Independently authenticated authority for the next block.
    #[must_use]
    pub const fn current(&self) -> &PotbState {
        &self.current
    }

    /// Previous authenticated block, or the explicit configuration anchor.
    #[must_use]
    pub const fn parent(&self) -> Hash256 {
        self.parent
    }

    /// Checks exact ancestry/capacity and the incumbent weighted quorum.
    pub fn verify_header(
        &self,
        header: &BlockHeader,
        certificate: &FinalityCertificate,
    ) -> Result<(), ConsensusError> {
        let committee = self.current.committee();
        if header.height != committee.height()
            || header.parent != self.parent
            || header.capacity != committee.capacity()
        {
            return Err(ConsensusError::InvalidTransition);
        }
        committee.context()?.verify_certificate(certificate, header)
    }

    /// Publishes committee, policy records, history and parent only after every check.
    /// All failures, including a valid quorum with a wrong state witness, leave it unchanged.
    pub fn apply(&mut self, handoff: &PotbHandoff) -> Result<(), ConsensusError> {
        handoff
            .validate_shape()
            .map_err(|_| ConsensusError::InvalidProof)?;
        self.verify_header(&handoff.header, &handoff.certificate)?;
        let next = self.current.stage(self.parent, &handoff.batch)?;
        let expected = next.to_bytes().map_err(|_| ConsensusError::InvalidProof)?;
        let actual = handoff
            .next_state
            .verify(handoff.header.state_root, &potb_state_key())
            .map_err(|_| ConsensusError::InvalidProof)?;
        if actual != Some(expected.as_slice()) {
            return Err(ConsensusError::InvalidTransition);
        }
        self.current = next;
        self.parent = handoff.header.compute_hash();
        Ok(())
    }
}
