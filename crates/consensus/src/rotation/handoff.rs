// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Streaming trust transfer from an old quorum to a fully verified next committee.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use genesis::Genesis;
use state::StateValueProof;
use types::{BlockHeader, Hash256};

use super::{CommitteeState, MAX_ROTATION_VALIDATORS, VrfBatch, committee_state_key};
use crate::{ConsensusError, FinalityCertificate};

const MAX_CERTIFICATE_BYTES: usize = 92 + 96 * MAX_ROTATION_VALIDATORS;
const MAX_WITNESS_BYTES: usize = 4096;

/// One complete transition authenticated by the committee that is handing over.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeHandoff {
    /// Header finalized by the current committee, not by the incoming one.
    pub header: BlockHeader,
    /// Current committee's canonical precommit quorum.
    pub certificate: FinalityCertificate,
    /// Full roster's role-separated proofs for the next height.
    pub contributions: VrfBatch,
    /// Membership witness for the exact computed next state under this header.
    pub next_state: StateValueProof,
}

impl CommitteeHandoff {
    /// Upper bound on an individual streaming handoff; no unbounded chain envelope.
    pub const MAX_BYTES: usize =
        8 + 200 + 12 + MAX_CERTIFICATE_BYTES + VrfBatch::MAX_BYTES + MAX_WITNESS_BYTES;

    fn validate_shape(&self) -> Result<(), DecodeError> {
        if self.certificate.signatures.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        match &self.next_state {
            StateValueProof::Present(witness)
                if witness.key == committee_state_key()
                    && witness.value.len() <= CommitteeState::MAX_BYTES
                    && witness.proof.siblings.len() <= 20 => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        self.certificate.validate_shape()?;
        self.contributions.validate_shape()
    }

    /// Canonical framing of one bounded handoff, without establishing authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_shape()?;
        let certificate = self.certificate.encode()?;
        let contributions = self.contributions.to_bytes()?;
        let witness = self
            .next_state
            .to_bytes()
            .map_err(|_| DecodeError::NonCanonical)?;
        if witness.len() > MAX_WITNESS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut bytes = b"ALHAND01".to_vec();
        self.header.encode(&mut bytes);
        for field in [&certificate, &contributions, &witness] {
            bytes.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| DecodeError::LimitExceeded)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    /// Preflights all field sizes before allocating owned fields or parsing proofs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALHAND01" {
            return Err(DecodeError::Unsupported);
        }
        let header = BlockHeader::decode(decoder.read_exact(200)?)?;
        let certificate = read_field(&mut decoder, MAX_CERTIFICATE_BYTES)?;
        let contributions = read_field(&mut decoder, VrfBatch::MAX_BYTES)?;
        let witness = read_field(&mut decoder, MAX_WITNESS_BYTES)?;
        decoder.finish()?;
        let result = Self {
            header,
            certificate: FinalityCertificate::decode(certificate)?,
            contributions: VrfBatch::from_bytes(contributions)?,
            next_state: StateValueProof::from_bytes(witness)
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        result.validate_shape()?;
        Ok(result)
    }
}

/// Constant-memory, sequential verification from an independently trusted genesis.
/// A state deserialized from the network cannot be installed as a trust anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffVerifier {
    current: CommitteeState,
    parent: Hash256,
    history: crate::history::CommitteeHistory,
}

impl HandoffVerifier {
    /// Resumes from independently pinned checkpoint coordinates and history frontier.
    /// The caller pins the frontier as well as the coordinates; earlier ancestry is not verified.
    pub fn from_checkpoint(
        height: u64,
        parent: Hash256,
        root: Hash256,
        witness: &StateValueProof,
        history: crate::history::CommitteeHistory,
    ) -> Result<Self, ConsensusError> {
        if height == 0 || parent.is_zero() {
            return Err(ConsensusError::InvalidTransition);
        }
        let bytes = witness
            .verify(root, &committee_state_key())
            .map_err(|_| ConsensusError::InvalidProof)?
            .ok_or(ConsensusError::InvalidProof)?;
        let current =
            CommitteeState::from_bytes(bytes).map_err(|_| ConsensusError::InvalidProof)?;
        if height.checked_add(1) != Some(current.height())
            || history.entries() != height
            || history.genesis() != current.genesis()
            || history.chain_id() != current.chain_id()
        {
            return Err(ConsensusError::InvalidTransition);
        }
        Ok(Self {
            current,
            parent,
            history,
        })
    }

    /// Starts at genesis and validates the complete registered-key set.
    pub fn new(genesis: &Genesis, keys: &[[u8; 32]]) -> Result<Self, ConsensusError> {
        let current = CommitteeState::from_genesis(genesis, keys)?;
        Ok(Self {
            parent: current.genesis(),
            history: crate::history::CommitteeHistory::new(current.chain_id(), current.genesis())?,
            current,
        })
    }

    /// Independently authenticated committee for the next unprocessed block.
    #[must_use]
    pub const fn current(&self) -> &CommitteeState {
        &self.current
    }

    /// Independently authenticated history of committees that finalized applied handoffs.
    /// This local verifier commitment does not activate policy in genesis-v1/v2 state.
    #[must_use]
    pub const fn history(&self) -> &crate::history::CommitteeHistory {
        &self.history
    }

    /// Hash of the last verified finalized header, or trusted genesis at height zero.
    #[must_use]
    pub const fn parent(&self) -> Hash256 {
        self.parent
    }

    /// Authenticates only the exact next header, including ancestry and capacity.
    /// It cannot bootstrap itself from a certificate supplied by an unknown committee.
    pub fn verify_header(
        &self,
        header: &BlockHeader,
        certificate: &FinalityCertificate,
    ) -> Result<(), ConsensusError> {
        if header.height != self.current.height
            || header.parent != self.parent
            || header.capacity != self.current.capacity
        {
            return Err(ConsensusError::InvalidTransition);
        }
        self.current
            .context()?
            .verify_certificate(certificate, header)
    }

    /// Validates the old quorum, full VRF batch and committed next-state witness.
    /// Publishes the new trust state only after every check succeeds. Replays,
    /// skipped heights, foreign forks and incomplete batches leave it unchanged.
    pub fn apply(&mut self, handoff: &CommitteeHandoff) -> Result<(), ConsensusError> {
        handoff
            .validate_shape()
            .map_err(|_| ConsensusError::InvalidProof)?;
        self.verify_header(&handoff.header, &handoff.certificate)?;
        let next = self.current.transition(&handoff.contributions)?;
        let expected = next.to_bytes().map_err(|_| ConsensusError::InvalidProof)?;
        let value = handoff
            .next_state
            .verify(handoff.header.state_root, &committee_state_key())
            .map_err(|_| ConsensusError::InvalidProof)?;
        if value != Some(expected.as_slice()) {
            return Err(ConsensusError::InvalidTransition);
        }
        let mut history = self.history.clone();
        history.append(&self.current.context()?)?;
        self.history = history;
        self.parent = handoff.header.compute_hash();
        self.current = next;
        Ok(())
    }
}

fn read_field<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8], DecodeError> {
    let size = usize::try_from(decoder.read_u32()?).map_err(|_| DecodeError::LengthOverflow)?;
    if size > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    decoder.read_exact(size)
}
