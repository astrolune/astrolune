// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded reference-network envelopes. Decoding never grants consensus authority.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use consensus::{FinalityCertificate, Proposal, Vote};
use types::{Block, BlockHeader, Hash256, Transaction};

/// Maximum complete response, checked before transport allocation.
pub const MAX_EXCHANGE_BYTES: usize = 8 * 1024 * 1024;
/// Fixed reference-network block-body bound.
pub const MAX_BLOCK_BYTES: usize = 1024 * 1024;
/// Reference network transaction bound, including its signed envelope.
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
/// Maximum messages retained in a decoded exchange.
pub const MAX_MESSAGES: usize = 512;

/// Authenticated payloads or untrusted transactions; certificates are verified by the node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkMessage {
    /// Signed designation with an available body and optional earlier-round prevotes.
    Proposal {
        /// Signed proposal metadata.
        envelope: Proposal,
        /// Re-executed body.
        block: Block,
        /// Empty for a fresh proposal; otherwise a canonical prevote proof.
        proof: Vec<u8>,
    },
    /// Signed prevote or precommit.
    Vote(Vote),
    /// Independently verifiable finalized block, including during catch-up.
    Finalized {
        /// Available body.
        block: Block,
        /// Precommit quorum.
        certificate: FinalityCertificate,
    },
    /// Available value with prevote evidence, retained across round changes.
    ValidValue {
        /// Available body.
        block: Block,
        /// Canonical prevote certificate bytes.
        proof: Vec<u8>,
    },
    /// Full-roster role-separated VRF contribution for the current finalized context.
    VrfContribution {
        /// Height whose system transaction will commit the next committee.
        height: u64,
        /// Both deterministic proofs under the registered identity.
        contribution: consensus::rotation::VrfContribution,
    },
    /// Signed native transaction; admission remains state-aware.
    Transaction(Transaction),
    /// Candidate consent and a strict incumbent quorum, scoped to the exact current parent.
    PotbAdmission(consensus::admission::AdmissionCertificate),
    /// Double-vote evidence authenticated against the current finalized history frontier.
    PotbEvidence(consensus::history::HistoricalEvidence),
    /// Current-incumbent quorum authorizing parameters for the next epoch.
    Governance(consensus::governance::GovernanceCertificate),
}

/// Request for one finalized height or the live consensus messages at that height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncRequest {
    /// Trusted genesis commitment; identifies the explicit reference-network profile.
    pub genesis: Hash256,
    /// First missing block height.
    pub height: u64,
}

impl SyncRequest {
    /// Fixed 48-byte request, independent of advertised peer state.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = b"ALRQ\x01\0\0\0".to_vec();
        bytes.extend_from_slice(&self.genesis.0);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes
    }

    /// Rejects versions, truncation, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Decoder::new(bytes);
        if reader.read_fixed::<8>()? != *b"ALRQ\x01\0\0\0" {
            return Err(DecodeError::Unsupported);
        }
        let result = Self {
            genesis: Hash256(reader.read_fixed()?),
            height: reader.read_u64()?,
        };
        reader.finish()?;
        Ok(result)
    }
}

fn put_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), DecodeError> {
    let len = u32::try_from(value.len()).map_err(|_| DecodeError::LimitExceeded)?;
    if bytes.len().saturating_add(value.len()).saturating_add(4) > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn blob<'a>(reader: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], DecodeError> {
    let len = usize::try_from(reader.read_u32()?).map_err(|_| DecodeError::LimitExceeded)?;
    if len > max {
        return Err(DecodeError::LimitExceeded);
    }
    reader.read_exact(len)
}

/// Encodes a bounded block without trusting externally supplied execution outputs.
pub fn encode_block(block: &Block) -> Result<Vec<u8>, DecodeError> {
    if block.transactions.len() > 256 {
        return Err(DecodeError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    put_blob(&mut bytes, &block.header.to_bytes())?;
    bytes.extend_from_slice(
        &u32::try_from(block.transactions.len())
            .map_err(|_| DecodeError::LimitExceeded)?
            .to_le_bytes(),
    );
    for tx in &block.transactions {
        let encoded = tx.to_bytes();
        if encoded.len() > MAX_TRANSACTION_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        put_blob(&mut bytes, &encoded)?;
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
    }
    Ok(bytes)
}

fn decode_block(bytes: &[u8]) -> Result<Block, DecodeError> {
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut reader = Decoder::new(bytes);
    let header = BlockHeader::decode(blob(&mut reader, 256)?)?;
    let count = usize::try_from(reader.read_u32()?).map_err(|_| DecodeError::LimitExceeded)?;
    if count > 256 || count > reader.remaining() / 4 {
        return Err(DecodeError::LimitExceeded);
    }
    let mut transactions = Vec::new();
    for _ in 0..count {
        transactions.push(Transaction::decode(blob(
            &mut reader,
            MAX_TRANSACTION_BYTES,
        )?)?);
    }
    reader.finish()?;
    Ok(Block {
        header,
        transactions,
    })
}

/// Encodes bounded messages. Genesis binding applies even to empty exchanges.
pub fn encode_exchange(
    genesis: Hash256,
    messages: &[NetworkMessage],
) -> Result<Vec<u8>, DecodeError> {
    if messages.len() > MAX_MESSAGES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut bytes = b"ALNX\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&genesis.0);
    bytes.extend_from_slice(
        &u32::try_from(messages.len())
            .map_err(|_| DecodeError::LimitExceeded)?
            .to_le_bytes(),
    );
    for message in messages {
        match message {
            NetworkMessage::Governance(certificate) => {
                bytes.push(8);
                put_blob(&mut bytes, &certificate.to_bytes()?)?;
            }
            NetworkMessage::PotbAdmission(certificate) => {
                bytes.push(6);
                put_blob(&mut bytes, &certificate.to_bytes()?)?;
            }
            NetworkMessage::PotbEvidence(evidence) => {
                bytes.push(7);
                put_blob(&mut bytes, &evidence.to_bytes()?)?;
            }
            NetworkMessage::Proposal {
                envelope,
                block,
                proof,
            } => {
                bytes.push(0);
                put_blob(&mut bytes, &envelope.encode())?;
                put_blob(&mut bytes, &encode_block(block)?)?;
                put_blob(&mut bytes, proof)?;
            }
            NetworkMessage::Vote(vote) => {
                bytes.push(1);
                put_blob(&mut bytes, &vote.encode())?;
            }
            NetworkMessage::Finalized { block, certificate } => {
                bytes.push(2);
                put_blob(&mut bytes, &encode_block(block)?)?;
                put_blob(&mut bytes, &certificate.encode()?)?;
            }
            NetworkMessage::ValidValue { block, proof } => {
                bytes.push(3);
                put_blob(&mut bytes, &encode_block(block)?)?;
                put_blob(&mut bytes, proof)?;
            }
            NetworkMessage::VrfContribution {
                height,
                contribution,
            } => {
                bytes.push(5);
                bytes.extend_from_slice(&height.to_le_bytes());
                put_blob(&mut bytes, &contribution.to_bytes()?)?;
            }
            NetworkMessage::Transaction(tx) => {
                bytes.push(4);
                let encoded = tx.to_bytes();
                if encoded.len() > MAX_TRANSACTION_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                put_blob(&mut bytes, &encoded)?;
            }
        }
    }
    Ok(bytes)
}

/// Performs complete bounded structural decoding before the caller processes any message.
pub fn decode_exchange(genesis: Hash256, bytes: &[u8]) -> Result<Vec<NetworkMessage>, DecodeError> {
    if bytes.len() > MAX_EXCHANGE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut reader = Decoder::new(bytes);
    if reader.read_fixed::<8>()? != *b"ALNX\x01\0\0\0" || reader.read_fixed::<32>()? != genesis.0 {
        return Err(DecodeError::Unsupported);
    }
    let count = usize::try_from(reader.read_u32()?).map_err(|_| DecodeError::LimitExceeded)?;
    if count > MAX_MESSAGES || count > reader.remaining() / 5 {
        return Err(DecodeError::LimitExceeded);
    }
    let mut messages = Vec::new();
    for _ in 0..count {
        messages.push(match reader.read_u8()? {
            8 => NetworkMessage::Governance(
                consensus::governance::GovernanceCertificate::from_bytes(blob(
                    &mut reader,
                    consensus::governance::GovernanceCertificate::MAX_BYTES,
                )?)?,
            ),
            6 => NetworkMessage::PotbAdmission(
                consensus::admission::AdmissionCertificate::from_bytes(blob(
                    &mut reader,
                    consensus::admission::AdmissionCertificate::MAX_BYTES,
                )?)?,
            ),
            7 => NetworkMessage::PotbEvidence(consensus::history::HistoricalEvidence::from_bytes(
                blob(
                    &mut reader,
                    consensus::history::HistoricalEvidence::MAX_BYTES,
                )?,
            )?),
            0 => NetworkMessage::Proposal {
                envelope: Proposal::decode(blob(&mut reader, 221)?)?,
                block: decode_block(blob(&mut reader, MAX_BLOCK_BYTES)?)?,
                proof: blob(&mut reader, MAX_BLOCK_BYTES)?.to_vec(),
            },
            1 => NetworkMessage::Vote(Vote::decode(blob(&mut reader, 186)?)?),
            2 => NetworkMessage::Finalized {
                block: decode_block(blob(&mut reader, MAX_BLOCK_BYTES)?)?,
                certificate: FinalityCertificate::decode(blob(&mut reader, MAX_BLOCK_BYTES)?)?,
            },
            3 => NetworkMessage::ValidValue {
                block: decode_block(blob(&mut reader, MAX_BLOCK_BYTES)?)?,
                proof: blob(&mut reader, MAX_BLOCK_BYTES)?.to_vec(),
            },
            4 => NetworkMessage::Transaction(Transaction::decode(blob(
                &mut reader,
                MAX_TRANSACTION_BYTES,
            )?)?),
            5 => NetworkMessage::VrfContribution {
                height: reader.read_u64()?,
                contribution: consensus::rotation::VrfContribution::from_bytes(blob(
                    &mut reader,
                    consensus::rotation::VrfContribution::BYTES,
                )?)?,
            },
            _ => return Err(DecodeError::Unsupported),
        });
    }
    reader.finish()?;
    Ok(messages)
}
