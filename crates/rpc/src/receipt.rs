// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Receipt queries bind execution results, genesis and fixed-committee finality.

use crate::{CertifiedStateProof, RpcError};
use codec::{CanonicalDecode, Decoder};
use storage::{BlockEffects, StoredReceipts};
use types::{BlockHeader, ExecutionReceipt, Hash256};

/// Bounded receipt set authenticated by a finalized block and its genesis witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedReceiptProof(pub StoredReceipts);
impl CertifiedReceiptProof {
    /// Maximum encoded proof, including all bounded receipts and the certificate.
    pub const MAX_BYTES: usize = 2 * 1024 * 1024;

    /// Authenticates finality and returns only the receipt for the exact requested transaction.
    pub fn verify(
        &self,
        genesis: &genesis::Genesis,
        keys: &[[u8; 32]],
        id: Hash256,
        minimum_height: u64,
    ) -> Result<&ExecutionReceipt, RpcError> {
        self.certified_state()?
            .verify(genesis, keys, &genesis::genesis_key(), minimum_height)?;
        self.matching_receipt(id)
    }

    /// Authenticates a receipt at the exact height of an independently verified
    /// handoff stream. The untrusted proof cannot choose its own committee.
    pub fn verify_with_handoffs(
        &self,
        trusted: &consensus::rotation::HandoffVerifier,
        id: Hash256,
        minimum_height: u64,
    ) -> Result<&ExecutionReceipt, RpcError> {
        self.certified_state()?.verify_with_handoffs(
            trusted,
            &genesis::genesis_key(),
            minimum_height,
        )?;
        self.matching_receipt(id)
    }

    fn certified_state(&self) -> Result<CertifiedStateProof, RpcError> {
        if self.0.certificate.len() > 256 * 1024 {
            return Err(RpcError::LimitExceeded);
        }
        self.0
            .effects
            .validate_header(&self.0.header)
            .map_err(|_| RpcError::InvalidRequest)?;
        // Enforce bounds before cloning the small genesis witness for the shared verifier.
        self.0
            .effects
            .to_bytes()
            .map_err(|_| RpcError::LimitExceeded)?;
        Ok(CertifiedStateProof {
            root: self.0.header.state_root,
            header: Some(self.0.header),
            certificate: self.0.certificate.clone(),
            genesis: self.0.effects.genesis.clone(),
            value: self.0.effects.genesis.clone(),
        })
    }

    /// Authenticates this exact header with independently advanced `PoTB` authority.
    pub fn verify_with_potb(
        &self,
        trusted: &consensus::potb_transition::PotbVerifier,
        id: Hash256,
        minimum_height: u64,
    ) -> Result<&ExecutionReceipt, RpcError> {
        self.certified_state()?.verify_with_potb(
            trusted,
            &genesis::genesis_key(),
            minimum_height,
        )?;
        self.matching_receipt(id)
    }

    fn matching_receipt(&self, id: Hash256) -> Result<&ExecutionReceipt, RpcError> {
        let mut matching = self
            .0
            .effects
            .receipts
            .iter()
            .filter(|receipt| receipt.transaction == id);
        let receipt = matching.next().ok_or(RpcError::InvalidRequest)?;
        if matching.next().is_some() {
            return Err(RpcError::InvalidRequest);
        }
        Ok(receipt)
    }
    /// Serializes exact versioned lengths; this does not authenticate signatures.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RpcError> {
        if self.0.certificate.len() > 256 * 1024 {
            return Err(RpcError::LimitExceeded);
        }
        let effects = self
            .0
            .effects
            .to_bytes()
            .map_err(|_| RpcError::LimitExceeded)?;
        let mut bytes = b"ALRCPT01".to_vec();
        bytes.extend_from_slice(&self.0.header.canonical_bytes());
        for field in [&self.0.certificate, &effects] {
            bytes.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| RpcError::LimitExceeded)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(field);
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(RpcError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Decodes framing and canonical receipts without trusting their finality.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RpcError> {
        fn decode(bytes: &[u8]) -> Result<CertifiedReceiptProof, codec::DecodeError> {
            let mut decoder = Decoder::new(bytes);
            if decoder.read_exact(8)? != b"ALRCPT01" {
                return Err(codec::DecodeError::Unsupported);
            }
            let header = BlockHeader::decode(decoder.read_exact(200)?)?;
            let length = decoder.read_u32()? as usize;
            if length > 256 * 1024 {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let certificate = decoder.read_exact(length)?.to_vec();
            let length = decoder.read_u32()? as usize;
            if length > storage::MAX_RECEIPTS_BYTES {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let effects = BlockEffects::from_bytes(decoder.read_exact(length)?)
                .map_err(|_| codec::DecodeError::NonCanonical)?;
            decoder.finish()?;
            Ok(CertifiedReceiptProof(StoredReceipts {
                header,
                certificate,
                effects,
            }))
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(RpcError::LimitExceeded);
        }
        decode(bytes).map_err(|_| RpcError::InvalidRequest)
    }
}
