// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded state proofs anchored to genesis and fixed-committee finality.

use crate::RpcError;
use codec::{CanonicalDecode, CanonicalEncode, Decoder};
use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, FinalityCertificate, PotbWeight,
};
use genesis::Genesis;
use state::{StateSnapshot, StateValueProof};
use types::{BlockHeader, Hash256, StateKey};

/// An immutable state value with the head certificate and a genesis-binding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedStateProof {
    /// State commitment shared by both witnesses and the certified header.
    pub root: Hash256,
    /// Finalized header; absent only at the genesis anchor.
    pub header: Option<BlockHeader>,
    /// Canonical precommit certificate; empty only at genesis.
    pub certificate: Vec<u8>,
    /// Membership or absence for the caller's requested key.
    pub value: StateValueProof,
    /// Membership proving the trusted genesis commitment lives in the same state.
    pub genesis: StateValueProof,
}

impl CertifiedStateProof {
    /// Maximum complete binary response; hexadecimal JSON remains below 8 MiB.
    pub const MAX_BYTES: usize = 3 * 1024 * 1024;

    /// Builds all witnesses from one snapshot while the caller holds the publication lock.
    pub fn create(
        snapshot: &dyn StateSnapshot,
        key: &StateKey,
        finality: Option<(BlockHeader, Vec<u8>)>,
    ) -> Result<Self, RpcError> {
        let (header, certificate) = finality.map_or((None, vec![]), |(header, certificate)| {
            (Some(header), certificate)
        });
        if header
            .as_ref()
            .is_some_and(|header| header.state_root != snapshot.root())
        {
            return Err(RpcError::Unavailable);
        }
        Ok(Self {
            root: snapshot.root(),
            header,
            certificate,
            value: StateValueProof::create(snapshot, key).map_err(|_| RpcError::Unavailable)?,
            genesis: StateValueProof::create(snapshot, &genesis::genesis_key())
                .map_err(|_| RpcError::Unavailable)?,
        })
    }

    /// Authenticates a value/absence and minimum height using a trusted closed-network registry.
    ///
    /// Callers supply genesis and validator public keys independently of the RPC peer.
    /// This verifier supports the fixed genesis committee, not future rotating profiles.
    pub fn verify<'a>(
        &'a self,
        trusted: &Genesis,
        keys: &[[u8; 32]],
        key: &StateKey,
        minimum_height: u64,
    ) -> Result<Option<&'a [u8]>, RpcError> {
        let invalid = || RpcError::InvalidRequest;
        let genesis = trusted.commitment().map_err(|_| invalid())?;
        if self
            .genesis
            .verify(self.root, &genesis::genesis_key())
            .map_err(|_| invalid())?
            != Some(genesis.as_bytes().as_slice())
        {
            return Err(invalid());
        }
        if let Some(header) = &self.header {
            if trusted.version == genesis::ROTATING_GENESIS_VERSION
                || header.height == 0
                || header.height < minimum_height
                || header.state_root != self.root
                || trusted.committee_size != trusted.validators.len()
            {
                return Err(invalid());
            }
            let committee = Committee {
                height: header.height,
                members: trusted
                    .validators
                    .iter()
                    .map(|validator| CommitteeMember {
                        id: validator.id,
                        power: PotbWeight(validator.weight),
                    })
                    .collect(),
            };
            let context = AuthenticatedCommittee::new(trusted.chain_id, &committee, keys)
                .map_err(|_| invalid())?;
            let certificate =
                FinalityCertificate::decode(&self.certificate).map_err(|_| invalid())?;
            context
                .verify_certificate(&certificate, header)
                .map_err(|_| invalid())?;
        } else if minimum_height != 0
            || !self.certificate.is_empty()
            || trusted.materialize().map_err(|_| invalid())?.root() != self.root
        {
            return Err(invalid());
        }
        self.value.verify(self.root, key).map_err(|_| invalid())
    }

    /// Authenticates a rotated committee using a separately verified handoff stream.
    /// The verifier must be positioned at this exact header's height; the proof
    /// cannot provide its own trust state or skip a missing transition. Genesis
    /// proofs continue to use [`Self::verify`]. The caller verifies a proof before
    /// applying the handoff contained in that same block.
    pub fn verify_with_handoffs<'a>(
        &'a self,
        trusted: &consensus::rotation::HandoffVerifier,
        key: &StateKey,
        minimum_height: u64,
    ) -> Result<Option<&'a [u8]>, RpcError> {
        let invalid = || RpcError::InvalidRequest;
        let header = self.header.as_ref().ok_or_else(invalid)?;
        if self.certificate.len() > 92 + 96 * consensus::rotation::MAX_ROTATION_VALIDATORS
            || header.height < minimum_height
            || header.state_root != self.root
            || self
                .genesis
                .verify(self.root, &genesis::genesis_key())
                .map_err(|_| invalid())?
                != Some(trusted.current().genesis().as_bytes().as_slice())
        {
            return Err(invalid());
        }
        let certificate = FinalityCertificate::decode(&self.certificate).map_err(|_| invalid())?;
        trusted
            .verify_header(header, &certificate)
            .map_err(|_| invalid())?;
        self.value.verify(self.root, key).map_err(|_| invalid())
    }

    /// Verifies the exact finalized header using independently advanced `PoTB` authority.
    pub fn verify_with_potb<'a>(
        &'a self,
        trusted: &consensus::potb_transition::PotbVerifier,
        key: &StateKey,
        minimum_height: u64,
    ) -> Result<Option<&'a [u8]>, RpcError> {
        let header = self.header.as_ref().ok_or(RpcError::InvalidRequest)?;
        if self.certificate.len() > 92 + 96 * consensus::rotation::MAX_ROTATION_VALIDATORS
            || header.height < minimum_height
            || header.state_root != self.root
            || self
                .genesis
                .verify(self.root, &genesis::genesis_key())
                .map_err(|_| RpcError::InvalidRequest)?
                != Some(
                    trusted
                        .current()
                        .committee()
                        .genesis()
                        .as_bytes()
                        .as_slice(),
                )
        {
            return Err(RpcError::InvalidRequest);
        }
        let certificate =
            FinalityCertificate::decode(&self.certificate).map_err(|_| RpcError::InvalidRequest)?;
        trusted
            .verify_header(header, &certificate)
            .map_err(|_| RpcError::InvalidRequest)?;
        self.value
            .verify(self.root, key)
            .map_err(|_| RpcError::InvalidRequest)
    }

    /// Authenticates a genesis-only `PoTB` proof using independent configuration and public keys.
    pub fn verify_potb_genesis<'a>(
        &'a self,
        configuration: &consensus::potb_transition::PotbConfiguration,
        keys: &[[u8; 32]],
        key: &StateKey,
    ) -> Result<Option<&'a [u8]>, RpcError> {
        let initial = configuration
            .materialize(keys)
            .map_err(|_| RpcError::InvalidRequest)?;
        if self.header.is_some()
            || !self.certificate.is_empty()
            || self.root != initial.root()
            || self
                .genesis
                .verify(self.root, &genesis::genesis_key())
                .map_err(|_| RpcError::InvalidRequest)?
                != Some(configuration.commitment().as_bytes().as_slice())
        {
            return Err(RpcError::InvalidRequest);
        }
        self.value
            .verify(self.root, key)
            .map_err(|_| RpcError::InvalidRequest)
    }

    /// Encodes explicit versioned framing and bounded subproofs.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RpcError> {
        if self.certificate.len() > 256 * 1024 {
            return Err(RpcError::LimitExceeded);
        }
        let value = self.value.to_bytes().map_err(|_| RpcError::LimitExceeded)?;
        let genesis = self
            .genesis
            .to_bytes()
            .map_err(|_| RpcError::LimitExceeded)?;
        if 256 + self.certificate.len() + value.len() + genesis.len() > Self::MAX_BYTES {
            return Err(RpcError::LimitExceeded);
        }
        let mut bytes = b"ALSTATE1".to_vec();
        bytes.extend_from_slice(self.root.as_bytes());
        bytes.push(u8::from(self.header.is_some()));
        if let Some(header) = &self.header {
            header.encode(&mut bytes);
        }
        for field in [&self.certificate, &value, &genesis] {
            bytes.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| RpcError::LimitExceeded)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    /// Decodes without accepting alternate flags, trailing bytes or oversized fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(RpcError::LimitExceeded);
        }
        Self::decode_inner(bytes).map_err(|_| RpcError::InvalidRequest)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, codec::DecodeError> {
        use codec::DecodeError;
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALSTATE1" {
            return Err(DecodeError::Unsupported);
        }
        let root = Hash256(decoder.read_fixed()?);
        let header = match decoder.read_u8()? {
            0 => None,
            1 => Some(BlockHeader::decode(decoder.read_exact(200)?)?),
            _ => return Err(DecodeError::NonCanonical),
        };
        let certificate = read_field(&mut decoder, 256 * 1024)?;
        let value = read_field(&mut decoder, StateValueProof::MAX_BYTES)?;
        let genesis = read_field(&mut decoder, StateValueProof::MAX_BYTES)?;
        decoder.finish()?;
        Ok(Self {
            root,
            header,
            certificate: certificate.to_vec(),
            value: StateValueProof::from_bytes(value).map_err(|_| DecodeError::NonCanonical)?,
            genesis: StateValueProof::from_bytes(genesis).map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

fn read_field<'a>(decoder: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], codec::DecodeError> {
    let length = decoder.read_u32()? as usize;
    if length > max {
        return Err(codec::DecodeError::LimitExceeded);
    }
    decoder.read_exact(length)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
