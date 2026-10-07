// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI proofs.

use ed25519_dalek::VerifyingKey;
use types::{Hash256, domain, hash::domain_hash};
use vrf_rfc9381::{
    Proof, Prover, Verifier,
    ec::edwards25519::{
        EdVrfProof,
        tai::{EdVrfEdwards25519TaiPublicKey, EdVrfEdwards25519TaiSecretKey},
    },
};

use crate::{CryptoError, VrfOutput};

/// Fixed RFC 9381 proof length for the selected suite.
pub const VRF_PROOF_BYTES: usize = 80;
/// Versioned output envelope length, including the proof.
pub const VRF_ENVELOPE_BYTES: usize = 120;
/// Domain for reducing the verified 64-byte RFC output to a protocol hash.
pub const VRF_OUTPUT_DOMAIN: &[u8] = b"astrolune.vrf.output.v1";

/// Separate uses of verifiable randomness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VrfRole {
    /// Committee sampling at a finalized transition.
    Committee,
    /// Producer sampling within the active committee.
    Producer,
}

/// Public, finalized context bound to every protocol VRF evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VrfInput {
    /// Chain identifier.
    pub chain_id: u32,
    /// Trusted genesis commitment, separating networks with the same chain ID.
    pub genesis: Hash256,
    /// Finalized epoch number.
    pub epoch: u64,
    /// Target consensus height.
    pub height: u64,
    /// Finalized parent randomness commitment.
    pub parent_randomness: Hash256,
    /// Consensus round (zero for committee selection).
    pub round: u32,
    /// Purpose of the evaluation.
    pub role: VrfRole,
}

impl VrfInput {
    /// Hashes fixed-width little-endian context fields under the role domain.
    #[must_use]
    pub fn seed(self) -> Hash256 {
        let mut bytes = [0; 88];
        bytes[..4].copy_from_slice(&self.chain_id.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.genesis.0);
        bytes[36..44].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[44..52].copy_from_slice(&self.height.to_le_bytes());
        bytes[52..84].copy_from_slice(&self.parent_randomness.0);
        bytes[84..].copy_from_slice(&self.round.to_le_bytes());
        let tag = match self.role {
            VrfRole::Committee => domain::VRF_COMMITTEE,
            VrfRole::Producer => domain::VRF_PRODUCER,
        };
        domain_hash(tag, &bytes)
    }
}

/// Evaluates the VRF using a 32-byte Ed25519 secret seed.
///
/// The input must come from trusted finalized context. Secret material is
/// cleared by the backend on drop; proofs are deterministic and publicly verifiable.
pub fn prove_vrf(secret: &[u8; 32], input: VrfInput) -> Result<VrfOutput, CryptoError> {
    let key =
        EdVrfEdwards25519TaiSecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidSeed)?;
    let proof = key
        .prove(&input.seed().0)
        .map_err(|_| CryptoError::InvalidVrfProof)?;
    let bytes = proof.encode_to_pi();
    let beta = key
        .verifier()
        .verify(&input.seed().0, proof)
        .map_err(|_| CryptoError::InvalidVrfProof)?;
    Ok(VrfOutput {
        randomness: domain_hash(VRF_OUTPUT_DOMAIN, &beta),
        proof: bytes,
    })
}

/// Verifies canonical key/proof encodings and the claimed output digest.
pub fn verify_vrf(
    public_key: &[u8; 32],
    seed: Hash256,
    output: &VrfOutput,
) -> Result<(), CryptoError> {
    let beta = verify_ecvrf(public_key, &seed.0, &output.proof)?;
    if domain_hash(VRF_OUTPUT_DOMAIN, &beta) != output.randomness {
        return Err(CryptoError::InvalidVrfProof);
    }
    Ok(())
}

/// Verifies the raw RFC suite for interoperability; protocol users pass a typed
/// [`VrfInput`] through [`prove_vrf`] and compare outputs with [`verify_vrf`].
pub fn verify_ecvrf(
    public_key: &[u8; 32],
    alpha: &[u8],
    proof: &[u8],
) -> Result<[u8; 64], CryptoError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    if key.is_weak() || key.to_edwards().compress().to_bytes() != *public_key {
        return Err(CryptoError::InvalidPublicKey);
    }
    let proof = decode_proof(proof)?;
    let key = EdVrfEdwards25519TaiPublicKey::from_slice(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    key.verify(alpha, proof)
        .map(Into::into)
        .map_err(|_| CryptoError::InvalidVrfProof)
}

fn decode_proof(bytes: &[u8]) -> Result<EdVrfProof, CryptoError> {
    if bytes.len() != VRF_PROOF_BYTES {
        return Err(CryptoError::InvalidVrfProof);
    }
    let proof = EdVrfProof::decode_pi(bytes).map_err(|_| CryptoError::InvalidVrfProof)?;
    // The backend reduces s mod q and decompresses Gamma permissively. Enforce
    // unique wire bytes, rejecting s+q and noncanonical point encodings.
    if proof.encode_to_pi() != bytes {
        return Err(CryptoError::InvalidVrfProof);
    }
    Ok(proof)
}

impl VrfOutput {
    /// Encodes a structurally canonical proof; authenticity needs verification.
    pub fn encode(&self) -> Result<[u8; VRF_ENVELOPE_BYTES], CryptoError> {
        decode_proof(&self.proof)?;
        let mut bytes = [0; VRF_ENVELOPE_BYTES];
        bytes[..4].copy_from_slice(b"ALVR");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..40].copy_from_slice(&self.randomness.0);
        bytes[40..].copy_from_slice(&self.proof);
        Ok(bytes)
    }

    /// Decodes the exact version-1 envelope without unbounded allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != VRF_ENVELOPE_BYTES
            || &bytes[..4] != b"ALVR"
            || bytes[4..8] != 1u32.to_le_bytes()
        {
            return Err(CryptoError::InvalidVrfProof);
        }
        decode_proof(&bytes[40..])?;
        let mut randomness = [0; 32];
        randomness.copy_from_slice(&bytes[8..40]);
        Ok(Self {
            randomness: Hash256(randomness),
            proof: bytes[40..].to_vec(),
        })
    }
}
