// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Ed25519 signing after a durable, monotonic journal reservation.

use crate::{
    ChainSigner, KeyHandle, KeyPurpose, KeystoreError, Signer, SigningContext, SigningPosition,
    SigningSafety, journal::Journal,
};
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use std::path::Path;
use types::{Hash256, ValidatorId};
use zeroize::Zeroizing;

/// Single-key reference signer with non-exporting, zeroizing in-memory key material.
///
/// The caller provisions the same raw Ed25519 seed and original journal on restart.
/// No private key is stored in the journal. This is not encrypted key storage, an
/// HSM, or protection against restoring an older valid journal or cloning a key.
pub struct DurableSigner {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
    validator: ValidatorId,
    handle: KeyHandle,
    context: SigningContext,
    journal: Journal,
}

impl std::fmt::Debug for DurableSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSigner")
            .field("handle", &self.handle)
            .field("context", &self.context)
            .field("last_position", &self.last_position())
            .finish_non_exhaustive()
    }
}

impl DurableSigner {
    /// Explicitly provisions a new journal; refuses to overwrite any existing file.
    ///
    /// # Errors
    /// Returns an error for an invalid namespace, existing file, lock, or failed write.
    pub fn create(
        path: impl AsRef<Path>,
        context: SigningContext,
        seed: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::initialize(path.as_ref(), context, Zeroizing::new(seed), true, false)
    }

    /// Opens and verifies an existing journal and resynchronizes it before signing.
    ///
    /// # Errors
    /// Missing, corrupt, incomplete, locked, or incompatible journals fail closed.
    pub fn open(
        path: impl AsRef<Path>,
        context: SigningContext,
        seed: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::initialize(path.as_ref(), context, Zeroizing::new(seed), false, false)
    }

    /// Creates a version-2 journal that requires atomic BFT safety metadata.
    ///
    /// # Errors
    /// Refuses existing files, invalid namespaces, and failed durable initialization.
    pub fn create_protected(
        path: impl AsRef<Path>,
        context: SigningContext,
        seed: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::initialize(path.as_ref(), context, Zeroizing::new(seed), true, true)
    }

    /// Generates a role-bound VRF proof without exporting secret material or reserving a vote.
    /// The caller supplies finalized randomness; namespace and target watermark are checked here.
    ///
    /// # Errors
    /// Rejects unprotected journals, a foreign namespace, stale targets and invalid epoch/round context.
    pub fn prove_vrf(&self, input: crypto::VrfInput) -> Result<crypto::VrfOutput, KeystoreError> {
        if !self.is_protected() {
            return Err(KeystoreError::InvalidSafety);
        }
        if input.chain_id != self.context.chain_id || input.genesis != self.context.genesis {
            return Err(KeystoreError::ContextMismatch);
        }
        if input.round != 0 || input.height < 2 || input.epoch != input.height {
            return Err(KeystoreError::InvalidSafety);
        }
        if self
            .last_position()
            .is_some_and(|position| position.height >= input.height)
        {
            return Err(KeystoreError::StalePosition);
        }
        crypto::prove_vrf(&self.seed, input).map_err(|_| KeystoreError::ProviderFailure)
    }

    /// Explicitly approves a candidate's typed, signed admission request.
    /// The caller must authenticate the incumbent committee and finalized parent.
    /// Multiple candidates may be approved; this is not a BFT vote or a decision
    /// reservation. It neither advances nor rewrites the consensus journal.
    ///
    /// # Errors
    /// Rejects unprotected signers, foreign namespaces, invalid consent, stale
    /// heights and a committee conflicting with a known same-height safety record.
    pub fn approve_admission(
        &self,
        intent: &crate::admission::AdmissionIntent,
        consent: &[u8; 64],
    ) -> Result<[u8; 64], KeystoreError> {
        if !self.is_protected() {
            return Err(KeystoreError::InvalidSafety);
        }
        if intent.chain_id != self.context.chain_id || intent.genesis != self.context.genesis {
            return Err(KeystoreError::ContextMismatch);
        }
        if !intent.verify_consent(consent) {
            return Err(KeystoreError::InvalidSafety);
        }
        if let Some(position) = self.last_position() {
            if position.height > intent.height {
                return Err(KeystoreError::StalePosition);
            }
            if position.height == intent.height
                && self
                    .safety()
                    .is_none_or(|safety| safety.committee_root != intent.committee_root)
            {
                return Err(KeystoreError::InvalidSafety);
            }
        }
        Ok(ed25519_sign(
            &self.seed,
            &intent.approval_hash(consent, self.validator).0,
        ))
    }

    /// Explicitly approves typed network parameters through the protected consensus key.
    /// The caller authenticates the current committee and activation policy. Like admission,
    /// operator approvals do not reserve BFT votes or change the consensus journal.
    ///
    /// # Errors
    /// Rejects unprotected signers, foreign namespaces, stale heights and conflicting contexts.
    pub fn approve_governance(
        &self,
        intent: &crate::governance::GovernanceIntent,
    ) -> Result<[u8; 64], KeystoreError> {
        if !self.is_protected() || intent.validate().is_err() {
            return Err(KeystoreError::InvalidSafety);
        }
        if intent.chain_id != self.context.chain_id || intent.genesis != self.context.genesis {
            return Err(KeystoreError::ContextMismatch);
        }
        if let Some(position) = self.last_position() {
            if position.height > intent.height {
                return Err(KeystoreError::StalePosition);
            }
            if position.height == intent.height
                && self
                    .safety()
                    .is_none_or(|safety| safety.committee_root != intent.committee_root)
            {
                return Err(KeystoreError::InvalidSafety);
            }
        }
        Ok(ed25519_sign(
            &self.seed,
            &intent.approval_hash(self.validator).0,
        ))
    }

    fn initialize(
        path: &Path,
        context: SigningContext,
        seed: Zeroizing<[u8; 32]>,
        create: bool,
        protected: bool,
    ) -> Result<Self, KeystoreError> {
        if context.genesis == Hash256::ZERO {
            return Err(KeystoreError::ContextMismatch);
        }
        let public_key = ed25519_public_key(&seed);
        let validator = ValidatorId(blake2s(&public_key).0);
        let journal = if create && protected {
            Journal::create_protected(path, context, public_key)?
        } else if create {
            Journal::create(path, context, public_key)?
        } else {
            Journal::open(path, context, public_key)?
        };
        let handle = KeyHandle {
            id: Hash256(validator.0).to_string(),
            purpose: KeyPurpose::Consensus,
        };
        Ok(Self {
            seed,
            public_key,
            validator,
            handle,
            context,
            journal,
        })
    }

    /// Opaque consensus-only handle derived from the public identity, not a label.
    #[must_use]
    pub fn key_handle(&self) -> KeyHandle {
        self.handle.clone()
    }

    /// Public Ed25519 key for trusted committee registration.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Highest fully synchronized decision known by this instance.
    #[must_use]
    pub const fn last_position(&self) -> Option<SigningPosition> {
        self.journal.last_position()
    }

    /// Whether this journal requires safety metadata for every signature.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        self.journal.is_protected()
    }

    /// Safety state atomically stored alongside the last reserved digest.
    #[must_use]
    pub const fn safety(&self) -> Option<SigningSafety> {
        self.journal.safety()
    }

    /// Reserves a digest and its BFT lock together before signing.
    ///
    /// The caller must verify the quorum proof authorizing any lock advance.
    /// # Errors
    /// Rejects raw journals, missing/invalid safety state, stale or conflicting slots,
    /// and failed writes. Lock rounds cannot regress or clear within a height.
    pub fn sign_protected(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
        safety: SigningSafety,
    ) -> Result<[u8; 64], KeystoreError> {
        self.validator_id(handle)?;
        self.journal.reserve_protected(position, message, safety)?;
        Ok(ed25519_sign(&self.seed, &message.0))
    }
}

impl Signer for DurableSigner {
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError> {
        if handle.purpose != KeyPurpose::Consensus {
            return Err(KeystoreError::WrongPurpose);
        }
        if handle.id != self.handle.id {
            return Err(KeystoreError::UnknownKey);
        }
        Ok(self.validator)
    }

    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError> {
        self.validator_id(handle)?;
        self.journal.reserve(position, message)?;
        Ok(ed25519_sign(&self.seed, &message.0))
    }
}

impl ChainSigner for DurableSigner {
    fn signing_context(&self) -> SigningContext {
        self.context
    }
}
