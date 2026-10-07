// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded historical handoff reads from atomically published block effects.

use consensus::FinalityCertificate;
use consensus::rotation::{CommitteeHandoff, VrfBatch};
use storage::{ChainStorage, StorageError};

/// Reads one atomically published `PoTB` handoff. Authority must be verified by the client.
pub fn read_potb_handoff(
    storage: &ChainStorage,
    height: u64,
) -> Result<Option<consensus::potb_transition::PotbHandoff>, StorageError> {
    use consensus::potb_transition::{PotbBatch, PotbHandoff};
    let Some(stored) = storage.read_receipts(height)? else {
        return Ok(None);
    };
    let Some(next_state) = stored.effects.potb.clone() else {
        return Ok(None);
    };
    let (block, encoded) = storage
        .read_finalized(height)?
        .ok_or(StorageError::VerificationFailed)?;
    if block.header.height != height
        || stored.header != block.header
        || encoded != stored.certificate
        || crate::compute_transactions_root(&block.transactions) != block.header.transactions_root
    {
        return Err(StorageError::VerificationFailed);
    }
    stored.effects.validate(&block)?;
    let first = block
        .transactions
        .first()
        .filter(|tx| tx.lane == types::TransactionLane::System)
        .ok_or(StorageError::VerificationFailed)?;
    let handoff = PotbHandoff {
        header: block.header,
        certificate: FinalityCertificate::decode(&encoded)
            .map_err(|_| StorageError::VerificationFailed)?,
        batch: PotbBatch::from_bytes(&first.payload)
            .map_err(|_| StorageError::VerificationFailed)?,
        next_state,
    };
    handoff
        .to_bytes()
        .map_err(|_| StorageError::VerificationFailed)?;
    Ok(Some(handoff))
}

/// Reads one retained transition without replaying history or trusting stored authority.
/// Absence means unavailable (including legacy records without a witness). A client
/// must authenticate the returned handoff from its own genesis with `HandoffVerifier`.
pub fn read_handoff(
    storage: &ChainStorage,
    height: u64,
) -> Result<Option<CommitteeHandoff>, StorageError> {
    let Some(stored) = storage.read_receipts(height)? else {
        return Ok(None);
    };
    let Some(next_state) = stored.effects.committee.clone() else {
        return Ok(None);
    };
    let (block, encoded) = storage
        .read_finalized(height)?
        .ok_or(StorageError::VerificationFailed)?;
    if block.header.height != height
        || stored.header != block.header
        || encoded != stored.certificate
        || crate::compute_transactions_root(&block.transactions) != block.header.transactions_root
    {
        return Err(StorageError::VerificationFailed);
    }
    stored.effects.validate(&block)?;
    let first = block
        .transactions
        .first()
        .filter(|tx| tx.lane == types::TransactionLane::System)
        .ok_or(StorageError::VerificationFailed)?;
    let handoff = CommitteeHandoff {
        header: block.header,
        certificate: FinalityCertificate::decode(&encoded)
            .map_err(|_| StorageError::VerificationFailed)?,
        contributions: VrfBatch::from_bytes(&first.payload)
            .map_err(|_| StorageError::VerificationFailed)?,
        next_state,
    };
    handoff
        .to_bytes()
        .map_err(|_| StorageError::VerificationFailed)?;
    Ok(Some(handoff))
}
