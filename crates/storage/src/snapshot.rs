// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Snapshot transport framing; trust comes from the caller's finalized checkpoint.

use codec::Decoder;
use state::{InMemoryState, MAX_SNAPSHOT_BYTES};
use types::Hash256;

use crate::{
    Checkpoint, SNAPSHOT_CHUNK_BYTES, SnapshotSink, SnapshotSource, StorageError, map_state_error,
};

const MAGIC: &[u8; 8] = b"ASTCHAIN";
const VERSION: u16 = 1;

pub(super) fn export(
    checkpoint: Checkpoint,
    state: &InMemoryState,
    sink: &mut dyn SnapshotSink,
) -> Result<(), StorageError> {
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&checkpoint.height.to_le_bytes());
    header.extend_from_slice(checkpoint.block.as_bytes());
    header.extend_from_slice(checkpoint.state_root.as_bytes());
    sink.write_chunk(0, &header)?;
    for (index, chunk) in state
        .export_snapshot()
        .chunks(SNAPSHOT_CHUNK_BYTES)
        .enumerate()
    {
        let index = u32::try_from(index + 1).map_err(|_| StorageError::LimitExceeded)?;
        sink.write_chunk(index, chunk)?;
    }
    Ok(())
}

pub(super) fn import(
    expected: Checkpoint,
    source: &mut dyn SnapshotSource,
) -> Result<InMemoryState, StorageError> {
    let header = source.next_chunk()?.ok_or(StorageError::Corrupt)?;
    let checkpoint = decode_header(&header)?;
    if checkpoint != expected || expected.block.is_zero() {
        return Err(StorageError::VerificationFailed);
    }
    let mut bytes = Vec::new();
    let mut short_chunk = false;
    while let Some(chunk) = source.next_chunk()? {
        if chunk.is_empty() || short_chunk {
            return Err(StorageError::Corrupt);
        }
        if chunk.len() > SNAPSHOT_CHUNK_BYTES || chunk.len() > MAX_SNAPSHOT_BYTES - bytes.len() {
            return Err(StorageError::LimitExceeded);
        }
        short_chunk = chunk.len() < SNAPSHOT_CHUNK_BYTES;
        bytes.extend_from_slice(&chunk);
    }
    InMemoryState::from_snapshot(&bytes, expected.state_root).map_err(map_state_error)
}

fn decode_header(bytes: &[u8]) -> Result<Checkpoint, StorageError> {
    let decode = || -> Result<Checkpoint, codec::DecodeError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != MAGIC || decoder.read_u16()? != VERSION {
            return Err(codec::DecodeError::NonCanonical);
        }
        let checkpoint = Checkpoint {
            height: decoder.read_u64()?,
            block: Hash256(decoder.read_fixed()?),
            state_root: Hash256(decoder.read_fixed()?),
        };
        decoder.finish()?;
        Ok(checkpoint)
    };
    decode().map_err(|_| StorageError::Corrupt)
}
