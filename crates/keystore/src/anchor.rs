// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independent-anchor rollback check for a consensus signing journal.
//!
//! The signing journal's monotonic watermark is derived entirely from the bytes of
//! one file, so an older complete prefix hashes correctly and is accepted as the
//! current watermark. This module adds a second, separately provisioned store that
//! records the journal's observable watermark and must agree with it before any
//! signature is released. Restoring an older journal next to a current anchor fails
//! loudly instead of silently continuing.
//!
//! The anchor is an **independent-anchor rollback check**, not hardware-enforced
//! rollback prevention. It raises the bar from rewriting one file to consistently
//! rewriting two independent stores: the anchor is expected to live on storage that
//! the journal's storage cannot restore in the same operation. It is not an HSM, a
//! TPM, a TEE, or a remote attestation service. An administrator with write access
//! to both stores, a backup restore covering both paths, or a virtual-machine
//! snapshot revert that includes both still defeats it, and neither store prevents
//! copying the seed into an unrelated journal and anchor pair.
//!
//! Both slots must validate. Falling back to an older slot after corruption could
//! authorize equivocation, exactly as for the journal's rollover extension.

use crate::journal::{JournalState, canonical_path, lock, sync_parent};
use crate::{KeystoreError, PRECOMMIT_PHASE, SigningContext, SigningPosition};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use types::{Hash256, hash::domain_hash};

const MAGIC: &[u8; 8] = b"ALSANCH1";
const HEADER_BYTES: usize = 140;
const SLOT_BYTES: usize = 118;
const HEADER_DOMAIN: &[u8] = b"astrolune.signing.anchor.v1";
const BINDING_DOMAIN: &[u8] = b"astrolune.signing.anchor.binding.v1";
const SLOT_DOMAIN: &[u8] = b"astrolune.signing.anchor.slot.v1";

/// Exact signing-anchor file length; the file never grows or shrinks.
pub const ANCHOR_BYTES: usize = HEADER_BYTES + 2 * SLOT_BYTES;

/// Separately provisioned witness for one journal's monotonic watermark.
pub(crate) struct AnchorStore {
    file: File,
    identity: Hash256,
    checksum: Hash256,
    slots: [JournalState; 2],
    poisoned: bool,
}

impl Drop for AnchorStore {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn header(context: SigningContext, public_key: [u8; 32], identity: Hash256) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..12].copy_from_slice(&context.chain_id.to_le_bytes());
    bytes[12..44].copy_from_slice(&context.genesis.0);
    bytes[44..76].copy_from_slice(&public_key);
    bytes[76..108].copy_from_slice(&identity.0);
    let checksum = domain_hash(HEADER_DOMAIN, &bytes[..108]);
    bytes[108..].copy_from_slice(&checksum.0);
    bytes
}

fn binding(checksum: Hash256, slot: u8) -> Hash256 {
    let mut bytes = checksum.0.to_vec();
    bytes.push(slot);
    domain_hash(BINDING_DOMAIN, &bytes)
}

fn slot_record(checksum: Hash256, slot: u8, state: JournalState) -> [u8; SLOT_BYTES] {
    let mut bytes = [0; SLOT_BYTES];
    bytes[..8].copy_from_slice(&state.sequence.to_le_bytes());
    bytes[8] = u8::from(state.position.is_some());
    let position = state.position.unwrap_or(SigningPosition {
        height: 0,
        round: 0,
        phase: 0,
    });
    bytes[9..17].copy_from_slice(&position.height.to_le_bytes());
    bytes[17..21].copy_from_slice(&position.round.to_le_bytes());
    bytes[21] = position.phase;
    bytes[22..54].copy_from_slice(&state.message.0);
    bytes[54..86].copy_from_slice(&state.tip.0);
    let mut input = binding(checksum, slot).0.to_vec();
    input.extend_from_slice(&bytes[..86]);
    bytes[86..].copy_from_slice(&domain_hash(SLOT_DOMAIN, &input).0);
    bytes
}

fn decode_slot(checksum: Hash256, slot: u8, bytes: &[u8]) -> Result<JournalState, KeystoreError> {
    let parsed = (|| -> Result<_, codec::DecodeError> {
        let mut decoder = codec::Decoder::new(bytes);
        let sequence = decoder.read_u64()?;
        let present = decoder.read_u8()?;
        let position = SigningPosition {
            height: decoder.read_u64()?,
            round: decoder.read_u32()?,
            phase: decoder.read_u8()?,
        };
        let message = Hash256(decoder.read_fixed()?);
        let tip = Hash256(decoder.read_fixed()?);
        let stored = Hash256(decoder.read_fixed()?);
        decoder.finish()?;
        Ok((sequence, present, position, message, tip, stored))
    })()
    .map_err(|_| KeystoreError::InvalidJournal)?;
    let (sequence, present, position, message, tip, stored) = parsed;
    let mut input = binding(checksum, slot).0.to_vec();
    input.extend_from_slice(&bytes[..86]);
    if stored != domain_hash(SLOT_DOMAIN, &input) {
        return Err(KeystoreError::InvalidJournal);
    }
    // Every field has exactly one canonical encoding: an empty journal records no
    // position, and a recorded position cannot carry an unsupported phase.
    let position = match present {
        0 if sequence == 0
            && position.height == 0
            && position.round == 0
            && position.phase == 0
            && message == Hash256::ZERO =>
        {
            None
        }
        1 if sequence > 0 && position.phase <= PRECOMMIT_PHASE => Some(position),
        _ => return Err(KeystoreError::InvalidJournal),
    };
    Ok(JournalState {
        sequence,
        position,
        message,
        tip,
    })
}

const fn destination(sequence: u64) -> u8 {
    if sequence.is_multiple_of(2) { 0 } else { 1 }
}

impl AnchorStore {
    /// Explicitly provisions a new anchor for an already verified journal.
    pub(crate) fn create(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
        identity: Hash256,
        state: JournalState,
    ) -> Result<Self, KeystoreError> {
        let path = canonical_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    KeystoreError::AlreadyExists
                } else {
                    KeystoreError::JournalFailure
                }
            })?;
        lock(&file)?;
        let bytes = header(context, public_key, identity);
        let checksum = domain_hash(HEADER_DOMAIN, &bytes[..108]);
        let mut image = Vec::with_capacity(ANCHOR_BYTES);
        image.extend_from_slice(&bytes);
        for slot in 0..2 {
            image.extend_from_slice(&slot_record(checksum, slot, state));
        }
        // Failure leaves the file in place: never silently reset an interrupted create.
        file.write_all(&image)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(Self {
            file,
            identity,
            checksum,
            slots: [state; 2],
            poisoned: false,
        })
    }

    /// Opens an existing anchor; a missing anchor is never created implicitly.
    pub(crate) fn open(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
        identity: Hash256,
    ) -> Result<Self, KeystoreError> {
        let path = canonical_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| KeystoreError::JournalFailure)?;
        lock(&file)?;
        let metadata = file.metadata().map_err(|_| KeystoreError::JournalFailure)?;
        if !metadata.is_file() || metadata.len() != ANCHOR_BYTES as u64 {
            return Err(KeystoreError::InvalidJournal);
        }
        let mut image = [0; ANCHOR_BYTES];
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut image))
            .map_err(|_| KeystoreError::InvalidJournal)?;
        let checksum = domain_hash(HEADER_DOMAIN, &image[..108]);
        if &image[..8] != MAGIC || image[108..HEADER_BYTES] != checksum.0 {
            return Err(KeystoreError::InvalidJournal);
        }
        // The anchor names exactly one journal namespace, key and chained origin.
        if image[..HEADER_BYTES] != header(context, public_key, identity) {
            return Err(KeystoreError::ContextMismatch);
        }
        let mut slots = [JournalState {
            sequence: 0,
            position: None,
            message: Hash256::ZERO,
            tip: Hash256::ZERO,
        }; 2];
        for slot in 0..2u8 {
            let offset = HEADER_BYTES + usize::from(slot) * SLOT_BYTES;
            // Both slots must validate; a damaged slot may hold the newer decision.
            slots[usize::from(slot)] =
                decode_slot(checksum, slot, &image[offset..offset + SLOT_BYTES])?;
        }
        let [a, b] = slots;
        if a != b {
            let (older, newer, physical) = if a.sequence < b.sequence {
                (a, b, 1u8)
            } else {
                (b, a, 0u8)
            };
            if older.sequence.checked_add(1) != Some(newer.sequence)
                || destination(newer.sequence) != physical
                || older.position >= newer.position
            {
                return Err(KeystoreError::InvalidJournal);
            }
        }
        let store = Self {
            file,
            identity,
            checksum,
            slots,
            poisoned: false,
        };
        // A preceding failed sync may have left a complete slot in the OS cache.
        store
            .file
            .sync_all()
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(store)
    }

    pub(crate) fn latest(&self) -> JournalState {
        if self.slots[0].sequence > self.slots[1].sequence {
            self.slots[0]
        } else {
            self.slots[1]
        }
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) const fn journal_identity(&self) -> Hash256 {
        self.identity
    }

    /// Requires the journal to be at or exactly one decision ahead of the anchor.
    ///
    /// A journal behind the anchor is the restored-older-journal case and fails. A
    /// journal one decision ahead is the interrupted anchor write: the decision is
    /// already durable, so the anchor catches up before any signature is released.
    pub(crate) fn reconcile(
        &mut self,
        current: JournalState,
        previous: Option<JournalState>,
    ) -> Result<(), KeystoreError> {
        let anchor = self.latest();
        if anchor.sequence > current.sequence {
            return Err(KeystoreError::StalePosition);
        }
        if anchor.sequence == current.sequence {
            return if anchor == current {
                Ok(())
            } else {
                Err(KeystoreError::ConflictingSign)
            };
        }
        if anchor.sequence.checked_add(1) != Some(current.sequence) {
            return Err(KeystoreError::StalePosition);
        }
        match previous {
            // The chained tip binds every retained record, so a journal rewritten
            // below this sequence cannot reproduce the anchor's predecessor state.
            Some(previous) if previous == anchor => {}
            _ => return Err(KeystoreError::ConflictingSign),
        }
        self.commit(current)
    }

    /// Durably records the journal's new watermark before a signature is released.
    pub(crate) fn commit(&mut self, state: JournalState) -> Result<(), KeystoreError> {
        if self.poisoned {
            return Err(KeystoreError::DurabilityUnknown);
        }
        let anchor = self.latest();
        if anchor == state {
            return Ok(());
        }
        if anchor.sequence.checked_add(1) != Some(state.sequence)
            || anchor.position >= state.position
        {
            return Err(KeystoreError::InvalidJournal);
        }
        let slot = destination(state.sequence);
        let bytes = slot_record(self.checksum, slot, state);
        // Any uncertain write poisons this instance. Reopening must validate both
        // slots again; never fall back to an older anchor value, because the lost
        // update could be the decision whose signature already escaped.
        self.poisoned = true;
        self.file
            .seek(SeekFrom::Start(
                HEADER_BYTES as u64 + u64::from(slot) * SLOT_BYTES as u64,
            ))
            .and_then(|_| self.file.write_all(&bytes))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| KeystoreError::DurabilityUnknown)?;
        self.slots[usize::from(slot)] = state;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "astrolune-anchor-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("temporary directory");
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("signing.anchor")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn context() -> SigningContext {
        SigningContext {
            chain_id: 7,
            genesis: Hash256([8; 32]),
        }
    }
    fn identity() -> Hash256 {
        Hash256([3; 32])
    }
    fn checksum() -> Hash256 {
        domain_hash(
            HEADER_DOMAIN,
            &header(context(), [9; 32], identity())[..108],
        )
    }
    fn state(sequence: u64, round: u32) -> JournalState {
        JournalState {
            sequence,
            position: Some(SigningPosition {
                height: 42,
                round,
                phase: 1,
            }),
            message: Hash256([6; 32]),
            tip: Hash256([4; 32]),
        }
    }
    fn image(first: JournalState, second: JournalState) -> Vec<u8> {
        let mut bytes = header(context(), [9; 32], identity()).to_vec();
        bytes.extend_from_slice(&slot_record(checksum(), 0, first));
        bytes.extend_from_slice(&slot_record(checksum(), 1, second));
        bytes
    }
    fn open(path: &Path) -> Result<AnchorStore, KeystoreError> {
        AnchorStore::open(path, context(), [9; 32], identity())
    }

    #[test]
    fn anchor_domains_and_physical_slots_match_independent_blake2s_vectors() {
        let header = header(context(), [9; 32], identity());
        assert_eq!(header.len(), HEADER_BYTES);
        assert_eq!(ANCHOR_BYTES, 376);
        assert_eq!(&header[..9], &[65, 76, 83, 65, 78, 67, 72, 49, 7]);
        assert_eq!(
            checksum().to_string(),
            "0dd867a8b8d47239a675ef059efd5f6372869f6db69806f3a4bf566b66b66004"
        );
        for (slot, expected) in [
            (
                0,
                "8a17be460b0aaace14b9798077b17b48e009cb4715ba072fa09ed3b1b1c6732d",
            ),
            (
                1,
                "c2544d98b1673efff32d6527c67341da89f29b4908fcec9be43f59a2277a512e",
            ),
        ] {
            let bytes = slot_record(checksum(), slot, state(1, 5));
            assert_eq!(
                Hash256(bytes[86..].try_into().expect("fixed checksum width")).to_string(),
                expected
            );
        }
    }

    #[test]
    fn noncanonical_absent_position_and_unsupported_phase_are_rejected() {
        let empty = JournalState {
            sequence: 0,
            position: None,
            message: Hash256::ZERO,
            tip: Hash256([4; 32]),
        };
        assert_eq!(
            decode_slot(checksum(), 0, &slot_record(checksum(), 0, empty)).expect("canonical slot"),
            empty
        );
        for invalid in [
            JournalState {
                sequence: 1,
                ..empty
            },
            JournalState {
                position: None,
                message: Hash256([1; 32]),
                ..state(1, 5)
            },
            JournalState {
                sequence: 0,
                ..state(1, 5)
            },
            JournalState {
                position: Some(SigningPosition {
                    height: 1,
                    round: 0,
                    phase: PRECOMMIT_PHASE + 1,
                }),
                ..state(1, 5)
            },
        ] {
            assert_eq!(
                decode_slot(checksum(), 0, &slot_record(checksum(), 0, invalid)),
                Err(KeystoreError::InvalidJournal)
            );
        }
        // The physical slot index is bound into every checksum.
        assert_eq!(
            decode_slot(checksum(), 1, &slot_record(checksum(), 0, state(1, 5))),
            Err(KeystoreError::InvalidJournal)
        );
    }

    #[test]
    fn every_anchor_truncation_and_single_byte_mutation_fails_closed() {
        let fixture = Fixture::new();
        let bytes = image(state(2, 5), state(3, 6));
        std::fs::write(fixture.path(), &bytes).expect("write anchor");
        assert_eq!(
            open(&fixture.path()).expect("valid anchor").latest(),
            state(3, 6)
        );
        for at in 0..bytes.len() {
            std::fs::write(fixture.path(), &bytes[..at]).expect("truncate");
            assert!(open(&fixture.path()).is_err(), "cut {at}");
            for mask in [1u8, 128, 255] {
                let mut altered = bytes.clone();
                altered[at] ^= mask;
                std::fs::write(fixture.path(), &altered).expect("mutate");
                assert!(open(&fixture.path()).is_err(), "bit {at}");
            }
        }
        let mut trailing = bytes;
        trailing.push(0);
        std::fs::write(fixture.path(), &trailing).expect("extend");
        assert!(matches!(
            open(&fixture.path()),
            Err(KeystoreError::InvalidJournal)
        ));
    }

    #[test]
    fn checksummed_gaps_slot_swaps_and_stale_positions_are_rejected() {
        let fixture = Fixture::new();
        for (first, second) in [
            (state(2, 5), state(4, 6)),
            (state(3, 6), state(2, 5)),
            (state(2, 5), state(3, 5)),
            (state(2, 6), state(3, 5)),
            (state(4, 5), state(3, 6)),
        ] {
            std::fs::write(fixture.path(), image(first, second)).expect("write anchor");
            assert!(open(&fixture.path()).is_err());
        }
        // Identical slots are the provisioning state and remain acceptable.
        std::fs::write(fixture.path(), image(state(2, 5), state(2, 5))).expect("write anchor");
        assert_eq!(
            open(&fixture.path()).expect("provisioned anchor").latest(),
            state(2, 5)
        );
    }

    #[test]
    fn a_journal_behind_the_anchor_never_reconciles_and_lagging_anchors_catch_up() {
        let fixture = Fixture::new();
        let mut store =
            AnchorStore::create(&fixture.path(), context(), [9; 32], identity(), state(3, 6))
                .expect("create anchor");
        assert_eq!(
            AnchorStore::create(&fixture.path(), context(), [9; 32], identity(), state(3, 6)).err(),
            Some(KeystoreError::AlreadyExists)
        );
        // Restored older journal: fails loudly rather than adopting the older value.
        assert_eq!(
            store.reconcile(state(2, 5), Some(state(1, 4))),
            Err(KeystoreError::StalePosition)
        );
        // Same sequence, different decision: a mismatched pair is never merged.
        assert_eq!(
            store.reconcile(state(3, 7), Some(state(2, 5))),
            Err(KeystoreError::ConflictingSign)
        );
        // Interrupted anchor write: one decision ahead with a matching predecessor.
        store
            .reconcile(state(4, 7), Some(state(3, 6)))
            .expect("catch up");
        assert_eq!(store.latest(), state(4, 7));
        // Two decisions ahead, or a predecessor that does not match, both fail.
        assert_eq!(
            store.reconcile(state(6, 9), Some(state(5, 8))),
            Err(KeystoreError::StalePosition)
        );
        assert_eq!(
            store.reconcile(state(5, 8), Some(state(4, 9))),
            Err(KeystoreError::ConflictingSign)
        );
        assert_eq!(
            store.reconcile(state(5, 8), None),
            Err(KeystoreError::ConflictingSign)
        );
        assert_eq!(store.journal_identity(), identity());
        assert!(!store.is_poisoned());
        drop(store);
        assert_eq!(
            std::fs::metadata(fixture.path())
                .expect("anchor file")
                .len(),
            ANCHOR_BYTES as u64
        );
        assert_eq!(open(&fixture.path()).expect("reopen").latest(), state(4, 7));
    }

    #[test]
    fn a_locked_anchor_cannot_be_opened_twice_and_missing_files_are_never_created() {
        let fixture = Fixture::new();
        assert!(matches!(
            open(&fixture.path()),
            Err(KeystoreError::JournalFailure)
        ));
        assert!(!fixture.path().exists());
        let store =
            AnchorStore::create(&fixture.path(), context(), [9; 32], identity(), state(1, 5))
                .expect("create anchor");
        assert!(matches!(open(&fixture.path()), Err(KeystoreError::Locked)));
        drop(store);
        assert!(open(&fixture.path()).is_ok());
        // A foreign namespace, key or journal origin is a mismatched pair.
        for (other, key, origin) in [
            (
                SigningContext {
                    chain_id: 8,
                    ..context()
                },
                [9; 32],
                identity(),
            ),
            (context(), [10; 32], identity()),
            (context(), [9; 32], Hash256([4; 32])),
        ] {
            assert!(matches!(
                AnchorStore::open(&fixture.path(), other, key, origin),
                Err(KeystoreError::ContextMismatch)
            ));
        }
    }
}
