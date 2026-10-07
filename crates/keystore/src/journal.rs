// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Exclusively locked signing journal with bounded protected-watermark rollover.

use crate::{
    KeystoreError, PRECOMMIT_PHASE, SigningContext, SigningLock, SigningPosition, SigningSafety,
};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use types::{Hash256, hash::domain_hash};

mod rollover;
#[cfg(test)]
mod rollover_tests;
use rollover::Rollover;

const HEADER_BYTES: usize = 108;
const RECORD_BYTES: usize = 85;
const PROTECTED_RECORD_BYTES: usize = 154;
const HEADER_DOMAIN: &[u8] = b"astrolune.signing.journal.v1";
const RECORD_DOMAIN: &[u8] = b"astrolune.signing.decision.v1";

/// Retained prefix decisions. Version 1 stops here; protected journals roll over.
pub const MAX_JOURNAL_RECORDS: u64 = 100_000;
/// Maximum reference journal size, including its header and chained checksums.
pub const MAX_JOURNAL_BYTES: u64 = HEADER_BYTES as u64 + RECORD_BYTES as u64 * MAX_JOURNAL_RECORDS;
/// Version-2 append-only prefix size, before protected watermark rollover.
pub const MAX_PROTECTED_JOURNAL_BYTES: u64 =
    HEADER_BYTES as u64 + PROTECTED_RECORD_BYTES as u64 * MAX_JOURNAL_RECORDS;
/// Maximum protected journal size including the fixed-size rollover extension.
pub const MAX_ROLLOVER_JOURNAL_BYTES: u64 =
    MAX_PROTECTED_JOURNAL_BYTES + rollover::EXTENSION_BYTES as u64;

pub(crate) struct Journal {
    file: File,
    count: u64,
    tip: Hash256,
    last: Option<(SigningPosition, Hash256)>,
    poisoned: bool,
    protected: bool,
    safety: Option<SigningSafety>,
    rollover: Option<Rollover>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
fn header(context: SigningContext, public_key: [u8; 32]) -> [u8; HEADER_BYTES] {
    header_version(context, public_key, false)
}

fn header_version(
    context: SigningContext,
    public_key: [u8; 32],
    protected: bool,
) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"ALSJ");
    bytes[4..8].copy_from_slice(&(if protected { 2u32 } else { 1u32 }).to_le_bytes());
    bytes[8..12].copy_from_slice(&context.chain_id.to_le_bytes());
    bytes[12..44].copy_from_slice(&context.genesis.0);
    bytes[44..76].copy_from_slice(&public_key);
    let checksum = domain_hash(HEADER_DOMAIN, &bytes[..76]);
    bytes[76..].copy_from_slice(&checksum.0);
    bytes
}

fn record(
    sequence: u64,
    position: SigningPosition,
    message: Hash256,
    tip: Hash256,
) -> [u8; RECORD_BYTES] {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
    bytes[8..16].copy_from_slice(&position.height.to_le_bytes());
    bytes[16..20].copy_from_slice(&position.round.to_le_bytes());
    bytes[20] = position.phase;
    bytes[21..53].copy_from_slice(&message.0);
    let checksum = record_hash(tip, &bytes[..53]);
    bytes[53..].copy_from_slice(&checksum.0);
    bytes
}

fn record_hash(tip: Hash256, body: &[u8]) -> Hash256 {
    let mut input = Vec::with_capacity(32 + body.len());
    input.extend_from_slice(&tip.0);
    input.extend_from_slice(body);
    domain_hash(RECORD_DOMAIN, &input)
}

#[cfg(test)]
fn decode_record(
    bytes: &[u8; RECORD_BYTES],
    sequence: u64,
    tip: Hash256,
) -> Result<(SigningPosition, Hash256, Hash256), KeystoreError> {
    let (position, message, checksum, _) = decode_entry(bytes, sequence, tip, false)?;
    Ok((position, message, checksum))
}

fn protected_record(
    sequence: u64,
    position: SigningPosition,
    message: Hash256,
    tip: Hash256,
    safety: SigningSafety,
) -> Vec<u8> {
    let base = record(sequence, position, message, tip);
    let mut bytes = Vec::with_capacity(PROTECTED_RECORD_BYTES);
    bytes.extend_from_slice(&base[..53]);
    bytes.extend_from_slice(&safety.committee_root.0);
    bytes.push(u8::from(safety.locked.is_some()));
    let locked = safety.locked.unwrap_or(SigningLock {
        round: 0,
        block: Hash256::ZERO,
    });
    bytes.extend_from_slice(&locked.round.to_le_bytes());
    bytes.extend_from_slice(&locked.block.0);
    let checksum = record_hash(tip, &bytes);
    bytes.extend_from_slice(&checksum.0);
    bytes
}

type DecodedEntry = (SigningPosition, Hash256, Hash256, Option<SigningSafety>);
fn decode_entry(
    bytes: &[u8],
    sequence: u64,
    tip: Hash256,
    protected: bool,
) -> Result<DecodedEntry, KeystoreError> {
    let parsed = (|| -> Result<_, codec::DecodeError> {
        let mut decoder = codec::Decoder::new(bytes);
        let sequence = decoder.read_u64()?;
        let position = SigningPosition {
            height: decoder.read_u64()?,
            round: decoder.read_u32()?,
            phase: decoder.read_u8()?,
        };
        let message = Hash256(decoder.read_fixed()?);
        let safety = if protected {
            let committee_root = Hash256(decoder.read_fixed()?);
            let flag = decoder.read_u8()?;
            let round = decoder.read_u32()?;
            let block = Hash256(decoder.read_fixed()?);
            let locked = match flag {
                0 if round == 0 && block == Hash256::ZERO => None,
                1 => Some(SigningLock { round, block }),
                _ => return Err(codec::DecodeError::NonCanonical),
            };
            Some(SigningSafety {
                committee_root,
                locked,
            })
        } else {
            None
        };
        let checksum = Hash256(decoder.read_fixed()?);
        decoder.finish()?;
        Ok((sequence, position, message, checksum, safety))
    })()
    .map_err(|_| KeystoreError::InvalidJournal)?;
    if parsed.0 != sequence
        || parsed.1.phase > PRECOMMIT_PHASE
        || parsed.3 != record_hash(tip, &bytes[..bytes.len() - 32])
    {
        return Err(KeystoreError::InvalidJournal);
    }
    Ok((parsed.1, parsed.2, parsed.3, parsed.4))
}

fn validate_safety(
    position: SigningPosition,
    safety: SigningSafety,
    previous: Option<(SigningPosition, SigningSafety)>,
) -> Result<(), KeystoreError> {
    if safety.committee_root == Hash256::ZERO
        || safety
            .locked
            .is_some_and(|lock| lock.round > position.round)
    {
        return Err(KeystoreError::InvalidSafety);
    }
    if let Some((old_position, old)) = previous
        && old_position.height == position.height
    {
        if old.committee_root != safety.committee_root {
            return Err(KeystoreError::InvalidSafety);
        }
        if let Some(locked) = old.locked
            && !safety
                .locked
                .is_some_and(|next| next.round > locked.round || next == locked)
        {
            return Err(KeystoreError::InvalidSafety);
        }
    }
    Ok(())
}

fn canonical_path(path: &Path) -> Result<PathBuf, KeystoreError> {
    let name = path.file_name().ok_or(KeystoreError::JournalFailure)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = fs::canonicalize(parent)
        .map_err(|_| KeystoreError::JournalFailure)?
        .join(name);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(KeystoreError::InvalidJournal);
    }
    Ok(path)
}

fn lock(file: &File) -> Result<(), KeystoreError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => KeystoreError::Locked,
        TryLockError::Error(_) => KeystoreError::JournalFailure,
    })
}

// Unix synchronizes the directory entry on create. Windows power-loss durability
// depends on the filesystem; existing journal updates synchronize the same file.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

impl Journal {
    pub(crate) fn create(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::create_mode(path, context, public_key, false)
    }

    pub(crate) fn create_protected(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::create_mode(path, context, public_key, true)
    }

    fn create_mode(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
        protected: bool,
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
        let bytes = header_version(context, public_key, protected);
        // Failure leaves the file in place: never silently reset an interrupted create.
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(Self {
            file,
            count: 0,
            tip: domain_hash(HEADER_DOMAIN, &bytes[..76]),
            last: None,
            poisoned: false,
            protected,
            safety: None,
            rollover: None,
        })
    }

    pub(crate) fn open(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        let path = canonical_path(path)?;
        // Never creates a missing journal, even if the key is available.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| KeystoreError::JournalFailure)?;
        lock(&file)?;
        let metadata = file.metadata().map_err(|_| KeystoreError::JournalFailure)?;
        let length = metadata.len();
        if !metadata.is_file()
            || !(HEADER_BYTES as u64..=MAX_ROLLOVER_JOURNAL_BYTES).contains(&length)
        {
            return Err(KeystoreError::InvalidJournal);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| KeystoreError::JournalFailure)?;
        let mut bytes = [0; HEADER_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| KeystoreError::InvalidJournal)?;
        let checksum = domain_hash(HEADER_DOMAIN, &bytes[..76]);
        let protected = match bytes[4..8] {
            [1, 0, 0, 0] => false,
            [2, 0, 0, 0] => true,
            _ => return Err(KeystoreError::InvalidJournal),
        };
        if &bytes[..4] != b"ALSJ" || bytes[76..] != checksum.0 {
            return Err(KeystoreError::InvalidJournal);
        }
        if bytes != header_version(context, public_key, protected) {
            return Err(KeystoreError::ContextMismatch);
        }
        let record_size = if protected {
            PROTECTED_RECORD_BYTES
        } else {
            RECORD_BYTES
        };
        let rolled = protected && length == MAX_ROLLOVER_JOURNAL_BYTES;
        let prefix_length = if rolled {
            MAX_PROTECTED_JOURNAL_BYTES
        } else {
            length
        };
        if !(prefix_length - HEADER_BYTES as u64).is_multiple_of(record_size as u64) {
            return Err(KeystoreError::InvalidJournal);
        }
        let count = (prefix_length - HEADER_BYTES as u64) / record_size as u64;
        if count > MAX_JOURNAL_RECORDS {
            return Err(KeystoreError::InvalidJournal);
        }
        let mut journal = Self {
            file,
            count,
            tip: checksum,
            last: None,
            poisoned: false,
            protected,
            safety: None,
            rollover: None,
        };
        for sequence in 1..=count {
            let mut bytes = [0; PROTECTED_RECORD_BYTES];
            journal
                .file
                .read_exact(&mut bytes[..record_size])
                .map_err(|_| KeystoreError::InvalidJournal)?;
            let (position, message, tip, safety) =
                decode_entry(&bytes[..record_size], sequence, journal.tip, protected)?;
            if let Some(next) = safety {
                validate_safety(
                    position,
                    next,
                    journal
                        .last
                        .zip(journal.safety)
                        .map(|((position, _), safety)| (position, safety)),
                )
                .map_err(|_| KeystoreError::InvalidJournal)?;
            }
            if journal
                .last
                .is_some_and(|(previous, _)| position <= previous)
            {
                return Err(KeystoreError::InvalidJournal);
            }
            journal.safety = safety;
            journal.last = Some((position, message));
            journal.tip = tip;
        }
        if rolled {
            journal.recover_rollover()?;
        }
        journal.check_length()?;
        // A preceding failed sync may have left a complete record in the OS cache.
        // Re-establish durability before allowing even an idempotent signature retry.
        journal
            .file
            .sync_all()
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(journal)
    }

    fn recover_rollover(&mut self) -> Result<(), KeystoreError> {
        let mut bytes = [0; rollover::EXTENSION_BYTES];
        self.file
            .read_exact(&mut bytes)
            .map_err(|_| KeystoreError::InvalidJournal)?;
        let rollover = Rollover::decode(self.tip, self.last, self.safety, &bytes)?;
        let latest = rollover.latest();
        self.count = latest.sequence;
        self.last = Some((latest.position, latest.message));
        self.safety = Some(latest.safety);
        self.rollover = Some(rollover);
        Ok(())
    }

    pub(crate) const fn last_position(&self) -> Option<SigningPosition> {
        match self.last {
            Some((position, _)) => Some(position),
            None => None,
        }
    }

    fn check_length(&mut self) -> Result<(), KeystoreError> {
        let record_size = if self.protected {
            PROTECTED_RECORD_BYTES
        } else {
            RECORD_BYTES
        };
        let expected = if self.rollover.is_some() {
            MAX_ROLLOVER_JOURNAL_BYTES
        } else {
            HEADER_BYTES as u64 + self.count * record_size as u64
        };
        if !self
            .file
            .metadata()
            .is_ok_and(|metadata| metadata.len() == expected)
        {
            self.poisoned = true;
            return Err(KeystoreError::InvalidJournal);
        }
        if let Some(rollover) = &self.rollover {
            let mut bytes = [0; rollover::EXTENSION_BYTES];
            if self
                .file
                .seek(SeekFrom::Start(MAX_PROTECTED_JOURNAL_BYTES))
                .and_then(|_| self.file.read_exact(&mut bytes))
                .is_err()
                || bytes.as_slice() != rollover.encode()
            {
                self.poisoned = true;
                return Err(KeystoreError::InvalidJournal);
            }
        }
        Ok(())
    }

    pub(crate) fn reserve(
        &mut self,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<(), KeystoreError> {
        self.reserve_with(position, message, |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        })
    }

    fn reserve_with(
        &mut self,
        position: SigningPosition,
        message: Hash256,
        persist: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), KeystoreError> {
        self.reserve_entry(position, message, None, persist)
    }

    pub(crate) const fn is_protected(&self) -> bool {
        self.protected
    }
    pub(crate) const fn safety(&self) -> Option<SigningSafety> {
        self.safety
    }

    pub(crate) fn reserve_protected(
        &mut self,
        position: SigningPosition,
        message: Hash256,
        safety: SigningSafety,
    ) -> Result<(), KeystoreError> {
        self.reserve_entry(position, message, Some(safety), |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        })
    }

    fn reserve_entry(
        &mut self,
        position: SigningPosition,
        message: Hash256,
        safety: Option<SigningSafety>,
        persist: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), KeystoreError> {
        if self.poisoned {
            return Err(KeystoreError::DurabilityUnknown);
        }
        if position.phase > PRECOMMIT_PHASE {
            return Err(KeystoreError::InvalidPosition);
        }
        if self.protected != safety.is_some() {
            return Err(KeystoreError::InvalidSafety);
        }
        self.check_length()?;
        if let Some((previous, digest)) = self.last {
            if position < previous {
                return Err(KeystoreError::StalePosition);
            }
            if position == previous {
                return if message == digest && safety == self.safety {
                    Ok(())
                } else {
                    Err(KeystoreError::ConflictingSign)
                };
            }
        }
        if !self.protected && self.count == MAX_JOURNAL_RECORDS {
            return Err(KeystoreError::LimitExceeded);
        }
        if let Some(next) = safety {
            validate_safety(
                position,
                next,
                self.last
                    .zip(self.safety)
                    .map(|((position, _), safety)| (position, safety)),
            )?;
        }
        let sequence = self
            .count
            .checked_add(1)
            .ok_or(KeystoreError::LimitExceeded)?;
        if self.protected && self.count == MAX_JOURNAL_RECORDS && self.rollover.is_none() {
            self.activate_rollover(|file, bytes| {
                file.write_all(bytes)?;
                file.sync_all()
            })?;
        }
        let update = self
            .rollover
            .as_ref()
            .map(|rollover| {
                rollover.prepare(
                    sequence,
                    position,
                    message,
                    safety.ok_or(KeystoreError::InvalidSafety)?,
                )
            })
            .transpose()?;
        let (offset, bytes) = if let Some((slot, bytes)) = &update {
            (Rollover::slot_offset(*slot), bytes.clone())
        } else if let Some(next) = safety {
            (
                HEADER_BYTES as u64 + self.count * PROTECTED_RECORD_BYTES as u64,
                protected_record(sequence, position, message, self.tip, next),
            )
        } else {
            (
                HEADER_BYTES as u64 + self.count * RECORD_BYTES as u64,
                record(sequence, position, message, self.tip).to_vec(),
            )
        };
        // Any uncertain write poisons this instance. No signature can escape until
        // reopening validates the complete prefix and synchronizes it successfully.
        self.poisoned = true;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| KeystoreError::DurabilityUnknown)?;
        persist(&mut self.file, &bytes).map_err(|_| KeystoreError::DurabilityUnknown)?;
        self.last = Some((position, message));
        self.safety = safety;
        if let Some((slot, _)) = update {
            self.rollover
                .as_mut()
                .ok_or(KeystoreError::InvalidJournal)?
                .publish(
                    slot,
                    sequence,
                    position,
                    message,
                    safety.ok_or(KeystoreError::InvalidSafety)?,
                );
        } else {
            self.tip = record_hash(self.tip, &bytes[..bytes.len() - 32]);
        }
        self.count = sequence;
        self.poisoned = false;
        Ok(())
    }

    fn activate_rollover(
        &mut self,
        persist: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), KeystoreError> {
        if !self.protected || self.count != MAX_JOURNAL_RECORDS || self.rollover.is_some() {
            return Err(KeystoreError::InvalidJournal);
        }
        let rollover = Rollover::new(self.tip, self.last, self.safety)?;
        // Keep the original inode and its lock, including through hard-link aliases.
        // The complete prefix is immutable; no signature is returned during activation.
        self.poisoned = true;
        self.file
            .seek(SeekFrom::Start(MAX_PROTECTED_JOURNAL_BYTES))
            .map_err(|_| KeystoreError::DurabilityUnknown)?;
        persist(&mut self.file, &rollover.encode())
            .map_err(|_| KeystoreError::DurabilityUnknown)?;
        self.rollover = Some(rollover);
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "astrolune-journal-fault-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("journal.bin")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn context() -> SigningContext {
        SigningContext {
            chain_id: 7,
            genesis: Hash256([8; 32]),
        }
    }

    #[test]
    fn protected_lock_and_digest_recover_together_after_uncertain_write() {
        let safety = SigningSafety {
            committee_root: Hash256([9; 32]),
            locked: Some(SigningLock {
                round: 3,
                block: Hash256([7; 32]),
            }),
        };
        for written in [0, 53, 122, PROTECTED_RECORD_BYTES] {
            let fixture = Fixture::new();
            let mut journal =
                Journal::create_protected(&fixture.path(), context(), [9; 32]).unwrap();
            assert_eq!(
                journal.reserve_entry(
                    position(42),
                    Hash256([6; 32]),
                    Some(safety),
                    |file, bytes| {
                        file.write_all(&bytes[..written])?;
                        Err(std::io::Error::other("injected sync failure"))
                    }
                ),
                Err(KeystoreError::DurabilityUnknown)
            );
            assert_eq!(
                journal.reserve_protected(position(43), Hash256([6; 32]), safety),
                Err(KeystoreError::DurabilityUnknown)
            );
            drop(journal);
            let before = fs::read(fixture.path()).unwrap();
            let result = Journal::open(&fixture.path(), context(), [9; 32]);
            if written == 0 {
                assert_eq!(result.unwrap().safety(), None);
            } else if written == PROTECTED_RECORD_BYTES {
                let mut recovered = result.unwrap();
                assert_eq!(recovered.safety(), Some(safety));
                recovered
                    .reserve_protected(position(42), Hash256([6; 32]), safety)
                    .unwrap();
            } else {
                assert!(matches!(result, Err(KeystoreError::InvalidJournal)));
            }
            assert_eq!(fs::read(fixture.path()).unwrap(), before);
        }
    }

    #[test]
    fn protected_checksum_binds_lock_metadata_and_matches_python_vector() {
        let initial = header_version(context(), [9; 32], true);
        let tip = domain_hash(HEADER_DOMAIN, &initial[..76]);
        let safety = SigningSafety {
            committee_root: Hash256([9; 32]),
            locked: Some(SigningLock {
                round: 3,
                block: Hash256([7; 32]),
            }),
        };
        let bytes = protected_record(
            1,
            SigningPosition {
                phase: 2,
                ..position(42)
            },
            Hash256([6; 32]),
            tip,
            safety,
        );
        assert_eq!(bytes.len(), PROTECTED_RECORD_BYTES);
        let (_, _, hash, restored) = decode_entry(&bytes, 1, tip, true).unwrap();
        assert_eq!(
            tip.to_string(),
            "ee1aa8e16d78a18a83505f8c1996452976d496f29b0f4fafc248ba029fdfe0fd"
        );
        assert_eq!(
            hash.to_string(),
            "44da84a2acf2ea8dbae18a2b11e157b550f6ebab9b294acd2722318bf667b02a"
        );
        assert_eq!(restored, Some(safety));
        assert_eq!(hash, record_hash(tip, &bytes[..122]));
        for index in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[index] ^= 1;
            assert!(decode_entry(&altered, 1, tip, true).is_err());
        }
    }
    #[test]
    fn protected_recovery_rejects_invalid_safety_even_with_valid_checksums() {
        let fixture = Fixture::new();
        let initial = header_version(context(), [9; 32], true);
        let tip = domain_hash(HEADER_DOMAIN, &initial[..76]);
        let safety = SigningSafety {
            committee_root: Hash256([9; 32]),
            locked: Some(SigningLock {
                round: 3,
                block: Hash256([7; 32]),
            }),
        };
        let first = protected_record(1, position(42), Hash256([6; 32]), tip, safety);
        let tip = record_hash(tip, &first[..122]);
        let next_position = SigningPosition {
            round: 6,
            ..position(42)
        };
        for next in [
            SigningSafety {
                committee_root: Hash256::ZERO,
                ..safety
            },
            SigningSafety {
                committee_root: Hash256([8; 32]),
                ..safety
            },
            SigningSafety {
                locked: None,
                ..safety
            },
            SigningSafety {
                locked: Some(SigningLock {
                    round: 2,
                    block: Hash256([7; 32]),
                }),
                ..safety
            },
            SigningSafety {
                locked: Some(SigningLock {
                    round: 3,
                    block: Hash256([8; 32]),
                }),
                ..safety
            },
            SigningSafety {
                locked: Some(SigningLock {
                    round: 7,
                    block: Hash256([7; 32]),
                }),
                ..safety
            },
        ] {
            let second = protected_record(2, next_position, Hash256([6; 32]), tip, next);
            let bytes = [initial.as_slice(), first.as_slice(), second.as_slice()].concat();
            fs::write(fixture.path(), &bytes).unwrap();
            assert!(matches!(
                Journal::open(&fixture.path(), context(), [9; 32]),
                Err(KeystoreError::InvalidJournal)
            ));
            assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        }
    }

    fn position(height: u64) -> SigningPosition {
        SigningPosition {
            height,
            round: 5,
            phase: 1,
        }
    }

    #[test]
    fn checksums_match_independent_python_blake2s_vectors() {
        let bytes = header(context(), [9; 32]);
        let tip = domain_hash(HEADER_DOMAIN, &bytes[..76]);
        assert_eq!(
            tip.to_string(),
            "d4bd91c229f50b736d91fd2031492b4a56b2e36dc98003cbe5643c5cff62e25d"
        );
        assert_eq!(&bytes[..12], &[65, 76, 83, 74, 1, 0, 0, 0, 7, 0, 0, 0]);
        let bytes = record(1, position(42), Hash256([6; 32]), tip);
        let (coordinate, digest, checksum) = decode_record(&bytes, 1, tip).unwrap();
        assert_eq!(coordinate, position(42));
        assert_eq!(digest, Hash256([6; 32]));
        assert_eq!(
            checksum.to_string(),
            "e39464bfed981fb45c77d2a76ca71b4ab005cfe3fbde1056554b072ba486566d"
        );
    }

    #[test]
    fn uncertain_writes_poison_signing_and_recovery_preserves_complete_decisions() {
        for written in [0, 12, RECORD_BYTES] {
            let fixture = Fixture::new();
            let mut journal = Journal::create(&fixture.path(), context(), [9; 32]).unwrap();
            let result = journal.reserve_with(position(42), Hash256([6; 32]), |file, bytes| {
                file.write_all(&bytes[..written])?;
                // Model failure before append, during append, or at synchronization.
                Err(std::io::Error::other("injected persistence failure"))
            });
            assert_eq!(result, Err(KeystoreError::DurabilityUnknown));
            assert_eq!(
                journal.reserve(position(42), Hash256([6; 32])),
                Err(KeystoreError::DurabilityUnknown)
            );
            assert_eq!(
                journal.reserve(position(43), Hash256([7; 32])),
                Err(KeystoreError::DurabilityUnknown)
            );
            drop(journal);
            let before = fs::read(fixture.path()).unwrap();
            let recovered = Journal::open(&fixture.path(), context(), [9; 32]);
            if written == 12 {
                assert!(matches!(recovered, Err(KeystoreError::InvalidJournal)));
            } else {
                let mut recovered = recovered.unwrap();
                if written == RECORD_BYTES {
                    assert_eq!(recovered.last_position(), Some(position(42)));
                    recovered.reserve(position(42), Hash256([6; 32])).unwrap();
                    assert_eq!(
                        recovered.reserve(position(42), Hash256([7; 32])),
                        Err(KeystoreError::ConflictingSign)
                    );
                } else {
                    assert_eq!(recovered.last_position(), None);
                }
            }
            assert_eq!(fs::read(fixture.path()).unwrap(), before);
        }
    }

    #[test]
    fn valid_checksums_do_not_allow_reordered_duplicate_or_invalid_coordinates() {
        let fixture = Fixture::new();
        let initial = header(context(), [9; 32]);
        let tip = domain_hash(HEADER_DOMAIN, &initial[..76]);
        let first = record(1, position(42), Hash256([6; 32]), tip);
        let tip = record_hash(tip, &first[..53]);
        for (sequence, next) in [
            (1, position(43)),
            (3, position(43)),
            (2, position(41)),
            (2, position(42)),
            (
                2,
                SigningPosition {
                    phase: 255,
                    ..position(43)
                },
            ),
        ] {
            let second = record(sequence, next, Hash256([7; 32]), tip);
            let bytes = [initial.as_slice(), first.as_slice(), second.as_slice()].concat();
            fs::write(fixture.path(), &bytes).unwrap();
            assert!(matches!(
                Journal::open(&fixture.path(), context(), [9; 32]),
                Err(KeystoreError::InvalidJournal)
            ));
            assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        }
    }

    #[test]
    fn full_journal_halts_new_signing_and_unexpected_length_poisons_the_session() {
        let fixture = Fixture::new();
        let mut journal = Journal::create(&fixture.path(), context(), [9; 32]).unwrap();
        journal
            .file
            .write_all(&vec![
                0;
                usize::try_from(MAX_JOURNAL_BYTES).unwrap()
                    - HEADER_BYTES
            ])
            .unwrap();
        journal.count = MAX_JOURNAL_RECORDS;
        journal.last = Some((position(42), Hash256([6; 32])));
        assert_eq!(
            journal.reserve(position(43), Hash256([6; 32])),
            Err(KeystoreError::LimitExceeded)
        );
        journal.reserve(position(42), Hash256([6; 32])).unwrap();
        journal.file.write_all(&[0]).unwrap();
        assert_eq!(
            journal.reserve(position(42), Hash256([6; 32])),
            Err(KeystoreError::InvalidJournal)
        );
        assert_eq!(
            journal.reserve(position(43), Hash256([6; 32])),
            Err(KeystoreError::DurabilityUnknown)
        );
    }
}
