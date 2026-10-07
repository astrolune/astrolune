// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Two alternating protected watermarks, bound to an immutable verified prefix.
//! Both slots must validate. Falling back after corruption could authorize equivocation.

use super::{
    MAX_JOURNAL_RECORDS, MAX_PROTECTED_JOURNAL_BYTES, PROTECTED_RECORD_BYTES, decode_entry,
    protected_record, validate_safety,
};
use crate::{KeystoreError, SigningPosition, SigningSafety};
use types::{Hash256, hash::domain_hash};

const MAGIC: &[u8; 8] = b"ALSR0001";
const HEADER_BYTES: usize = 40;
pub(super) const EXTENSION_BYTES: usize = HEADER_BYTES + 2 * PROTECTED_RECORD_BYTES;
const HEADER_DOMAIN: &[u8] = b"astrolune.signing.rollover.v1";
const SLOT_DOMAIN: &[u8] = b"astrolune.signing.rollover.slot.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Watermark {
    pub(super) sequence: u64,
    pub(super) position: SigningPosition,
    pub(super) message: Hash256,
    pub(super) safety: SigningSafety,
}

pub(super) struct Rollover {
    anchor: Hash256,
    slots: [Watermark; 2],
}

impl Rollover {
    pub(super) fn new(
        tip: Hash256,
        last: Option<(SigningPosition, Hash256)>,
        safety: Option<SigningSafety>,
    ) -> Result<Self, KeystoreError> {
        let (position, message) = last.ok_or(KeystoreError::InvalidJournal)?;
        let safety = safety.ok_or(KeystoreError::InvalidJournal)?;
        let initial = Watermark {
            sequence: MAX_JOURNAL_RECORDS,
            position,
            message,
            safety,
        };
        Ok(Self {
            anchor: domain_hash(HEADER_DOMAIN, tip.as_bytes()),
            slots: [initial; 2],
        })
    }

    pub(super) fn latest(&self) -> Watermark {
        if self.slots[0].sequence > self.slots[1].sequence {
            self.slots[0]
        } else {
            self.slots[1]
        }
    }

    fn binding(&self, slot: u8) -> Hash256 {
        let mut bytes = self.anchor.0.to_vec();
        bytes.push(slot);
        domain_hash(SLOT_DOMAIN, &bytes)
    }

    fn encode_slot(&self, slot: u8, watermark: Watermark) -> Vec<u8> {
        protected_record(
            watermark.sequence,
            watermark.position,
            watermark.message,
            self.binding(slot),
            watermark.safety,
        )
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(EXTENSION_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.anchor.as_bytes());
        for slot in 0..2 {
            bytes.extend_from_slice(&self.encode_slot(slot, self.slots[usize::from(slot)]));
        }
        bytes
    }

    pub(super) fn decode(
        tip: Hash256,
        last: Option<(SigningPosition, Hash256)>,
        safety: Option<SigningSafety>,
        bytes: &[u8],
    ) -> Result<Self, KeystoreError> {
        let mut result = Self::new(tip, last, safety)?;
        let baseline = result.latest();
        if bytes.len() != EXTENSION_BYTES
            || &bytes[..8] != MAGIC
            || bytes[8..HEADER_BYTES] != result.anchor.0
        {
            return Err(KeystoreError::InvalidJournal);
        }
        for slot in 0..2u8 {
            let offset = HEADER_BYTES + usize::from(slot) * PROTECTED_RECORD_BYTES;
            let entry = &bytes[offset..offset + PROTECTED_RECORD_BYTES];
            let sequence = u64::from_le_bytes(
                entry[..8]
                    .try_into()
                    .map_err(|_| KeystoreError::InvalidJournal)?,
            );
            let (position, message, _, safety) =
                decode_entry(entry, sequence, result.binding(slot), true)?;
            let safety = safety.ok_or(KeystoreError::InvalidJournal)?;
            let watermark = Watermark {
                sequence,
                position,
                message,
                safety,
            };
            if sequence < MAX_JOURNAL_RECORDS
                || (sequence == MAX_JOURNAL_RECORDS && watermark != baseline)
                || (sequence > MAX_JOURNAL_RECORDS
                    && (Self::slot(sequence) != slot || position <= baseline.position))
            {
                return Err(KeystoreError::InvalidJournal);
            }
            validate_safety(position, safety, Some((baseline.position, baseline.safety)))
                .map_err(|_| KeystoreError::InvalidJournal)?;
            result.slots[usize::from(slot)] = watermark;
        }
        let [a, b] = result.slots;
        if a.sequence == b.sequence {
            if a != baseline || b != baseline {
                return Err(KeystoreError::InvalidJournal);
            }
        } else {
            let (older, newer) = if a.sequence < b.sequence {
                (a, b)
            } else {
                (b, a)
            };
            if older.sequence.checked_add(1) != Some(newer.sequence)
                || older.position >= newer.position
            {
                return Err(KeystoreError::InvalidJournal);
            }
            validate_safety(
                newer.position,
                newer.safety,
                Some((older.position, older.safety)),
            )
            .map_err(|_| KeystoreError::InvalidJournal)?;
        }
        Ok(result)
    }

    fn slot(sequence: u64) -> u8 {
        // Called only for sequences strictly greater than the retained prefix count.
        u8::from(!(sequence - MAX_JOURNAL_RECORDS - 1).is_multiple_of(2))
    }

    pub(super) const fn slot_offset(slot: u8) -> u64 {
        MAX_PROTECTED_JOURNAL_BYTES
            + HEADER_BYTES as u64
            + slot as u64 * PROTECTED_RECORD_BYTES as u64
    }

    pub(super) fn prepare(
        &self,
        sequence: u64,
        position: SigningPosition,
        message: Hash256,
        safety: SigningSafety,
    ) -> Result<(u8, Vec<u8>), KeystoreError> {
        let latest = self.latest();
        if latest.sequence.checked_add(1) != Some(sequence) || position <= latest.position {
            return Err(KeystoreError::InvalidJournal);
        }
        validate_safety(position, safety, Some((latest.position, latest.safety)))?;
        let slot = Self::slot(sequence);
        Ok((
            slot,
            self.encode_slot(
                slot,
                Watermark {
                    sequence,
                    position,
                    message,
                    safety,
                },
            ),
        ))
    }

    pub(super) fn publish(
        &mut self,
        slot: u8,
        sequence: u64,
        position: SigningPosition,
        message: Hash256,
        safety: SigningSafety,
    ) {
        self.slots[usize::from(slot)] = Watermark {
            sequence,
            position,
            message,
            safety,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningLock;

    fn baseline() -> Watermark {
        Watermark {
            sequence: MAX_JOURNAL_RECORDS,
            position: SigningPosition {
                height: 42,
                round: 5,
                phase: 2,
            },
            message: Hash256([6; 32]),
            safety: SigningSafety {
                committee_root: Hash256([9; 32]),
                locked: Some(SigningLock {
                    round: 3,
                    block: Hash256([7; 32]),
                }),
            },
        }
    }
    fn new() -> Rollover {
        let b = baseline();
        Rollover::new(
            Hash256([3; 32]),
            Some((b.position, b.message)),
            Some(b.safety),
        )
        .unwrap()
    }
    fn decode(bytes: &[u8]) -> Result<Rollover, KeystoreError> {
        let b = baseline();
        Rollover::decode(
            Hash256([3; 32]),
            Some((b.position, b.message)),
            Some(b.safety),
            bytes,
        )
    }
    fn advance(r: &mut Rollover) {
        let p = r.latest();
        let position = SigningPosition {
            round: p.position.round + 1,
            phase: 1,
            ..p.position
        };
        let (slot, _) = r
            .prepare(p.sequence + 1, position, p.message, p.safety)
            .unwrap();
        r.publish(slot, p.sequence + 1, position, p.message, p.safety);
    }

    #[test]
    fn rollover_domains_and_physical_slots_match_independent_blake2s_vectors() {
        let r = new();
        assert_eq!(
            r.anchor.to_string(),
            "7a85be7e2d4c0048b3d425263255d52bdafbc178022dedd5a9a3b34e3797c236"
        );
        for (slot, expected) in [
            (
                0,
                "af693cd79244642cef1291c011fb78a43311844e9ca1b5743908a6766d8cac1e",
            ),
            (
                1,
                "aa8686167f8b238dc25e80b8380d5655584cb6d80a938a31995b35f76384e7a8",
            ),
        ] {
            let bytes = r.encode_slot(slot, baseline());
            assert_eq!(
                Hash256(bytes[122..].try_into().unwrap()).to_string(),
                expected
            );
        }
    }

    #[test]
    fn every_extension_truncation_and_single_byte_mutation_fails_closed() {
        let mut r = new();
        for _ in 0..5 {
            let bytes = r.encode();
            assert_eq!(decode(&bytes).unwrap().encode(), bytes);
            for at in 0..bytes.len() {
                assert!(decode(&bytes[..at]).is_err(), "truncation {at}");
                for mask in [1, 128, 255] {
                    let mut altered = bytes.clone();
                    altered[at] ^= mask;
                    assert!(decode(&altered).is_err(), "mutation {at}");
                }
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode(&trailing).is_err());
            advance(&mut r);
        }
    }

    #[test]
    fn checksummed_gaps_slot_swaps_stale_positions_and_lock_regressions_are_rejected() {
        for case in 0..9 {
            let mut r = new();
            advance(&mut r);
            advance(&mut r);
            match case {
                0 => r.slots[1].sequence += 2,
                1 => r.slots.swap(0, 1),
                2 => r.slots[1].position = r.slots[0].position,
                3 => r.slots[0].position = baseline().position,
                4 => r.slots[1].safety.locked = None,
                5 => r.slots[1].safety.committee_root = Hash256([10; 32]),
                6 => r.slots[1].safety.locked.as_mut().unwrap().round = 2,
                7 => r.slots[1].safety.locked.as_mut().unwrap().block = Hash256([8; 32]),
                8 => r.slots[1].safety.locked.as_mut().unwrap().round = u32::MAX,
                _ => unreachable!(),
            }
            assert!(decode(&r.encode()).is_err(), "case {case}");
        }
        let r = new();
        let b = baseline();
        assert!(
            Rollover::decode(
                Hash256([4; 32]),
                Some((b.position, b.message)),
                Some(b.safety),
                &r.encode()
            )
            .is_err()
        );
    }

    #[test]
    fn exhausted_sequence_decodes_without_wrapping_or_authorizing_another_decision() {
        let mut r = new();
        r.slots[1] = Watermark {
            sequence: u64::MAX - 1,
            position: SigningPosition {
                round: 6,
                ..baseline().position
            },
            ..baseline()
        };
        r.slots[0] = Watermark {
            sequence: u64::MAX,
            position: SigningPosition {
                round: 7,
                ..baseline().position
            },
            ..baseline()
        };
        let recovered = decode(&r.encode()).unwrap();
        assert_eq!(recovered.latest().sequence, u64::MAX);
        assert!(
            recovered
                .prepare(
                    0,
                    SigningPosition {
                        round: 8,
                        ..baseline().position
                    },
                    baseline().message,
                    baseline().safety
                )
                .is_err()
        );
    }
}
