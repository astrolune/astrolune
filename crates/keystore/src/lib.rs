// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Purpose-separated non-exporting signer and anti-equivocation boundaries.

#![forbid(unsafe_code)]

pub mod admission;
mod durable;
pub mod error;
pub mod governance;
mod journal;
pub mod key;
pub mod mock;
pub mod signer;
pub mod vault;

pub use durable::DurableSigner;
pub use error::KeystoreError;
pub use journal::{
    MAX_JOURNAL_BYTES, MAX_JOURNAL_RECORDS, MAX_PROTECTED_JOURNAL_BYTES, MAX_ROLLOVER_JOURNAL_BYTES,
};
pub use key::{
    KeyHandle, KeyPurpose, PRECOMMIT_PHASE, PREVOTE_PHASE, PROPOSAL_PHASE, SigningContext,
    SigningPosition,
};
pub use key::{SigningLock, SigningSafety};
pub use mock::MockKeystore;
pub use signer::{ChainSigner, Signer};

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Hash256, ValidatorId};

    #[test]
    fn consensus_key_rejects_a_relabelled_handle() {
        let mut store = MockKeystore::new();
        store.insert("consensus", vid(1), KeyPurpose::Consensus);
        for purpose in [KeyPurpose::Network, KeyPurpose::Wallet, KeyPurpose::Service] {
            assert_eq!(
                store.sign_consensus(
                    &handle("consensus", purpose),
                    SigningPosition {
                        height: 1,
                        round: 0,
                        phase: 0,
                    },
                    Hash256::ZERO
                ),
                Err(KeystoreError::WrongPurpose)
            );
        }
        assert!(!store.has_conflict());
    }

    fn vid(n: u8) -> ValidatorId {
        ValidatorId([n; 32])
    }

    fn handle(id: &str, purpose: KeyPurpose) -> KeyHandle {
        KeyHandle {
            id: id.to_string(),
            purpose,
        }
    }

    #[test]
    fn keystore_error_display() {
        assert_eq!(KeystoreError::UnknownKey.to_string(), "unknown key");
        assert_eq!(KeystoreError::WrongPurpose.to_string(), "wrong purpose");
        assert_eq!(
            KeystoreError::ConflictingSign.to_string(),
            "conflicting sign"
        );
        assert_eq!(KeystoreError::JournalFailure.to_string(), "journal failure");
        assert_eq!(
            KeystoreError::ProviderFailure.to_string(),
            "provider failure"
        );
    }

    #[test]
    fn keystore_error_is_std_error() {
        let err: &dyn std::error::Error = &KeystoreError::UnknownKey;
        assert_eq!(err.to_string(), "unknown key");
    }

    #[test]
    fn insert_and_lookup() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);

        let h = handle("k1", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h).unwrap(), vid(1));
    }

    #[test]
    fn unknown_key_returns_error() {
        let ks = MockKeystore::new();
        let h = handle("missing", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::UnknownKey));
    }

    #[test]
    fn wrong_purpose_returns_error() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Network);

        let h = handle("k1", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::WrongPurpose));
    }

    #[test]
    fn purpose_exact_match() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Service);

        for purpose in [
            KeyPurpose::Consensus,
            KeyPurpose::Network,
            KeyPurpose::Service,
            KeyPurpose::Wallet,
        ] {
            let h = handle("k1", purpose);
            if purpose == KeyPurpose::Service {
                assert_eq!(ks.validator_id(&h).unwrap(), vid(1));
            } else {
                assert_eq!(ks.validator_id(&h), Err(KeystoreError::WrongPurpose));
            }
        }
    }

    #[test]
    fn sign_consensus_unknown_key() {
        let mut ks = MockKeystore::new();
        let h = handle("missing", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        assert_eq!(
            ks.sign_consensus(&h, pos, Hash256([1u8; 32])),
            Err(KeystoreError::UnknownKey)
        );
    }

    #[test]
    fn sign_consensus_wrong_purpose() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Network);
        let h = handle("k1", KeyPurpose::Network);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        assert_eq!(
            ks.sign_consensus(&h, pos, Hash256([1u8; 32])),
            Err(KeystoreError::WrongPurpose)
        );
    }

    #[test]
    fn sign_consensus_success() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let sig = ks.sign_consensus(&h, pos, Hash256([0xAB; 32])).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_consensus_same_message_no_conflict() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 5,
            round: 1,
            phase: 2,
        };
        let msg = Hash256([42u8; 32]);

        let sig1 = ks.sign_consensus(&h, pos, msg).unwrap();
        let sig2 = ks.sign_consensus(&h, pos, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_consensus_different_message_equivocation() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 5,
            round: 1,
            phase: 2,
        };

        let msg1 = Hash256([1u8; 32]);
        let msg2 = Hash256([2u8; 32]);

        ks.sign_consensus(&h, pos, msg1).unwrap();
        assert_eq!(
            ks.sign_consensus(&h, pos, msg2),
            Err(KeystoreError::ConflictingSign)
        );
    }

    #[test]
    fn has_conflict_tracks_state() {
        let mut ks = MockKeystore::new();
        assert!(!ks.has_conflict());

        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };

        ks.sign_consensus(&h, pos, Hash256([0u8; 32])).unwrap();
        assert!(ks.has_conflict());
    }

    #[test]
    fn different_positions_do_not_conflict() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);

        let pos_a = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let pos_b = SigningPosition {
            height: 1,
            round: 0,
            phase: 1,
        };

        let msg = Hash256([42u8; 32]);
        ks.sign_consensus(&h, pos_a, msg).unwrap();
        // different position, no conflict even with same message
        ks.sign_consensus(&h, pos_b, msg).unwrap();
    }

    #[test]
    fn mock_signature_deterministic() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 10,
            round: 3,
            phase: 1,
        };
        let msg = Hash256([0xFF; 32]);

        let sig1 = ks.sign_consensus(&h, pos, msg).unwrap();
        // reset and recreate
        let mut ks2 = MockKeystore::new();
        ks2.insert("k1", vid(1), KeyPurpose::Consensus);
        let sig2 = ks2.sign_consensus(&h, pos, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn mock_signature_varies_by_validator() {
        let make_sig = |n: u8| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(n), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height: 1,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256::ZERO).unwrap()
        };

        assert_ne!(make_sig(1), make_sig(2));
    }

    #[test]
    fn mock_signature_varies_by_message() {
        let make_sig = |m: u8| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(1), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height: 1,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256([m; 32])).unwrap()
        };

        assert_ne!(make_sig(0), make_sig(1));
    }

    #[test]
    fn mock_signature_varies_by_position() {
        let make_sig = |height: u64| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(1), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256::ZERO).unwrap()
        };

        assert_ne!(make_sig(0), make_sig(1));
    }

    #[test]
    fn multiple_keys_independent() {
        let mut ks = MockKeystore::new();
        ks.insert("a", vid(1), KeyPurpose::Consensus);
        ks.insert("b", vid(2), KeyPurpose::Consensus);

        let ha = handle("a", KeyPurpose::Consensus);
        let hb = handle("b", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };

        let sig_a = ks.sign_consensus(&ha, pos, Hash256([1u8; 32])).unwrap();
        let sig_b = ks.sign_consensus(&hb, pos, Hash256([2u8; 32])).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn default_is_empty() {
        let ks = MockKeystore::default();
        assert!(!ks.has_conflict());
        let h = handle("anything", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::UnknownKey));
    }

    #[test]
    fn signing_position_ord() {
        let a = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let b = SigningPosition {
            height: 2,
            round: 0,
            phase: 0,
        };
        let c = SigningPosition {
            height: 1,
            round: 1,
            phase: 0,
        };
        assert!(a < b);
        assert!(a < c);
        assert!(b > c);
    }
}
