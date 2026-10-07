// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical non-membership proof decoding and adversarial verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use state::StateAbsenceProof;
use types::{Hash256, StateKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = StateAbsenceProof::from_bytes(data) {
        assert_eq!(proof.to_bytes().unwrap(), data);
        // The zero sentinel is never a valid trusted state commitment.
        assert!(!proof.verify(Hash256::ZERO, &StateKey(vec![])));
    }
});
