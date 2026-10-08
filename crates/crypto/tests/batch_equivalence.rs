// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded parallel verification decides adversarial Ed25519 inputs exactly as
//! the serial strict path does, and reports the same failing index at every
//! worker count. These are the inputs where the randomized cofactored batch
//! equation would disagree with strict verification: small-order and weak keys,
//! non-canonical key encodings with `y >= p`, scalars that are congruent to a
//! valid scalar modulo the group order, and degenerate signature bytes. Every
//! case asserts that the strict predicate decides, not the batch layout.

use crypto::batch::{
    DigestRequest, SignatureRequest, first_digest_failure, first_failure, verify_all,
};
use crypto::blake2s::{derive_key, ed25519_public_key, ed25519_sign, ed25519_verify};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
}

const WORKER_COUNTS: [usize; 8] = [0, 1, 2, 3, 4, 8, 32, 64];

/// Compressed encodings of the eight points whose order divides eight.
const SMALL_ORDER_KEYS: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// Key encodings whose `y` coordinate is `p`, `p + 1` and `2^255 - 1`.
const NONCANONICAL_KEYS: [&str; 3] = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// Little-endian encoding of the Ed25519 group order `L`.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Adds the group order to the signature scalar, leaving it congruent but unreduced.
fn plus_group_order(signature: &[u8; 64]) -> [u8; 64] {
    let mut result = *signature;
    let mut carry = 0u16;
    for (byte, order) in result[32..].iter_mut().zip(GROUP_ORDER) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = u8::try_from(sum & 0xFF).unwrap();
        carry = sum >> 8;
    }
    result
}

fn valid_batch(count: usize) -> Vec<DigestRequest> {
    (0..count)
        .map(|index| {
            let secret = derive_key(&[u8::try_from(index).unwrap(); 32], "batch.equivalence");
            let digest = *crypto::blake2s_hash(&index.to_le_bytes()).as_bytes();
            DigestRequest {
                public_key: ed25519_public_key(&secret),
                digest,
                signature: ed25519_sign(&secret, &digest),
            }
        })
        .collect()
}

fn borrow(requests: &[DigestRequest]) -> Vec<SignatureRequest<'_>> {
    requests
        .iter()
        .map(|request| SignatureRequest {
            public_key: &request.public_key,
            message: &request.digest,
            signature: &request.signature,
        })
        .collect()
}

/// Every case a cofactored batch equation could decide differently.
fn adversarial() -> Vec<DigestRequest> {
    let secret = [5u8; 32];
    let digest = *crypto::blake2s_hash(b"astrolune.batch.equivalence").as_bytes();
    let public_key = ed25519_public_key(&secret);
    let signature = ed25519_sign(&secret, &digest);
    let mut requests: Vec<_> = SMALL_ORDER_KEYS
        .into_iter()
        .chain(NONCANONICAL_KEYS)
        .map(|encoded| DigestRequest {
            public_key: hex(encoded),
            digest,
            signature,
        })
        .collect();
    let mut flipped = signature;
    flipped[63] ^= 1;
    for altered in [plus_group_order(&signature), [0; 64], [0xFF; 64], flipped] {
        requests.push(DigestRequest {
            public_key,
            digest,
            signature: altered,
        });
    }
    requests
}

#[test]
fn every_adversarial_request_is_rejected_by_the_strict_predicate() {
    let requests = adversarial();
    assert_eq!(
        requests.len(),
        SMALL_ORDER_KEYS.len() + NONCANONICAL_KEYS.len() + 4
    );
    for (case, request) in requests.iter().enumerate() {
        assert!(!request.verify(), "case {case}");
        assert_eq!(first_digest_failure(&[*request]), Some(0), "case {case}");
    }
}

#[test]
fn adversarial_requests_are_rejected_at_the_same_index_at_every_worker_count() {
    let valid = valid_batch(9);
    for (case, bad) in adversarial().into_iter().enumerate() {
        for position in [0, 4, 8] {
            let mut requests = valid.clone();
            requests[position] = bad;
            let serial = requests.iter().position(|request| !request.verify());
            assert_eq!(serial, Some(position), "case {case} position {position}");
            assert_eq!(
                first_digest_failure(&requests),
                serial,
                "case {case} position {position}"
            );
            let borrowed = borrow(&requests);
            for workers in WORKER_COUNTS {
                assert_eq!(
                    first_failure(&borrowed, workers),
                    serial,
                    "case {case} position {position} workers {workers}"
                );
                assert!(
                    !verify_all(&borrowed, workers),
                    "case {case} position {position} workers {workers}"
                );
            }
        }
    }
}

#[test]
fn noncanonical_key_encodings_are_rejected_at_every_batch_position() {
    // A `y >= p` encoding is never the canonical encoding of a point, so strict
    // verification rejects it before any signature arithmetic. An
    // implementation that reduced `y` first would accept a second encoding of
    // the same key, and the batch path must not reintroduce that.
    let valid = valid_batch(9);
    for encoded in NONCANONICAL_KEYS {
        let key: [u8; 32] = hex(encoded);
        for position in [0, 4, 8] {
            let mut requests = valid.clone();
            requests[position].public_key = key;
            assert!(!requests[position].verify(), "position {position}");
            assert_eq!(
                first_digest_failure(&requests),
                Some(position),
                "position {position}"
            );
            let borrowed = borrow(&requests);
            for workers in WORKER_COUNTS {
                assert_eq!(
                    first_failure(&borrowed, workers),
                    Some(position),
                    "position {position} workers {workers}"
                );
            }
        }
    }
}

#[test]
fn malleable_and_degenerate_signatures_never_pass_a_batch() {
    let secret = [5u8; 32];
    let digest = *crypto::blake2s_hash(b"astrolune.batch.malleability").as_bytes();
    let public_key = ed25519_public_key(&secret);
    let signature = ed25519_sign(&secret, &digest);
    let original = DigestRequest {
        public_key,
        digest,
        signature,
    };
    assert!(original.verify());
    // S + L is congruent to S modulo the group order, all-zero bytes encode a
    // small-order R with a zero scalar, and all-one bytes set the high scalar
    // bits. None of the three is a valid strict signature.
    for altered in [plus_group_order(&signature), [0; 64], [0xFF; 64]] {
        let request = DigestRequest {
            public_key,
            digest,
            signature: altered,
        };
        assert!(!request.verify());
        let mut requests = vec![original; 9];
        requests[4] = request;
        assert_eq!(first_digest_failure(&requests), Some(4));
        let borrowed = borrow(&requests);
        for workers in WORKER_COUNTS {
            assert_eq!(
                first_failure(&borrowed, workers),
                Some(4),
                "workers {workers}"
            );
            assert!(!verify_all(&borrowed, workers), "workers {workers}");
        }
    }
}

#[test]
fn empty_message_batches_match_serial_verification_at_every_worker_count() {
    let public: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature: [u8; 64] = hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    let weak: [u8; 32] = hex(SMALL_ORDER_KEYS[4]);
    let good = SignatureRequest {
        public_key: &public,
        message: b"",
        signature: &signature,
    };
    let bad = SignatureRequest {
        public_key: &weak,
        message: b"",
        signature: &signature,
    };
    assert!(ed25519_verify(&public, b"", &signature));
    assert!(good.verify());
    assert!(!bad.verify());
    let accepted = vec![good; 9];
    for workers in WORKER_COUNTS {
        assert!(verify_all(&accepted, workers), "workers {workers}");
        assert_eq!(first_failure(&accepted, workers), None, "workers {workers}");
    }
    for position in 0..accepted.len() {
        let mut requests = accepted.clone();
        requests[position] = bad;
        for workers in WORKER_COUNTS {
            assert_eq!(
                first_failure(&requests, workers),
                Some(position),
                "position {position} workers {workers}"
            );
        }
    }
}
