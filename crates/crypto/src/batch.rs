// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded parallel strict Ed25519 verification.
//!
//! Every request is decided by the same [`ed25519_verify`] call used on the
//! serial path. Workers only split independent requests across threads, so the
//! accept/reject decision never depends on the worker count, the chunk layout
//! or the host's available parallelism.
//!
//! This is deliberately not Ed25519 batch verification in the cryptographic
//! sense. The randomized batch equation is cofactored and would accept
//! signatures that [`ed25519_verify`] rejects, so it cannot decide a
//! consensus-visible predicate that is specified as strict verification.

use crate::blake2s::ed25519_verify;

/// Maximum verification workers. Worker count never changes a decision.
pub const MAX_VERIFY_WORKERS: usize = 32;

/// Smallest request count that may use more than one worker.
///
/// Below this bound the thread handshake costs more than the verifications it
/// would overlap, so the serial path is taken regardless of the worker count.
pub const MIN_PARALLEL_REQUESTS: usize = 8;

/// One independent strict Ed25519 verification request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureRequest<'a> {
    /// Candidate 32-byte Ed25519 public key; weak and non-canonical keys fail.
    pub public_key: &'a [u8; 32],
    /// Exact signed message bytes.
    pub message: &'a [u8],
    /// Candidate 64-byte signature; malleable encodings fail.
    pub signature: &'a [u8; 64],
}

impl SignatureRequest<'_> {
    /// Decides this single request exactly as the serial path does.
    #[must_use]
    pub fn verify(&self) -> bool {
        ed25519_verify(self.public_key, self.message, self.signature)
    }
}

/// Returns true only when every request passes strict verification.
///
/// The result equals `requests.iter().all(SignatureRequest::verify)` for any
/// `workers` value, including zero and values above [`MAX_VERIFY_WORKERS`].
/// An empty request list is accepted; callers decide whether empty input is
/// meaningful. Verification is pure, so a failed thread spawn falls back to
/// verifying the remaining requests on the calling thread.
#[must_use]
pub fn verify_all(requests: &[SignatureRequest<'_>], workers: usize) -> bool {
    let workers = workers.min(MAX_VERIFY_WORKERS).min(requests.len());
    if workers < 2 || requests.len() < MIN_PARALLEL_REQUESTS {
        return requests.iter().all(SignatureRequest::verify);
    }
    // Chunk length is at least one because workers never exceeds the request count.
    let chunk = requests.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut pending: &[SignatureRequest<'_>] = &[];
        for (index, part) in requests.chunks(chunk).enumerate() {
            // Keep the first chunk on this thread instead of spawning for it.
            if index == 0 {
                pending = part;
                continue;
            }
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                part.iter().all(SignatureRequest::verify)
            }) {
                Ok(handle) => handles.push(handle),
                // Spawn failure is a host condition, never a verification outcome.
                Err(_) => return requests.iter().all(SignatureRequest::verify),
            }
        }
        let mut valid = pending.iter().all(SignatureRequest::verify);
        // Join every worker before returning so no verification outlives the scope.
        for handle in handles {
            // A panic in pure verification cannot be treated as success.
            valid &= handle.join().unwrap_or(false);
        }
        valid
    })
}

/// Returns a bounded nonzero worker count for `requests` on this host.
///
/// Worker count is a local scheduling choice and never enters a commitment.
#[must_use]
pub fn suggested_workers(requests: usize) -> usize {
    if requests < MIN_PARALLEL_REQUESTS {
        return 1;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_VERIFY_WORKERS)
        .min(requests)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake2s::{ed25519_public_key, ed25519_sign};

    struct Fixture {
        keys: Vec<[u8; 32]>,
        messages: Vec<[u8; 32]>,
        signatures: Vec<[u8; 64]>,
    }

    impl Fixture {
        fn new(count: usize) -> Self {
            let mut keys = Vec::with_capacity(count);
            let mut messages = Vec::with_capacity(count);
            let mut signatures = Vec::with_capacity(count);
            for index in 0..count {
                let secret = crate::blake2s::derive_key(&[index as u8; 32], "batch.test");
                let message = *crate::blake2s::blake2s(&index.to_le_bytes()).as_bytes();
                keys.push(ed25519_public_key(&secret));
                signatures.push(ed25519_sign(&secret, &message));
                messages.push(message);
            }
            Self {
                keys,
                messages,
                signatures,
            }
        }

        fn requests(&self) -> Vec<SignatureRequest<'_>> {
            (0..self.keys.len())
                .map(|index| SignatureRequest {
                    public_key: &self.keys[index],
                    message: &self.messages[index],
                    signature: &self.signatures[index],
                })
                .collect()
        }
    }

    const WORKER_COUNTS: [usize; 8] = [0, 1, 2, 3, 4, 8, 32, 64];

    #[test]
    fn valid_batch_accepted_at_every_worker_count() {
        let fixture = Fixture::new(64);
        let requests = fixture.requests();
        for workers in WORKER_COUNTS {
            assert!(verify_all(&requests, workers), "workers {workers}");
        }
    }

    #[test]
    fn every_corrupted_position_is_rejected_at_every_worker_count() {
        let fixture = Fixture::new(37);
        for position in 0..fixture.keys.len() {
            let mut requests = fixture.requests();
            let broken = [0xAA; 64];
            requests[position].signature = &broken;
            for workers in WORKER_COUNTS {
                assert!(
                    !verify_all(&requests, workers),
                    "position {position} workers {workers}"
                );
            }
        }
    }

    #[test]
    fn parallel_decision_matches_serial_on_mixed_batches() {
        let fixture = Fixture::new(41);
        let forged = [0x11; 64];
        let wrong_key = [0x22; 32];
        for mask in 0..64u32 {
            let mut requests = fixture.requests();
            for (index, request) in requests.iter_mut().enumerate() {
                match (mask >> (index % 6)) & 1 {
                    1 if index % 3 == 0 => request.signature = &forged,
                    1 if index % 3 == 1 => request.public_key = &wrong_key,
                    _ => {}
                }
            }
            let serial = requests.iter().all(SignatureRequest::verify);
            for workers in WORKER_COUNTS {
                assert_eq!(verify_all(&requests, workers), serial, "mask {mask}");
            }
        }
    }

    #[test]
    fn empty_batch_is_accepted() {
        for workers in WORKER_COUNTS {
            assert!(verify_all(&[], workers));
        }
    }

    #[test]
    fn single_request_matches_direct_verification() {
        let fixture = Fixture::new(1);
        let requests = fixture.requests();
        assert!(verify_all(&requests, 8));
        assert_eq!(verify_all(&requests, 8), requests[0].verify());
    }

    #[test]
    fn batch_rejects_weak_key_like_the_serial_path() {
        let fixture = Fixture::new(16);
        let mut requests = fixture.requests();
        // An all-zero encoding is a small-order point that strict verification rejects.
        let weak = [0u8; 32];
        requests[9].public_key = &weak;
        assert!(!requests[9].verify());
        for workers in WORKER_COUNTS {
            assert!(!verify_all(&requests, workers));
        }
    }

    #[test]
    fn suggested_workers_is_bounded_and_nonzero() {
        assert_eq!(suggested_workers(0), 1);
        assert_eq!(suggested_workers(MIN_PARALLEL_REQUESTS - 1), 1);
        for requests in [MIN_PARALLEL_REQUESTS, 64, 4096] {
            let workers = suggested_workers(requests);
            assert!(workers >= 1 && workers <= MAX_VERIFY_WORKERS && workers <= requests);
        }
    }

    #[test]
    fn chunk_boundaries_cover_every_request() {
        // A failure in the final short chunk must still be observed.
        let fixture = Fixture::new(33);
        let broken = [0x7F; 64];
        let mut requests = fixture.requests();
        requests[32].signature = &broken;
        for workers in [2, 3, 4, 8, 32] {
            assert!(!verify_all(&requests, workers), "workers {workers}");
        }
    }
}
