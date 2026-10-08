// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded parallel strict Ed25519 verification.
//!
//! Every request is decided by the same [`ed25519_verify`] call used on the
//! serial path. Workers only split independent requests across threads, so the
//! accept/reject decision never depends on the worker count, the chunk layout
//! or the host's available parallelism. [`first_failure`] additionally reports
//! *which* request failed, combining chunk results with a minimum rather than a
//! first-observed short circuit, so the reported index is also independent of
//! the worker count and of thread scheduling.
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
    first_failure(requests, workers).is_none()
}

/// Returns the lowest failing request index, or `None` when every request passes.
///
/// The result equals `requests.iter().position(|r| !r.verify())` for any
/// `workers` value, including zero and values above [`MAX_VERIFY_WORKERS`].
/// Chunk results are combined by taking the smaller index, never by returning
/// the first failure a thread happens to report, so the reported index is the
/// same for every worker count and every chunk layout. Call sites that must
/// report a positioned rejection use this instead of [`verify_all`].
///
/// An empty request list has no failing index. Verification is pure, so a
/// failed thread spawn falls back to the calling thread and is never itself a
/// verification outcome. A panicking worker is reported as a failure at its
/// chunk's first index, because a panic can never be evidence that its chunk
/// verified. Every spawned worker is joined before this function returns.
#[must_use]
pub fn first_failure(requests: &[SignatureRequest<'_>], workers: usize) -> Option<usize> {
    let workers = workers.min(MAX_VERIFY_WORKERS).min(requests.len());
    if workers < 2 || requests.len() < MIN_PARALLEL_REQUESTS {
        return chunk_failure(requests, 0);
    }
    // Chunk length is at least one because workers never exceeds the request count.
    let chunk = requests.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut pending: (usize, &[SignatureRequest<'_>]) = (0, &[]);
        for (index, part) in requests.chunks(chunk).enumerate() {
            let base = index * chunk;
            // Keep the first chunk on this thread instead of spawning for it.
            if index == 0 {
                pending = (base, part);
                continue;
            }
            match std::thread::Builder::new().spawn_scoped(scope, move || chunk_failure(part, base))
            {
                Ok(handle) => handles.push((base, handle)),
                // Spawn failure is a host condition, never a verification outcome.
                Err(_) => return chunk_failure(requests, 0),
            }
        }
        let mut failure = chunk_failure(pending.1, pending.0);
        // Join every worker before returning so no verification outlives the scope.
        for (base, handle) in handles {
            // A panic in pure verification cannot be treated as success.
            failure = lower(failure, handle.join().unwrap_or(Some(base)));
        }
        failure
    })
}

/// Lowest failing index inside one chunk, reported in whole-slice coordinates.
fn chunk_failure(requests: &[SignatureRequest<'_>], base: usize) -> Option<usize> {
    requests
        .iter()
        .position(|request| !request.verify())
        .map(|offset| base + offset)
}

/// Combines two chunk results by lowest index, making the join order irrelevant.
fn lower(left: Option<usize>, right: Option<usize>) -> Option<usize> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(index), None) | (None, Some(index)) => Some(index),
        (None, None) => None,
    }
}

/// One independent strict verification over an owned 32-byte digest.
///
/// [`SignatureRequest`] only borrows, so a caller that computes its signed
/// digests while hoisting cheap checks needs somewhere to keep them. This type
/// owns that material; the decision is the same strict predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DigestRequest {
    /// Candidate 32-byte Ed25519 public key; weak and non-canonical keys fail.
    pub public_key: [u8; 32],
    /// Exact 32-byte digest that was signed.
    pub digest: [u8; 32],
    /// Candidate 64-byte signature; malleable encodings fail.
    pub signature: [u8; 64],
}

impl DigestRequest {
    /// Decides this single request exactly as the serial path does.
    #[must_use]
    pub fn verify(&self) -> bool {
        ed25519_verify(&self.public_key, &self.digest, &self.signature)
    }
}

/// Returns the lowest failing index of an owned digest batch, or `None`.
///
/// Equivalent to borrowing each entry as a [`SignatureRequest`] and calling
/// [`first_failure`] with [`suggested_workers`]. The worker count is chosen
/// locally and never changes the result, so it is not a parameter here; the
/// result equals `requests.iter().position(|r| !r.verify())`.
#[must_use]
pub fn first_digest_failure(requests: &[DigestRequest]) -> Option<usize> {
    let borrowed: Vec<SignatureRequest<'_>> = requests
        .iter()
        .map(|request| SignatureRequest {
            public_key: &request.public_key,
            message: &request.digest,
            signature: &request.signature,
        })
        .collect();
    first_failure(&borrowed, suggested_workers(borrowed.len()))
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
                let seed = u8::try_from(index).expect("fixture count stays below 256");
                let secret = crate::blake2s::derive_key(&[seed; 32], "batch.test");
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

        fn digests(&self) -> Vec<DigestRequest> {
            (0..self.keys.len())
                .map(|index| DigestRequest {
                    public_key: self.keys[index],
                    digest: self.messages[index],
                    signature: self.signatures[index],
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
            assert!((1..=MAX_VERIFY_WORKERS).contains(&workers) && workers <= requests);
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

    #[test]
    fn first_failure_reports_the_lowest_index_at_every_worker_count() {
        let fixture = Fixture::new(17);
        let broken = [0xAA; 64];
        for position in 0..fixture.keys.len() {
            let mut requests = fixture.requests();
            requests[position].signature = &broken;
            for workers in WORKER_COUNTS {
                assert_eq!(
                    first_failure(&requests, workers),
                    Some(position),
                    "position {position} workers {workers}"
                );
            }
        }
    }

    #[test]
    fn first_failure_reports_the_lowest_of_several_failures_at_every_worker_count() {
        let fixture = Fixture::new(10);
        let forged = [0x11; 64];
        let wrong_key = [0x22; 32];
        // Every subset of the first six positions, so chunk boundaries at some
        // worker count separate a higher failure from the lowest one.
        for mask in 0..1u32 << 6 {
            let mut requests = fixture.requests();
            let mut expected = None;
            for (index, request) in requests.iter_mut().enumerate().take(6) {
                if (mask >> index) & 1 == 0 {
                    continue;
                }
                if index % 2 == 0 {
                    request.signature = &forged;
                } else {
                    request.public_key = &wrong_key;
                }
                expected = expected.or(Some(index));
            }
            let serial = requests.iter().position(|request| !request.verify());
            assert_eq!(serial, expected, "mask {mask}");
            for workers in WORKER_COUNTS {
                assert_eq!(
                    first_failure(&requests, workers),
                    expected,
                    "mask {mask} workers {workers}"
                );
            }
        }
    }

    #[test]
    fn first_failure_and_verify_all_agree_on_mixed_batches() {
        let fixture = Fixture::new(13);
        let forged = [0x11; 64];
        for mask in 0..16u32 {
            let mut requests = fixture.requests();
            for (index, request) in requests.iter_mut().enumerate() {
                if (mask >> (index % 4)) & 1 == 1 && index % 3 == 0 {
                    request.signature = &forged;
                }
            }
            for workers in WORKER_COUNTS {
                assert_eq!(
                    first_failure(&requests, workers).is_none(),
                    verify_all(&requests, workers),
                    "mask {mask} workers {workers}"
                );
            }
        }
    }

    #[test]
    fn first_failure_is_none_for_valid_and_empty_batches() {
        let fixture = Fixture::new(17);
        let requests = fixture.requests();
        for workers in WORKER_COUNTS {
            assert_eq!(first_failure(&requests, workers), None, "workers {workers}");
            assert_eq!(first_failure(&[], workers), None, "workers {workers}");
        }
    }

    #[test]
    fn first_digest_failure_matches_the_serial_digest_scan() {
        let fixture = Fixture::new(13);
        let digests = fixture.digests();
        assert_eq!(first_digest_failure(&digests), None);
        assert_eq!(first_digest_failure(&[]), None);
        for position in 0..digests.len() {
            let mut corrupted = digests.clone();
            corrupted[position].signature[0] ^= 1;
            let serial = corrupted.iter().position(|request| !request.verify());
            assert_eq!(serial, Some(position), "position {position}");
            assert_eq!(
                first_digest_failure(&corrupted),
                serial,
                "position {position}"
            );
        }
    }
}
