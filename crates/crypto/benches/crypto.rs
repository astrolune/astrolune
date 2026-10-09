// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures the hash, signature and bounded parallel verification primitives.
//!
//! These figures describe one machine and one toolchain. They are not a
//! correctness gate: `batch::first_failure` is required to return the same
//! index at every worker count, and that equivalence is established by the
//! tests in `crates/crypto`, not here. A worker count that measures faster
//! does not make it more correct, and a slower one does not make it wrong.
//!
//! What this does NOT establish: end-to-end block or quorum throughput, any
//! bound under contention from other processes, or a figure comparable to a
//! different machine.

use crypto::{
    batch::{self, SignatureRequest},
    blake2s::{blake2s, ed25519_public_key, ed25519_sign, ed25519_verify},
    vrf::{VrfInput, VrfRole, prove_vrf, verify_ecvrf, verify_vrf},
};
use testkit::bench::Suite;

/// Request counts for the bounded parallel verification sweep.
///
/// `MIN_PARALLEL_REQUESTS` is the documented threshold below which the serial
/// path is taken regardless of the worker count, so the sweep brackets it.
const REQUEST_COUNTS: [usize; 3] = [batch::MIN_PARALLEL_REQUESTS, 64, 512];

/// Worker counts measured at each request count.
const WORKER_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];

/// Deterministic signing material for one benchmark request.
struct Signed {
    public_key: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
}

/// Builds `count` independent valid signatures from a deterministic seed.
///
/// Distinct keys and messages are used so verification cannot be shortened by
/// reusing a decompressed key across requests.
fn signed_requests(count: usize) -> Vec<Signed> {
    (0..count)
        .map(|index| {
            let mut seed = [0u8; 32];
            // Spread the index across two bytes so counts above 256 stay distinct.
            seed[0] = u8::try_from(index % 256).unwrap_or_default();
            seed[1] = u8::try_from(index / 256).unwrap_or_default();
            seed[31] = 1; // keep every seed non-zero
            let public_key = ed25519_public_key(&seed);
            let message = format!("astrolune benchmark request {index}").into_bytes();
            let signature = ed25519_sign(&seed, &message);
            Signed {
                public_key,
                message,
                signature,
            }
        })
        .collect()
}

/// Borrows owned signing material as verification requests.
fn borrow(signed: &[Signed]) -> Vec<SignatureRequest<'_>> {
    signed
        .iter()
        .map(|entry| SignatureRequest {
            public_key: &entry.public_key,
            message: &entry.message,
            signature: &entry.signature,
        })
        .collect()
}

/// Builds a finalized VRF context for the committee role.
///
/// Every field is fixed, so the seed and therefore the proof are deterministic
/// across runs and machines.
fn vrf_input() -> VrfInput {
    VrfInput {
        chain_id: 7,
        genesis: testkit::hash(3),
        epoch: 11,
        height: 42,
        parent_randomness: testkit::hash(5),
        round: 0,
        role: VrfRole::Committee,
    }
}

/// Measures the VRF prove, verify and envelope paths.
///
/// `prove_vrf` verifies its own proof before returning, so its figure includes
/// one verification and is not a lower bound on proving alone.
fn bench_vrf(suite: &mut Suite) {
    let mut secret = [0u8; 32];
    secret[0] = 9;
    let input = vrf_input();
    let seed = input.seed();
    let public_key = ed25519_public_key(&secret);
    let output = prove_vrf(&secret, input).expect("fixed secret and input prove");
    let envelope = output.encode().expect("a proven output encodes");

    suite.bench("vrf/seed", || input.seed());
    suite.bench("vrf/prove", || prove_vrf(&secret, input));
    suite.bench("vrf/verify", || verify_vrf(&public_key, seed, &output));
    suite.bench("vrf/verify_ecvrf_raw", || {
        verify_ecvrf(&public_key, &seed.0, &output.proof)
    });
    suite.bench("vrf/encode_envelope", || output.encode());
    suite.bench("vrf/decode_envelope", || {
        crypto::VrfOutput::decode(&envelope)
    });
    // A rejected proof is the path a node takes on hostile input, so its cost
    // is measured next to the accepting one rather than assumed equal.
    let mut tampered = output.clone();
    tampered.proof[0] ^= 1;
    suite.bench("vrf/verify_rejects_tampered_proof", || {
        verify_vrf(&public_key, seed, &tampered)
    });
}

fn main() {
    let mut suite = Suite::new("crypto");

    for size in [32_usize, 256, 1_024, 16_384] {
        let data = vec![0xa5; size];
        suite.bench(format!("blake2s_256/{size}B"), || blake2s(&data));
    }

    let mut seed = [0u8; 32];
    seed[0] = 7;
    let public_key = ed25519_public_key(&seed);
    let message = b"astrolune single signature benchmark message".to_vec();
    let signature = ed25519_sign(&seed, &message);
    suite.bench("ed25519/public_key_from_secret", || {
        ed25519_public_key(&seed)
    });
    suite.bench("ed25519/sign", || ed25519_sign(&seed, &message));
    suite.bench("ed25519/verify_strict", || {
        ed25519_verify(&public_key, &message, &signature)
    });

    for count in REQUEST_COUNTS {
        let signed = signed_requests(count);
        let requests = borrow(&signed);
        // The serial reference the parallel path must agree with.
        suite.bench(format!("batch/serial_position/{count}"), || {
            requests.iter().position(|request| !request.verify())
        });
        for workers in WORKER_COUNTS {
            suite.bench(format!("batch/first_failure/{count}/w{workers}"), || {
                batch::first_failure(&requests, workers)
            });
        }
    }

    bench_vrf(&mut suite);

    suite.report();
}
