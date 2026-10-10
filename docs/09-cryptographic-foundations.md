<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 9. Cryptographic Foundations

## Implemented suite

The `crypto` crate uses unkeyed BLAKE2s-256 from [`blake2` 0.11.0](https://docs.rs/blake2/0.11.0/blake2/) and Ed25519 from [`ed25519-dalek` 3.0.0](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/). Direct backend versions are pinned and transitive versions are recorded in `Cargo.lock`. `zeroize` protects temporary derived seeds; keystore entries hold dalek signing keys and do not expose secret material through `Debug`.

Verification rejects non-canonical public-key encodings and uses `verify_strict`, including weak-key and signature-malleability checks. `Blake2sProvider` verifies signatures only for registered public keys. Registration derives the validator ID as raw BLAKE2s-256 of the public key. Unknown identities fail verification. Registered keys also verify strict RFC 9381 ECVRF proofs; generation, canonical encodings, RFC vectors and weighted sampling are specified in [document 28](28-vrf-and-weighted-selection.md).

These implementations replaced the earlier custom hash and forgeable signature placeholders. Choosing standard, pinned backends does not by itself establish that the protocol's use of them is correct; that integration has not been independently reviewed.

## Domain framing

For domain bytes `D` and message bytes `M`, the protocol helper computes:

```text
H(D, M) = BLAKE2s-256("astrolune.v1." || u64_le(len(D)) || D || M)
```

The domain length precedes the domain, so domain and message boundaries are unambiguous. Integer framing is independent of host pointer width.

Wallet addresses are `H("astrolune.account.ed25519.v1", public_key)`. Validator identities and wallet addresses have separate derivations and must not be interchanged.

## Transaction commitments

`codec::protocol::encode_unsigned_transaction` encodes all current transaction fields in canonical wire order except the signature. The signed message is the 32-byte digest `H("astrolune.tx.v1", unsigned_bytes)`. This uses ordinary Ed25519 over that digest, not the distinct Ed25519ph construction.

The transaction ID is `H("astrolune.tx.id.v1", signed_canonical_bytes)`. It includes the signature, version, expiry, lane, access list, resource limits, prices, and payload. Envelope IDs, admission IDs, execution receipt transaction IDs, and node transaction leaves use this same function.

The node constructs transaction roots with the shared binary Merkle builder. Receipt leaves and `ExecutionReceipt::commitment()` both use `H("astrolune.receipt.v1", canonical_receipt_bytes)`. `BlockHeader::compute_hash()` uses `H("astrolune.block.v1", canonical_header_bytes)`. Canonical headers are exactly 200 bytes and receipts are 97 bytes, without padding. The domain helper lives in `types::hash` and is re-exported by `crypto::blake2s`, avoiding a cyclic dependency. State commitments are specified in [state and recovery](10-state-and-recovery.md).

## Signed admission

`SignedValidator` receives an account snapshot containing public keys, expected nonces, and balances, plus explicit resource limits and unit prices. It applies checks in this order:

1. Codec bounds and exact canonical size, before hashing or allocating encoded bytes.
2. Chain identity and inclusive expiry at the proposed inclusion height.
3. Sender existence, address/public-key binding, and exact nonce; exhausted nonces are rejected.
4. Exact equality of signed and finalized resource prices, per-resource limits, and available balance; every multiplication and addition is checked.
5. Strict Ed25519 verification of the signing digest.
6. Explicit payment lane, valid version-1 payment payload, and matching sender public key. Reserved contract/system lanes fail closed.

Validation does not mutate accounts or reserve balances. Callers must maintain a consistent overlay when admitting or executing multiple transactions from one sender. Fees and account state transitions are not implemented by this validator. Version, expiry, lane, and resource prices are signed fields in the [version-1 transaction envelope](14-versioned-transactions.md).

`BasicValidator`, genesis-free producers, and `SimpleExecutor` remain demonstration components. Genesis-backed producers and the daemon use `SignedValidator` over committed accounts and sequential execution overlays for [native payments](13-native-payments.md), including execution revalidation and durable balance/nonce updates. [Authenticated finality](15-authenticated-finality.md) verifies the votes and certificates that accompany those commits in the certified network profiles. The workspace integration test exercises signed decoding, validation, mempool selection, and planning explicitly.

## Bounded parallel verification

`crypto::batch` verifies independent signature requests on more than one thread. A `SignatureRequest` borrows a candidate public key, the exact signed message, and a candidate signature; a `DigestRequest` owns the same material for callers that compute 32-byte digests while hoisting their cheap checks. Both decide through the same `ed25519_verify` call the serial path uses, so every request is decided by the strict predicate: non-canonical public-key encodings are rejected, and `verify_strict` rejects weak keys and malleable scalars. `verify_all` returns whether every request passes and `first_failure` returns the lowest failing index. `MAX_VERIFY_WORKERS` caps the worker count at 32, `MIN_PARALLEL_REQUESTS` keeps request sets below eight on the calling thread, and `suggested_workers` derives a bounded nonzero count from `std::thread::available_parallelism`.

Worker count is a local scheduling choice that never reaches a commitment. For request list `R` and any worker count `w`:

```text
verify_all(R, w)     = all i. verify(R[i])
first_failure(R, w)  = min { i : not verify(R[i]) }
```

Both identities hold for `w = 0` and for `w` above `MAX_VERIFY_WORKERS`. Chunk results are combined by taking the smaller index rather than by returning whichever thread reported first, so the reported index does not depend on the chunk layout or on thread scheduling. An empty request list is accepted and has no failing index. A failed thread spawn falls back to the calling thread and is never itself a verification outcome, a panicking worker is reported as a failure at its chunk's first index because a panic cannot be evidence that its chunk verified, and every spawned worker is joined before the call returns.

`AuthenticatedCommittee::verify_certificate`, `PrevoteCertificate::from_votes`, `AdmissionCertificate::verify`, and `GovernanceCertificate::verify` each hoist their non-cryptographic checks for the whole certificate, in the serial order those checks already had, and stop at the first one that rejects. Only entries below that position were reachable serially, so exactly those signatures go into one batch and a failure there is the lowest failing position overall. This keeps the reported `ConsensusError` variant unchanged: a membership or framing rejection below a forged signature still reports `UnknownVoter` or `InvalidCertificate`, and a forged signature below a membership rejection still reports `InvalidProof`. Hoisting also replaces the per-approval linear roster scan in `AdmissionApproval` and `GovernanceApproval` with one `BTreeMap` index per certificate, and resolves the incumbent context once instead of per approval. Reaching quorum never ends a loop; the batch always covers every signature the serial path would have verified, as required for [quorum admission](43-quorum-admission.md) and [parameter governance](48-parameter-governance.md). Finality quorum rules are specified in [document 15](15-authenticated-finality.md) and prevote proofs in [document 17](17-local-bft-voting.md).

Per-transaction signatures do not use this path. `transaction::SignedValidator` is already invoked one transaction per worker inside the execution worker pool described in [document 29](29-parallel-payments-and-wasm.md), so nesting a second thread scope there would oversubscribe threads without adding parallelism. `DoubleVoteEvidence` carries exactly two signatures and stays serial.

This is bounded parallel strict verification, not Ed25519 batch verification in the cryptographic sense. The randomized batch equation of `ed25519-dalek` is cofactored, accepts signatures that `ed25519_verify` rejects, and therefore cannot decide a consensus-visible predicate specified as strict verification; its `batch` feature is not enabled, and enabling it would also remove that crate's own `forbid(unsafe_code)`. Nothing here reduces the number of scalar multiplications per signature, so throughput improves only by the available worker count and never by a cheaper equation. Worker count never changes a decision or a reported index, and independent cryptographic review of this path remains open.

## Compatibility

The original cryptographic backend change preserved transaction bytes but changed cryptographic outputs: raw and domain hashes, derived keys, validator IDs, transaction IDs, signatures, and roots using those functions. Signatures and commitments produced by the earlier placeholders are incompatible. Existing data cannot be silently treated as data from the new suite; no database migration or network upgrade is implied. The subsequent version-1 transaction envelope changes canonical transaction bytes and commitments again, and requires archive version 2.

The original in-memory signing-position guard does not survive restarts. The separate [durable signer](16-durable-signing.md) now journals decisions before issuing signatures and restores its watermark on restart. [Finality certificate verification](15-authenticated-finality.md) is also implemented. Authenticated TLS networking, local BFT voting, durable daemon signing and VRF verification are implemented. Encrypted key custody, rollback-resistant journal anchoring, live VRF rotation and independent review remain open.

## Verification

Tests include the Ed25519 empty-message vector from [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), BLAKE2s vectors and block boundaries checked against Python's `hashlib`, signature corruption, weak keys, unregistered identities, field mutation, resource overflow, exact encoded sizes, and consistent IDs across component boundaries. [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) describes BLAKE2.

Batch equivalence is tested by exhaustive loops rather than by a property-testing framework, because the workspace has none. `crates/crypto/src/batch.rs` sweeps every single-failure position and every multi-failure bitmask over a prefix, at worker counts including zero and a count above `MAX_VERIFY_WORKERS`, asserting that `first_failure` returns the same lowest index each time and that `verify_all` agrees with it. `crates/crypto/tests/batch_equivalence.rs` adds the inputs on which a cofactored equation would disagree: all eight points whose order divides eight, key encodings whose `y` coordinate is `p`, `p + 1`, or `2^255 - 1`, a signature scalar shifted by the group order, all-zero and all-one signature bytes, and empty messages. `crates/consensus/tests/batch_equivalence.rs` asserts that the refactored certificate, prevote, admission, and governance paths accept and reject exactly as before, that the specific `ConsensusError` variant depends on which check the serial order reached first, and that an invalid signature beyond the quorum threshold is still rejected. These loops bound the input space they cover and are not a proof of equivalence over all inputs, and they do not measure throughput. Worker-count cost is measured separately by `crates/crypto/benches/crypto.rs`; at 512 requests the measured speedup from one worker to eight is 5.7x on one eight-core host, and sixteen workers are slower than eight at 64 requests. Those figures describe one machine and establish no bound; [measurement method and limits](56-performance-measurement.md).
