<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 9. Cryptographic Foundations

## Implemented suite

The `crypto` crate uses unkeyed BLAKE2s-256 from [`blake2` 0.11.0](https://docs.rs/blake2/0.11.0/blake2/) and Ed25519 from [`ed25519-dalek` 3.0.0](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/). Direct backend versions are pinned and transitive versions are recorded in `Cargo.lock`. `zeroize` protects temporary derived seeds; keystore entries hold dalek signing keys and do not expose secret material through `Debug`.

Verification rejects non-canonical public-key encodings and uses `verify_strict`, including weak-key and signature-malleability checks. `Blake2sProvider` verifies signatures only for registered public keys. Registration derives the validator ID as raw BLAKE2s-256 of the public key. Unknown identities fail verification. Registered keys also verify strict RFC 9381 ECVRF proofs; generation, canonical encodings, RFC vectors and weighted sampling are specified in [document 28](28-vrf-and-weighted-selection.md).

These implementations replace the former custom hash and forgeable signature placeholders. Standard backend selection is not an independent audit of the protocol or its integration.

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

`BasicValidator`, genesis-free producers, and `SimpleExecutor` remain demonstration components. Genesis-backed producers and the daemon now use `SignedValidator` over committed accounts and sequential execution overlays for [native payments](13-native-payments.md), including execution revalidation and durable balance/nonce updates. Authenticated consensus finality remains unfinished. The workspace integration test exercises signed decoding, validation, mempool selection, and planning explicitly.

## Compatibility

The original cryptographic backend change preserved transaction bytes but changed cryptographic outputs: raw and domain hashes, derived keys, validator IDs, transaction IDs, signatures, and roots using those functions. Old experimental signatures and commitments are incompatible. Existing data cannot be silently treated as data from the new suite; no database migration or network upgrade is implied. The subsequent version-1 transaction envelope changes canonical transaction bytes and commitments again, and requires archive version 2.

The original in-memory signing-position guard does not survive restarts. The separate [durable signer](16-durable-signing.md) now journals decisions before issuing signatures and restores its watermark on restart. [Finality certificate verification](15-authenticated-finality.md) is also implemented. Authenticated TLS networking, local BFT voting, durable daemon signing and VRF verification are implemented. Encrypted key custody, rollback-resistant journal anchoring, live VRF rotation and independent review remain open.

## Verification

Tests include the Ed25519 empty-message vector from [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), BLAKE2s vectors and block boundaries checked against Python's `hashlib`, signature corruption, weak keys, unregistered identities, field mutation, resource overflow, exact encoded sizes, and consistent IDs across component boundaries. [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) describes BLAKE2.
