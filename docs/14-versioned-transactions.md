<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 14. Versioned Transactions

## Canonical version 1

`types::Transaction` now carries an explicit version, last authorized inclusion height (`expires_at`), execution lane, and exact per-resource prices. The following fields, in order, are signed and committed:

| Field | Encoding |
|---|---|
| Magic | Four ASCII bytes `ALTX` |
| Version | `u32` little-endian, exactly 1 |
| Chain ID | `u32` little-endian |
| Sender | 32 address bytes |
| Nonce | `u64` little-endian |
| Expiry | `u64` little-endian, inclusive block height |
| Lane | One byte: 0 payment, 1 contract, 2 system |
| Access list | Canonical compact count followed by length-prefixed state keys |
| Resource limits | Four `u64` values: compute, memory, IO, bandwidth |
| Resource prices | Four `u64` values in the same order |
| Payload | Canonical compact length and bytes |
| Signature | 64 Ed25519 signature bytes |

The minimum envelope is 191 bytes, 49 bytes longer than the unversioned baseline. Structural bounds and compact length rules remain unchanged. Full preflight validation precedes owned key/payload allocation. Bad magic, unsupported versions or lanes, overlong lengths, truncation, and trailing bytes fail decoding. Contract and system lane tags are structurally recognized but rejected by authenticated admission until their execution rules exist.

The signing digest remains `H("astrolune.tx.v1", unsigned_bytes)` and the ID remains `H("astrolune.tx.id.v1", signed_bytes)`, with the domain framing specified in [cryptographic foundations](09-cryptographic-foundations.md). All new fields, including the version prefix, are covered. Wallets must sign the new bytes; old signatures and transaction IDs cannot be reused.

## Policy and execution

A transaction can be included at height `H` only if `H <= expires_at`. The equality boundary is valid. `u64::MAX` imposes no earlier expiry; zero permits inclusion only at height zero. Genesis-backed chains begin at height one. Admission checks the next proposed block height, never wall-clock time.

Signed prices must exactly equal the finalized resource policy. This version has no bidding, tip, or price-cap semantics. Payments use `(1, 0, 0, 0)` and reserve amount plus the maximum authorized fee, while burning the actual one-unit fee. A future price change requires a separate activation policy; nodes cannot substitute local prices. Multiplication and addition remain checked for overflow.

`SignedValidator` checks shape/version, chain/expiry, account/nonce, prices/resources/balance, signature, then the payment lane and payload/key binding. `PaymentSession` applies these checks again against the sequential account overlay. An invalid received transaction rejects the block before any state is published. Proposal construction can skip invalid entries.

A successful durable commit removes pending entries whose expiry precedes the next inclusion height, including entries skipped by the block-size limit. Eviction releases both item and byte capacity. Failed storage writes preserve the queue and expiry state for retry. Pending transactions remain memory-only.

## Compatibility and verification

Whole-chain archives now use version 2 with the same outer field layout and checksum domain. Version-1 archives, including empty archives, fail recovery without being rewritten. No automatic migration is provided. Operators must retain old experimental archives separately and initialize a new data directory to use this format. Genesis/account/state-snapshot bytes remain unchanged.

Tests cover golden wire bytes and independent BLAKE2s vectors, every lane byte, unknown versions, byte mutations and truncations, signing-field mutation, inclusive expiry, policy mismatch, unsupported payloads, atomic block rejection, expiry eviction and failed-commit retry, live RPC rejection, restart, and storage publication/recovery. The transaction fuzz target retains its exact re-encoding invariant. Long fuzz campaigns and authenticated consensus remain open.
