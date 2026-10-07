<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 6. Ecosystem Services

AstroLune DNS is a separate Rust service. It reuses finalized chain data and wallet authorization while remaining outside the consensus hot path. It can be disabled without preventing block validation.

## 6.1 AstroLune DNS

AstroLune DNS maps normalized in-network names to wallet/contract addresses or application service records. Ownership and updates are authorized on-chain. Resolvers verify finalized registry state and proofs.

Names require a canonical Unicode and normalization policy, reserved-name policy, lease/renewal rules, maximum depth and length, and protection against confusable display. Resolvers do not silently fall back to public DNS for an AstroLune name.

## 6.2 Isolation

DNS uses dedicated keys and listeners. A compromised resolver must not expose validator signing keys or gain trusted access to consensus internals. Requests are rate-limited, authenticated where appropriate, and parsed as untrusted input.
