<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 28. VRF verification and weighted selection

## Implemented profile

`crypto` implements ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03) from
[RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html#section-5.5), using pinned
`vrf-rfc9381 = 0.0.7` over the existing Dalek arithmetic. The provider uses the
same explicitly registered Ed25519 public keys and BLAKE2s validator identities
as signature verification. Unknown identities, weak/noncanonical keys, malformed
proofs and incorrect claimed outputs are rejected. This is an implemented and
tested provider, not a claim of an independent cryptographic audit.

The backend's scalar decoder reduces values modulo the group order. The wrapper
requires proof decode/re-encode equality, rejecting alternative `s + q` encodings
and noncanonical curve points before cryptographic verification. The proof must
be exactly 80 bytes. The 64-byte verified RFC output is converted to `Hash256`
with `domain_hash("astrolune.vrf.output.v1", beta)`; it is never trusted directly
from the sender or derived from an ordinary Ed25519 signature.

## Context and envelope

`VrfInput::seed()` hashes these fixed-width fields, in order:

| Field | Encoding |
| --- | --- |
| chain ID | u32 little endian |
| genesis commitment | 32 bytes |
| epoch | u64 little endian |
| target height | u64 little endian |
| finalized parent randomness | 32 bytes |
| round | u32 little endian |

Committee and producer evaluations use `astrolune.vrf.committee.v1` and
`astrolune.vrf.producer.v1`, respectively. The resulting digest is the RFC alpha
input. Committee rounds must be zero in the sampler and CLI. Callers obtain
the context from trusted finalized state, not from a proof's claims.

The fixed 120-byte output envelope is `ALVR || u32_le(1) || randomness[32] ||
proof[80]`. Wrong versions, truncations and trailing bytes are rejected.
Structural decoding does not establish authenticity; verification is required.

## Weighted draws and rotation

`VerifiedVrfSampler` requires a complete bounded roster of eligible keys and
positive finalized weights, plus exactly one valid proof per roster member.
Candidate weights must match the trusted roster. Duplicates, unknown identities,
missing contributions and aggregate u128 overflow are errors. Banned and
unadmitted validators are excluded when the caller constructs the trusted roster.

The batch commits the context digest and the ordered `(identity, weight,
randomness)` tuples, sorted by identity. A separate hash domain derives a
128-bit ticket for each seat. Rejection sampling discards values below
`2^128 mod total_weight` before reduction modulo the remaining total. This
avoids modulo bias. The rejection loop is capped at 256 attempts and fails
without choosing a fallback winner. Cumulative weight intervals select a
member with probability `weight / remaining_weight`, then remove that member.
No floating point or arrival order affects the result.

`rotate` retains the newest `size - replacement_count` seats, updates their
weights from the trusted roster, and samples the other seats without duplicating
retained members. Outgoing members may be selected again. Zero replacements
preserve seat identities; excessive counts, invalid retained membership and
nonconsecutive heights fail. `producer` requires a separate producer-role batch
whose membership and weights exactly equal the active committee. The new
`producer_for_subset` API instead retains full-roster entropy while drawing only
among an authenticated selected subset.

The old unverified sorter is now explicitly called `DemonstrationSampler`.
Its replacement-count bug is corrected; it remains a fixture helper.

## Operator commands

```text
cli vrf-prove genesis.bin validator.seed 1 5 <parent-randomness-hex> committee 0 proof.bin
cli vrf-verify genesis.bin <public-key-hex> 1 5 <parent-randomness-hex> committee 0 proof.bin
```

The CLI verifies genesis membership, reads exactly 32 secret bytes from a file,
never prints secrets, and creates proof files exclusively without overwriting.
Changing the context, key, proof or claimed randomness causes verification to fail.
This CLI uses the genesis roster; it does not infer later membership changes.

## Activation boundary

The certified daemon retains fixed membership for version-1 genesis. Explicit
[version-2 activation](40-live-vrf-network.md) enables contribution gossip,
complete-roster availability, standby participation, historical handoff RPC and
client catch-up. The [handoff and rotating execution APIs](38-authenticated-committee-handoff.md)
implement parent randomness, old-quorum trust transfer, reserved system execution
and authenticated history replay. Existing network identities are never migrated
implicitly; activation requires a new trusted genesis and signing namespace.

The complete roster must be fixed before proof revelation. Missing proofs halt
this sampler; dropping missing validators or changing the seed would create a
different lottery and is not an automatic fallback. Withholding resistance,
grinding analysis and rotating-committee liveness are separate unresolved tasks.

Tests cover RFC examples 16–18, every proof-byte mutation, output mutation,
wrong contexts/keys, scalar malleability, envelope bounds, trusted weights,
canonical batch ordering, rotation, producer membership and finality-context
construction. Integer draw tests exercise full-width totals and weighted intervals.
