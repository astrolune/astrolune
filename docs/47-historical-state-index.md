<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Historical state indexing

The append log maintains a derived reverse-delta index for exact historical state
queries. It retains at most 64 transitions, 32 MiB of accounted entries and 65,536
distinct changed keys. A transition exceeding a bound advances the availability
floor; it never invalidates an otherwise valid block. The current state remains
available. Old block bodies remain on disk: index eviction is not physical pruning.

Each entry remembers the original value of each changed key, including absence.
Repeated writes and deletion of the same key in one block keep only its original
value. Reconstruction coalesces reverse changes, deletes affected keys before
restoring originals, and checks the resulting Merkle root against the requested
checkpoint. This avoids a transient union exceeding the snapshot limit. The index
is published only after durable commit and rebuilt during authenticated structural
log replay. A storage instance with uncertain durability refuses reads.

`state_proof_at` accepts `key` and an exact `height`, including zero. A null result
means unavailable history; an encoded absence proof means the key was absent in
that authenticated state. The existing `state_proof` method retains latest-state
semantics. The typed client rejects a proof returned for a different height.

```text
cli state-proof-at <genesis-or-profile> <validators> <key-hex> <exact-height> <output> [rpc-address]
cli verify-state-proof <genesis-or-profile> <validators> <key-hex> <minimum-height> <output>
```

Rotating and PoTB queries use the same independently authenticated handoff
sidecars as latest-state queries. RPC delivery itself is not a trust anchor.
Legacy archive queries use their retained snapshots. No background retention job
or deletion of existing chain files is enabled by this feature.

Tests cover repeated writes, deletions, absent keys, count/byte/key eviction,
reopening, failed publication, unknown heights, and RPC/CLI verification after
validator and observer restart. See [storage](22-append-only-chain-storage.md)
and [certified proofs](32-certified-state-proofs.md).
