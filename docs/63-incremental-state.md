<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 63. Persistent version-1 state and incremental commitments

This implements the state-backend portion of P1 from the
[architecture research](61-network-architecture-research.md). Existing-key updates
share unchanged state and Merkle subtrees instead of cloning the entire map and
rehashing every entry. Membership and absence proofs use retained hashes.

This is an adoption of established persistent-tree techniques. It is not VeyraFold,
LuneSeal, a new consensus protocol, or a claim of original invention. E2E benchmark
infrastructure, more precise execution access modes, and the research proposals
remain separate work.

## Compatibility

The public `InMemoryState`/`StateDatabase` interfaces, version-1 root domains, sorted
leaf order, odd-node promotion, count wrapper, proof bytes, snapshot bytes, and
state bounds are unchanged. No network activation or data migration is required.
All cryptographic verification and durable-publication boundaries remain in place.

`tree.rs` stores immutable leaves and branches behind `Arc`. Each node retains its
subtree hash, entry count, encoded entry bytes, and a shared reference to its last
key. A snapshot clones the root handle. Lookup descends by key; proofs descend by
leaf index and return the existing sibling hashes in leaf-to-root order. Promoted
odd nodes do not acquire synthetic hashes or proof siblings.

## Preparing a transition

1. Reject a stale parent before examining changes.
2. Traverse changes in transaction and operation order. Check key/value bounds and
   the encoded snapshot size after **every** operation, using the pending value
   for repeated writes. A transient overflow still rejects the batch even if a
   later write would shrink it.
3. When every write addresses an existing key and no existing key is deleted,
   collect final values by key. Rebuild only the union of changed paths; unchanged
   values and branches retain their original handles. Shared ancestors are hashed
   once per batch, not once per transaction. Cached subtree sizes avoid a full
   encoded-size scan.
4. An insertion or deletion of an existing key requests the reference path. It
   materializes the old map, applies the complete original batch with ordered
   bounds checks, and builds a new tree. Earlier speculative bookkeeping is never
   published. Deleting an absent key remains a no-op, subject to key bounds.
5. Wrap the final subtree hash with the unchanged leaf count. `commit_verified`
   publishes only after matching the expected root; storage still controls durable
   publication. Errors leave the original tree and all retained snapshots intact.

The fallback is necessary because insertion/deletion can shift subsequent leaf
indices in the existing v1 format. It is deliberately not advertised as an
incremental topology update.

## Costs and tradeoffs

For `N` leaves and `k` distinct changed keys, update-only preparation visits the
union of affected paths, bounded by `O(k log N)` tree work plus ordered processing
of the input operations. Proof generation visits `O(log N)` nodes, plus copying
the returned values for absence witnesses. A no-change transition shares the tree.

Topology changes, snapshot export, and snapshot import remain whole-state work.
Import validates complete framing before allocating entries, builds the tree, and
checks its root without a second hashing pass. The reference flat-map hash/proof
algorithms remain test oracles.

The cached tree retains more metadata and allocations than a flat map. Point
lookup locality may be worse, and immutable historical snapshots retain changed
paths and values until their owners release them. The 64 MiB snapshot limit bounds
canonical payload bytes, not resident memory. No claim of lower peak RSS or a
production disk database follows from this change.

## Verification

Differential tests compare the persistent implementation with the original flat
algorithms across odd/even tree shapes, repeated writes, insertions/deletions,
membership and absence proofs, and canonical snapshot bytes. A structural-sharing
test checks that an unaffected branch and old snapshots survive an update.
A boundary test fills an exact 64 MiB snapshot and checks both transient overflow
rejection and a valid shrink-then-grow sequence.

Existing golden roots, malformed snapshot/proof cases, atomic commit failures,
file recovery, execution, node, and frozen protocol fixtures are also exercised.
The measurement record below distinguishes completed local checks from external
cross-platform qualification.

## Measurement scope

The state benchmark now labels a no-change transition
`commit/prepare/<count>/unchanged`. Its former `state_root/recompute` label would
incorrectly describe shared-tree reuse as a full rehash. The flat-map copy row
remains a historical baseline, not a separable component of the new backend.
Additional fixtures cover scattered updates, insertion into a gap, and deleting
the first key.

Measurements compare complete operations, including allocation and destruction.
State microbenchmark speedups must not be reported as network TPS or finality
improvements. The execution suite includes signed transactions and in-memory
state preparation, but excludes network agreement and durable disk publication.
