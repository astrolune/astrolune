<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# Pinned history retention

Physical retention uses an explicit operator-pinned checkpoint. The chosen rule
allows bounded storage without keeping an ever-growing committee proof chain.
The checkpoint hash must be retained independently of the history directory.
Recovery never derives its own trust pin from the file it is checking.

`export-retained` authenticates source history, selects a recent checkpoint,
and writes a NEW append log containing that snapshot and 0–64 later blocks.
Every exported block is re-executed and finalized effects are regenerated. The
exported head must equal the authenticated source head. An existing destination
is refused; a failed export is not automatically reused. The source is unchanged.

```text
cli export-retained <genesis-or-profile> <validators> <directory> <minimum-height> <retain-blocks> <new-directory> [checkpoint-file checkpoint-id]
cli verify-retained <genesis-or-profile> <validators> <directory> <minimum-height> <checkpoint-file> <checkpoint-id>
daemon --observer --genesis <profile> --validators <keys> --data-dir <new-directory> --checkpoint <checkpoint-file> --checkpoint-id <trusted-hash> --tls-dir <tls> --run
```

The CLI prints `checkpoint_id` and writes `checkpoint.bin`, profile/public-key
files, an observer marker and recovery instructions. No signing journals, wallet
keys, transport identities or pending transactions are exported. Supply both
checkpoint options together. A pin for a different descriptor, network, height,
state root or history frontier fails closed. A normal genesis-only launch refuses
shortened history. Copying a pin alongside a snapshot is not independent trust;
retain the printed hash in separately controlled configuration before switching.

The selected checkpoint must be above height zero and within the bounded recent
state index. Large state changes may evict it before the 64-transition limit;
request a smaller retained suffix in that case. Both legacy archives and append
logs can be exported. A previously shortened log can be exported again by passing
its existing descriptor and independently held pin.

## Recovery and bounds

`ALANCH01` commits the network namespace, height, block hash, state root and,
for genesis-v2 rotation, the bounded committee history frontier. Its ID uses
`astrolune.recovery.checkpoint.v1`. PoTB carries its history, policy, weights and
pending governance in the state snapshot itself. State membership authenticates
the next committee against the pinned root. Subsequent blocks require exact
ancestry, current quorum, execution roots and current resource parameters.

The snapshot has the state engine's 64 MiB bound. Each retained log record has
the existing 72 MiB bound, with at most 64 exported bodies. The descriptor has a
fixed maximum independent of chain age. A running node continues appending new
blocks: retention is an explicit offline operation, not an automatic background
deletion policy. The old directory remains available for rollback inspection or
archival operation; retire it only after validating and switching to the export.

Validator recovery uses the same pinned execution verification. Production
signing journals must retain their protected watermark and exclusive ownership;
the observer export deliberately does not copy or reset them. Pending offence
proofs predating the retained boundary cannot be reauthenticated locally and are
rejected rather than trusted implicitly. PoTB bans already committed in the
snapshot survive retention.

Older bodies, receipts and handoffs are unavailable. The checkpoint snapshot is
available to local recovery but does not pretend to have an ordinary retained
block certificate over RPC. Exact-height certified queries return unavailable
at that boundary; subsequent retained heights work normally. Clients starting
only from genesis need an archival proof source. Library consumers may explicitly
bootstrap committee verifiers from an independently trusted checkpoint and
membership witness. The existing CLI proof commands continue requiring a full
handoff chain from genesis.

Tests cover fixed genesis, rotating genesis, PoTB and governed PoTB; pending
governance across the retained boundary; repeated compaction exports; wrong pins,
descriptor alteration, wrong start anchors, refusal of genesis-only recovery;
observer catch-up and restart; validator binding; both source storage formats;
non-overwrite CLI behavior and real daemon startup.
