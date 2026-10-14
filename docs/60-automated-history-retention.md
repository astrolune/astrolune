<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 60. Automated history retention

An opt-in local policy lets a running validator or observer compact its own
append-only log in place, keeping a committed anchor and a bounded suffix of
finalized bodies and physically reclaiming the older bytes. The policy is
evaluated after each published commit. The default is disabled, so a node that
configures nothing keeps every finalized block exactly as before.

This document specifies local disk occupancy and the recovery rule that makes a
self-compacted directory restartable. It does not establish any new trust: a
retention policy authenticates no finality, creates no exportable checkpoint
descriptor, grants no authority to accept history shortened by another party, and
replaces neither the independently pinned retention of
[document 49](49-pinned-history-retention.md) nor rollback-resistant key custody.

## Policy and configuration

`config::HistoryRetentionConfig` holds the first retention fields in the
configuration crate: `enabled`, `retained_blocks`, `interval_blocks` and
`max_compaction_bytes`. `Default` leaves `enabled` false while carrying valid
numbers, and `HistoryRetentionConfig::validate` checks every bound whether or not
retention is enabled, so a disabled policy with impossible numbers is reported
rather than ignored. `NodeConfig::validate` calls it with the default policy;
`NodeConfig::validate_with_retention` accepts an explicit one. An out-of-range
value returns `ConfigError::InvalidRetentionPolicy`.

```text
retained_blocks       minimum 8      default 32          maximum 64
interval_blocks       minimum 1      default 16          maximum 65,536
max_compaction_bytes  minimum 16 MiB default 512 MiB     maximum 8 GiB
```

`storage::RetentionPolicy` is the engine-side form of the same three numbers,
constructed by `RetentionPolicy::bounded` and defaulting to
`RetentionPolicy::disabled`. The two crates state the same constants because the
configuration crate deliberately depends on no other crate; a test in
`apps/cli/src/recovery.rs` asserts that every pair agrees. `retained_blocks` is
capped at `MAX_STATE_HISTORY_BLOCKS` because the anchor state is rebuilt through
the bounded reverse state index of
[document 47](47-historical-state-index.md).

`RetentionPolicy::target_floor(floor, head)` selects the next anchor height.
Nothing happens unless the excess above the retained suffix has reached
`interval_blocks`, and a selected floor is always strictly above the current
floor, strictly below the head, and above zero.

```text
excess = (head - floor) - retained_blocks
compact when excess >= interval_blocks, to floor = head - retained_blocks
```

## Automatic evaluation

`AppendOnlyStorage::commit` publishes its record first and only then evaluates
the policy once. Work per commit is therefore bounded by `retained_blocks`
rewritten bodies, one anchor state snapshot, and `max_compaction_bytes` total
rewritten bytes; a compaction that would exceed the byte budget is refused
instead of truncated. Because the evaluation happens after publication, a
retention failure never unpublishes the commit: the commit returns its
checkpoint, the failure is recorded in `RetentionState::last_error`, and a
failure that leaves durability uncertain poisons the handle so the next
operation returns `DurabilityUnknown` and the operator reopens the directory.

`ChainStorage::set_retention_policy` installs the policy and
`NetworkNode::set_retention_policy` forwards it to the node's storage. The
bounded legacy `ASTSTORE` archive of
[document 22](22-append-only-chain-storage.md) returns
`StorageError::Unsupported` for both, since it has no append-only log to replace.

`ChainStorage::retained_floor` reports the oldest retained checkpoint height and
`ChainStorage::history_floor` reports the lowest height whose exact state the
reverse index can still rebuild. Both are now public, so a policy, RPC handler or
operator command reads the floor instead of probing for `read_state_at` returning
`Ok(None)`. A floor states local availability only; it never asserts that an
absent height was not finalized.

## Publication and crash recovery

Compaction writes a complete replacement rather than editing the published log,
because every frame digest chains from its predecessor and a new first record
rehashes the whole suffix. The replacement starts with the same header, so its
first record is an anchor at the new floor and its first frame still begins at
offset 40; the full-replay loop in `export_snapshot` therefore picks up the
anchor as its start state with no change, and returns
`StorageError::VerificationFailed` for a height below the floor.

The directory gains three reserved sidecars beside the existing `chain.bin`,
`.head`, `.lock` and `.pending`.

| File | Purpose |
| --- | --- |
| `chain.bin.compact` | Unpublished replacement log; never authoritative |
| `chain.bin.swap` | Published head of the replacement; its readability is the commit point |
| `chain.bin.retain` | Durable local record that this writer shortened its own history |
| `chain.bin.retain.pending` | Staged record awaiting the same commit point |

The sequence is: write and synchronize the replacement; write and synchronize the
staged record; write and synchronize `.swap`; then rename the replacement over
`chain.bin`, the staged record over `.retain`, and `.swap` over `.head`. Opening
the directory resolves any interruption under the writer lock before the header
or head is trusted. An unreadable or absent `.swap` means the commit point was
never crossed, so the replacement and the staged record are discarded and the
previous log stays authoritative. A readable `.swap` means the replacement is
published, so the candidate bytes are verified frame by frame against the
recorded end offset and digest, and the renames are completed. A committed marker
whose candidate does not verify fails closed with `StorageError::Corrupt` rather
than repairing or discarding the committed prefix. Only unpublished tail bytes are
ever discarded, and no path resets history to genesis.

```text
"ASTRET01" || floor:u64 || compactions:u64 || anchor_block:32
           || anchor_state_root:32 || H("astrolune.storage.retention.v1", preceding 88 bytes)
```

The record is 120 bytes. `floor` is a high-water mark: opening refuses a record
below the log's own anchor height, and refuses a record at that height naming a
different block or state root, because both indicate an inconsistent directory. A
record above the anchor height is accepted, which is exactly the state left by a
crash between the record write and the commit point.

## Checkpoint and signing-state recovery

The offline export of [document 49](49-pinned-history-retention.md) requires an
independently held pin because an operator importing a shortened history has no
other trust: an anchor record carries its own state, so whoever writes those bytes
chooses the committee the node will believe.

In-place retention is a different situation and uses a different trust root. The
same process authenticated every one of those blocks against trusted genesis,
published them itself, still holds the directory's exclusive writer lock, still
holds its own protected signing journal, and records the anchor it kept before the
replacement is committed. Continuity, not an external pin, is what authenticates
the shortening, and restart resumes from the locally recorded anchor.

`ChainStorage::local_retention_anchor` returns the recorded anchor only when the
log anchor is above height zero and a readable record covers it.
`StaticNetwork::local_retention` turns that into an internal recovery checkpoint
for the node's existing pinned recovery path, so `StaticNetwork::recover` and
`StaticNetwork::verify_storage` accept a self-compacted directory, reconstruct the
producer from the anchor state, and replay the retained suffix with full
certificate verification. Without that record the same bytes are an externally
supplied shortened history: `local_retention_anchor` returns `None`, the unpinned
check that complete history descends from genesis applies again, and startup is
refused until the operator supplies an independently held pin. Rotating genesis-v2
profiles are refused outright, because their recovery needs a committee history
frontier that only a pin carries.

Retention never reads, copies, writes or resets a signing journal, its monotonic
anchor, a consensus cache or a transport identity. It touches only `chain.bin` and
the sidecars listed above, and the journal watermark continues to advance
monotonically across a compaction and a restart.

## Threat boundary

Before this feature, a node starting without a pin required complete history from
genesis, so the only history an attacker with write access to the data directory
could present was a prefix of the real chain: every height had to carry a quorum
certificate they could not forge. After this feature, an attacker with write
access can additionally write a 120-byte `chain.bin.retain` record alongside a
shortened log and have the node start from an anchor of their choosing. The record
is checksummed, not signed, so it stops accidental and partial damage, not a
deliberate local writer. Because the anchor record carries its own state, such an
attacker can choose the state root, and on a PoTB or rotating profile the
committee, that the node resumes from.

That is a real widening and it is stated plainly here. It is bounded by what was
already true: an attacker who can write the data directory could already replace
`chain.bin` and `chain.bin.head` wholesale, roll the directory back coherently, or
delete it. Checksums never detected a coherent rollback of all local files, which
is why [document 23](23-signing-journal-rollover.md) custody and a separately
stored signing anchor remain required, and why `verify-signing-anchor` exists. The
boundary this feature does not move: a shortened directory still proves nothing to
a peer, an observer or an auditor, and nothing here lets a node accept a shortened
history that arrived over the network or from another operator.

Signing the retention record with the validator's consensus key would close the
widening, since forging the record would then require the signing key rather than
directory write access. That is not implemented.

## Operator commands

Both commands acquire the exclusive storage writer lock, so the node must be
stopped first. `retention-status` is read-only. `retention-compact`
authenticates the existing history against the independently supplied profile and
public keys, enforces an independent minimum height, compacts in place, and then
reauthenticates the shortened directory before reporting.

```text
cli retention-status <directory> [retained-blocks interval-blocks]
cli retention-compact <genesis-or-profile> <validators> <directory> <minimum-height> <retain-blocks>
```

`retention-status` prints `backend`, `head_height`, `retained_floor`,
`retained_bodies`, `history_floor`, `self_compacted`, `compactions`, `policy` and
`last_retention_error`. With the two optional arguments it also validates the
requested policy and prints `requested_retained_blocks`,
`requested_interval_blocks` and `requested_next_floor` without writing anything.
`retention-compact` prints the same report for the compacted directory.

## Daemon activation

Three daemon flags install the policy on a running node, so retention no longer
requires a library caller or an offline command.

```text
daemon --run --retain-blocks N [--retention-interval N] [--retention-bytes N] ...
```

`--retain-blocks` is what enables retention; naming it alone takes the documented
defaults for the other two. `--retention-interval` and `--retention-bytes` shape
a policy that flag has already turned on and are refused on their own, because
shaping a disabled policy would silently keep every block. Every bound is checked
by `NodeConfig::validate_with_retention` before a directory is opened or a
listener bound, so an impossible policy fails in argument parsing rather than at
the first commit.

All three require `--validators`. The demonstration path authenticates nothing
and its finality is simulated, so there is no history there that the continuity
argument below could authorize shortening; the flag is refused rather than
accepted and ignored. Both roles accept it: `NetworkNode::set_retention_policy`
and `ObserverNode::set_retention_policy` are installed through the one daemon
role seam, and an observer qualifies for the same reason a validator does — it
authenticated and published every block it holds against its own trusted genesis.

Two combinations are refused, both before the first commit rather than at a later
one. A rotating genesis-v2 profile that is not PoTB is refused because the storage
log that installs a policy cannot see the network profile: it would accept the
policy and compact, and only the *next* startup would find that
`StaticNetwork::local_retention` refuses a self-compacted rotating directory for
want of a committee history frontier that only an external pin carries. That is a
node that shortens its history and then cannot start, so the daemon refuses the
pair instead. `--checkpoint` is refused alongside `--retain-blocks` because pinned
recovery takes precedence over a directory's own anchor, so a node given both would
keep verifying a descriptor whose height its own compaction can move the floor
past; externally pinned recovery and self-compaction stay separate paths, and that
interaction is not qualified here.

The policy is installed after certified recovery and before the first block of
the run is produced or imported, so that block already evaluates it, and a
directory that cannot retain in place says so at startup: the bounded legacy
archive refuses automated retention. An enabled policy prints one `retention :`
line naming the suffix, interval and byte budget.

A policy is runtime configuration and is never written to disk. A restart without
the flags retains every subsequent block, and what the directory carries across
that restart is the durable compaction record, not the policy that caused it.

## Limits

On 2026-10-10, on Windows 11 with Rust 1.99.0, `cargo test --locked -p storage -p
config -p cli -p node --all-features` passes, including 13 storage integration
tests and 3 command-line tests specific to retention. Windows power-loss
guarantees still depend on the filesystem and storage stack, and the
fault-injection tests here interrupt a compaction at its two publication windows
rather than qualifying power loss.

Automated retention is disabled by default and must be enabled explicitly.
`crates/config` exposes `HistoryRetentionConfig` as a standalone validated type
rather than a `NodeConfig` field, because `NodeConfig` is built from exhaustive
struct literals in `apps/daemon` and `tests/integration`. The daemon flags above
install it; `retention-compact` still applies one compaction offline, and a
library caller can still install a policy directly.

Daemon activation is covered by two integration tests.
`configured_retention_compacts_a_running_daemon_and_still_recovers_locally` runs a
three-validator quorum with the smallest retained suffix and the smallest interval,
and checks the durable record, the floor and local recovery without a pin.
`rotating_profiles_refuse_automated_retention_before_shortening_anything` checks
that a rotating genesis-v2 directory refuses the flag while the same directory and
arguments recover without it, and that PoTB accepts the identical flag. Together
they establish that the flags reach storage, that one shortening recovers, and that
the one profile whose recovery needs an external pin cannot shorten itself by
accident. They do not establish a retention schedule under load, the observer role,
which is reasoned from the shared daemon role seam rather than exercised, or any
figure about compaction cost.

The retained suffix is at most 64 blocks, because the anchor state comes from the
bounded reverse state index; a large state transition can evict the intended floor
earlier, and compaction is then skipped and retried on a later commit rather than
retaining less than configured. The byte budget is enforced but is not covered by
a test above the 16 MiB minimum. One compaction rewrites the whole retained
suffix, so its cost grows with `retained_blocks` and with body size, and it runs
on the committing thread.

Rotating genesis-v2 retention is refused; the recovery path accepts a
self-compacted directory for fixed-committee and PoTB profiles, and only the
fixed-committee profile is covered by a test here. Bodies, receipts and handoffs
below the floor are gone, so exact-height certified queries return unavailable
there, and a
pending offence proof that predates the floor can no longer be reauthenticated
locally: the evidence path replays handoffs from genesis when no pin is
configured, so such a proof already stored in the directory should make startup
fail closed rather than be trusted implicitly. That case is reasoned from the
code and is not covered by a test here. The durable record counts compactions for
reporting only; it is checksummed rather than signed, and it is not a recovery
descriptor, so it must never be copied into another directory. Automated
retention for the legacy `ASTSTORE` archive, in-place archive migration, a
bounded startup cost, a background compaction thread and signed retention records
all remain open.
