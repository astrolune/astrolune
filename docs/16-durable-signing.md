<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 16. Durable Consensus Signing

## Implemented reference signer

`keystore::DurableSigner` holds one raw Ed25519 seed in a private zeroizing buffer and signs only after a durable journal reservation. The caller supplies the seed; this API does not persist, generate, encrypt, or export private keys. The caller remains responsible for its own seed copies and provisioning. Debug output contains public metadata and the last signing position, never the seed.

Creation is explicit with `DurableSigner::create(path, context, seed)` and refuses to overwrite any existing file. Recovery uses `open` with the same seed, chain ID, and nonzero trusted genesis commitment. It never initializes a missing journal. Invalid namespaces, malformed bytes, and interrupted files are rejected without rewriting or truncating them. The journal contains the public key, not the private seed; it binds the key independently of caller-chosen labels. The consensus handle derives from the validator ID and rejects other purposes.

Protected version-2 journals support [bounded watermark rollover](23-signing-journal-rollover.md) after 100,000 decisions, preserving the original locked file and BFT safety state. The version-1 raw journal described below retains its original decision limit.

Protected version-2 journals now also reserve [signed proposals](18-signed-proposals-and-participants.md) in phase 0 through `LocalBft::propose`, preserving lock metadata and checking exact retries after restart.

The original `MockKeystore` and `crypto::Ed25519Keystore` remain in-memory helpers. They do not acquire durable behavior through this change.

## Decision ordering

A signing position is the lexicographic tuple `(height:u64, round:u32, phase:u8)`:

| Operation | Journal phase | Vote wire phase |
|---|---:|---:|
| Proposal | 0 | Not a vote |
| Prevote | 1 | 0 |
| Precommit | 2 | 1 |

The latest durable position and digest form a monotonic watermark. A greater position may be reserved; the same position and digest returns the same deterministic signature without appending. A different digest at the latest position returns `ConflictingSign`. Every earlier position returns `StalePosition`, even when its original digest would match. Phases outside 0 through 2 are rejected. This conservative rule bounds recovery memory without allowing old positions to be reused.

`consensus::Vote::sign_with` verifies chain ID and signer identity, derives the position from the vote's actual height/round/phase, and signs its canonical digest. It updates the vote's signature only on success. It does not allow a caller to relabel a prevote as a different journal phase. Nil, block hash, committee commitment, and all other vote fields remain protected by the existing signing digest. The low-level `Signer::sign_consensus` requires its caller to supply the correct digest and coordinates; vote callers should use the typed helper.

Changing height or round does not establish permission to vote for a different block. The separate [local BFT guard](17-local-bft-voting.md) now implements fixed-height lock and timeout transitions using version-2 protected journals. Version 1 described here protects signing coordinates without lock history and cannot be used by `LocalBft`. Create protected journals explicitly with `create_protected`; no automatic conversion is provided.

## Version-1 journal bytes

All integers are unsigned little-endian. The fixed 108-byte header is:

```text
ALSJ || version:u32=1 || chain_id:u32 || genesis:32 || public_key:32
     || header_checksum:32
```

`header_checksum = H("astrolune.signing.journal.v1", first_76_bytes)`, with the length-framed BLAKE2s domain hash already used by the protocol.

Each decision adds exactly 85 bytes:

```text
sequence:u64 || height:u64 || round:u32 || phase:u8 || message_digest:32
             || record_checksum:32
```

Sequence begins at one and increases by one. The checksum is `H("astrolune.signing.decision.v1", previous_checksum || first_53_record_bytes)`; the first previous checksum is the header checksum. Recovery verifies every checksum, sequence, supported phase, and strictly increasing position. Version/tag changes, reordered or duplicate decisions, corrupted bytes, and partial records fail closed.

The reference limit is 100000 decisions, or 8500108 bytes including the header. Recovery checks the file size before reading, streams fixed-size records, and retains only the current watermark and checksum. New decisions stop at the limit; an identical retry of the latest decision still works. There is no automatic pruning, migration, or journal reset.

## Persistence and failure behavior

The signer holds an exclusive OS lock on the journal file until it is dropped. It appends prefix records through explicit offsets in the same file; protected rollover later rewrites only its two fixed slots. There is no replacement window or removable sidecar lock. Cooperative opens through another path or hard link contend on the same file lock. Symbolic file aliases are rejected. Journal directories and file ownership must remain under the operator's control.

For each new decision, the signer appends the complete record and calls `sync_all` before computing and returning an Ed25519 signature. It checks the expected file length before accepting any decision, including an idempotent retry. Unexpected length changes disable the instance.

Any append or synchronization error returns `DurabilityUnknown` and disables subsequent signing on that instance. A complete record can exist even though the caller received no signature. Reopening validates all records and synchronizes the file again before permitting an idempotent retry. A partial final record is rejected; recovery never guesses whether it is safe to discard it. Interrupted creation also leaves its file in place.

Unix additionally synchronizes the containing directory on creation and reopening. Windows initial directory-entry durability under power loss remains filesystem-dependent. Tests establish process-restart behavior and injected I/O failure handling, not hardware power-loss guarantees.

## Trust and operational limits

The checksum chain detects accidental corruption; it is not a defense against a storage administrator who rewrites a valid journal. Restoring an older complete prefix, deleting the original journal and explicitly provisioning another, copying a seed to an independent journal, or reverting a virtual-machine snapshot bypasses a purely local watermark. An opt-in [independent anchor](53-key-custody-and-release-authority.md) now closes the restored-journal and replacement-journal cases: `DurableSigner::open_with_anchor` pairs the journal with a separately provisioned store, fails loudly when the journal is behind it, and refuses a mismatched pair. That raises the bar from rewriting one file to consistently rewriting two independent stores; it is not hardware-enforced rollback prevention, and a coordinated two-store rewrite, a backup restore covering both paths, a snapshot revert covering both, or a cloned seed in an unrelated pair still succeeds. Hardware isolation, an HSM, and a TPM or TEE sealed counter remain open. The anchor is opt-in, so an unanchored journal retains exactly the original limits. Existing trusted journal files must not be reset, restored to old backups, renamed, or replaced while the validator remains authorized to sign.

Genesis binding identifies the journal's namespace; the version-1 vote wire format still carries the chain ID rather than the genesis hash. The protocol must assign chain IDs consistently, and committee trust must come from finalized state. There is no automatic conversion of in-memory signing history, or of signatures produced before the journal existed, into durable history.

The certified daemon opens existing protected journals and authenticates genesis key registration; explicit CLI provisioning and fixed-committee voting/timers are implemented. `daemon --signing-anchor PATH`, which requires `--validator-key` and the key's existing journal, selects `DurableSigner::open_with_anchor` so the journal is paired with a separately provisioned [rollback anchor](53-key-custody-and-release-authority.md); without that argument the daemon opens the journal alone and retains exactly the unanchored limits above. [Encrypted consensus-key custody](53-key-custody-and-release-authority.md) is reachable through `keystore` and the CLI. Local demonstration mode remains separate. Hardware-backed custody and independent review of key operations remain open.

## Verification

Tests cover independent Python BLAKE2s header/record vectors, byte corruption and partial truncations, valid-checksum invalid coordinates, bounds, identity and purpose checks, full-width positions, stale/conflicting/idempotent requests, same-file and hard-link process locks, forced process exit without destructors, failures before/during append and at synchronization, resynchronization on reopen, typed vote phase mapping, and independently verified certificates produced by restarted signers. Linux-specific symbolic-link coverage is included; the current local run exercises Windows.
