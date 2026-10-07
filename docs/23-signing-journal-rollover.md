<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 23. Protected signing journal rollover

## Implemented behavior

Protected version-2 signing journals continue past 100,000 reserved decisions without replacing, truncating or unlocking the journal file. The original header and first 100,000 records stay immutable. A fixed 348-byte extension then retains two alternating watermarks. Each watermark includes the decision sequence, signing position, digest, committee and BFT lock.

The protected journal's maximum size is **15,400,456 bytes**, exported as `MAX_ROLLOVER_JOURNAL_BYTES`. `MAX_PROTECTED_JOURNAL_BYTES` remains the original 15,400,108-byte prefix boundary. `MAX_JOURNAL_RECORDS` remains the retained-prefix count and the version-1 raw journal limit. Version-1 journals cannot supply BFT locks and do not roll over.

The daemon benefits automatically through its existing `DurableSigner`. No new identity, key, operator command, peer protocol or consensus rule is introduced. Earlier signing positions remain forbidden, including positions no longer individually retained. An exact retry of the latest position must match its digest and safety metadata. The sequence counter uses checked `u64` arithmetic; exhaustion rejects further decisions while preserving exact retries.

## Activation and durable updates

Only a valid request for a new decision beyond the full protected prefix activates rollover. Stale, conflicting or invalid-lock requests, and exact retries of the prefix's final decision, leave the file unchanged.

Activation appends the extension header and two copies of the verified final prefix watermark, then synchronizes the file. The next decision overwrites slot zero and synchronizes again before any Ed25519 signature can be returned. Later decisions alternate slots. The file remains under the same exclusive OS lock throughout activation, updates and recovery. Hard-link aliases still contend on that lock; there is no replacement inode or removable lock sidecar.

Before every decision, including an exact retry, the signer checks the expected file length. After rollover it also compares the entire on-disk extension with the last verified in-memory version. Unexpected changes disable the signer. All writes seek explicitly within the same read/write file; append-mode handles must not be used for rotating slots.

On any uncertain activation, write, seek or synchronization failure, the instance stops signing. Reopening verifies the complete immutable prefix, both slots, their relationship, and namespace, then synchronizes the file again before signing is permitted.

**Both slots must validate. Recovery never falls back to an older valid slot when the other is damaged.** The damaged slot might contain a newer decision whose signature already escaped. An incomplete overwrite therefore fails closed even if the file length is unchanged. A complete record whose synchronization was uncertain can be recovered, but only that decision can be retried at its position.

## Extension format version 1

The extension starts exactly at byte offset 15,400,108. All integers are fixed-width unsigned little-endian. `H` is the protocol's length-framed domain-separated BLAKE2s-256 function. `prefix_tip` is the checksum of record 100,000 after verifying the original journal.

```text
extension header (40 bytes):
    "ALSR0001" || anchor:32
    anchor = H("astrolune.signing.rollover.v1", prefix_tip:32)

slot 0 (154 bytes), followed by slot 1 (154 bytes):
    sequence:u64 || height:u64 || round:u32 || phase:u8 || digest:32
    || committee_root:32 || lock_present:u8
    || locked_round:u32 || locked_block:32 || checksum:32

slot_binding = H("astrolune.signing.rollover.slot.v1", anchor:32 || slot_index:u8)
checksum = H("astrolune.signing.decision.v1", slot_binding:32 || first_122_slot_bytes)
```

Immediately after activation, both slots contain sequence 100,000 and exactly the verified final prefix decision. Their checksums differ because the physical slot index is bound into the checksum. For every later sequence `n`, the destination is `(n - 100001) mod 2`.

Recovery requires either the two initial copies or two adjacent sequences in their designated slots. Signing positions must increase with sequence. The older and newer watermark both extend the retained prefix; the newer also extends the older. Validation rejects gaps, swapped slots, stale/duplicate positions, committee changes within a height, cleared/regressed locks, same-round lock conflicts, future-round locks, unsupported phases and noncanonical absent-lock fields. Every byte belongs to a fixed-size frame; trailing bytes and partial extensions fail.

## Compatibility and operational limits

Existing version-1 and version-2 prefixes remain readable without conversion. The journal header remains version 2 when its extension activates. Older executables reject an extended journal because its length exceeds their accepted limit. Downgrading by truncating the extension would discard signing authority and is unsafe. Upgrade validator software before its protected journal reaches the old limit; preserve the original key and journal through every restart.

An interrupted activation that wrote nothing leaves the old full prefix recoverable. A complete extension can recover even when its writer reported a synchronization failure. Any partial extension or damaged slot requires the validator to remain stopped; automatic repair, slot deletion and rollback are deliberately absent. Do not provision another journal for an active identity to bypass a failure. Fencing or rotating an affected identity requires the separately governed consensus/key-custody procedure, which is not implemented here.

Only the immutable prefix and latest two decisions remain available in this file after rollover. It is an anti-equivocation guard, not a complete historical audit log. Original decision positions, current digest and lock protection remain intact, but external signed-evidence archival is separate work.

Checksums cannot stop a storage administrator from restoring a coherent old file, deleting the extension, or cloning a key. External rollback-resistant custody remains necessary. Unix directory synchronization and Windows filesystem-dependent creation durability retain the original journal's qualifications. Process-exit and injected-I/O tests do not establish hardware power-loss guarantees or an independent consensus audit.

## Verification

Tests use the real 100,000-record threshold. Coverage includes actual Ed25519 signing after activation, repeated slot reuse at constant size, immutable prefix preservation, exact/stale/conflicting retries, committee/lock continuity, advancing to a later height, hard-link and cross-process writer exclusion, and child-process exit without destructors.

Failure injection covers zero, partial and complete activation writes, partial slot overwrites and complete writes with uncertain synchronization. Fixed-format tests cover every extension truncation and single-byte mutation, valid-checksum structural attacks, physical-slot binding, sequence exhaustion and independent Python BLAKE2s vectors. An integrated network fixture resumes from a full journal, crosses the boundary, restarts, finalizes a signed payment, synchronizes an observer and then continues at the next height.
