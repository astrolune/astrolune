<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 53. Key custody and release authority

## Independent signing anchors

Every guard in `keystore`'s signing journal is derived from the bytes of one file.
The checksum chain is self-consistent, so an older complete prefix hashes correctly
and the journal accepts it as the current watermark. `keystore::anchor` adds a
second store, provisioned separately at an operator-specified path, that records the
journal's observable watermark and must agree with it before any signature leaves
the process. Pairing is opt-in: `DurableSigner::create` /
`DurableSigner::create_protected` / `DurableSigner::open` keep their original
behavior and limits, and only `DurableSigner::create_anchor` and
`DurableSigner::open_with_anchor` involve an anchor.

The anchor records a monotonically increasing decision sequence, the latest
`SigningPosition`, the reserved digest, and the journal's chained record tip. It
also binds the journal's origin commitment, which is the journal header checksum
over the version, chain ID, trusted genesis and public key. A journal and an anchor
that disagree on that origin are a mismatched pair and are never merged.

This is an independent-anchor rollback check, not hardware-enforced rollback
prevention. It raises the bar from rewriting one file to consistently rewriting two
independent stores, and it only does so when the anchor actually lives on storage
that cannot be restored in the same operation as the journal. Nothing in the code
verifies that separation; the path is an operator decision. Hardware isolation, an
HSM, a TPM or TEE sealed counter, remote attestation, and a monotonic counter that
survives a coordinated two-store rewrite are **not** established. An administrator
with write access to both stores, a backup restore covering both paths, and a
virtual-machine snapshot revert that includes both still defeat this check, as does
copying the seed into an unrelated journal and anchor pair.

## Anchor file format version 1

The anchor file is exactly 376 bytes, exported as `SIGNING_ANCHOR_BYTES`, and never
grows or shrinks. All integers are fixed-width unsigned little-endian. `H` is the
protocol's length-framed domain-separated BLAKE2s-256 function.

| Bytes | Meaning |
| --- | --- |
| 0..8 | ASCII `ALSANCH1` |
| 8..12 | chain ID |
| 12..44 | trusted genesis commitment |
| 44..76 | validator Ed25519 public key |
| 76..108 | journal origin commitment |
| 108..140 | header checksum |
| 140..258 | slot 0 |
| 258..376 | slot 1 |

```text
header_checksum = H("astrolune.signing.anchor.v1", first_108_bytes)

slot (118 bytes):
    sequence:u64 || position_present:u8 || height:u64 || round:u32 || phase:u8
    || digest:32 || journal_tip:32 || checksum:32

slot_binding = H("astrolune.signing.anchor.binding.v1",
                 header_checksum:32 || slot_index:u8)
checksum = H("astrolune.signing.anchor.slot.v1",
             slot_binding:32 || first_86_slot_bytes)
```

Each field has exactly one canonical encoding. Sequence zero means an empty journal
and requires an absent position with a zero height, round, phase and digest; a
present position requires a nonzero sequence and a phase of 0 through 2. The
destination slot for sequence `n` is `n mod 2`, so a torn write never damages the
other slot. Provisioning writes the same verified state into both slots.

Recovery requires either two identical slots or two adjacent sequences in their
designated physical slots with strictly increasing positions. **Both slots must
validate. Recovery never falls back to an older valid slot when the other is
damaged**, because the damaged slot may hold the decision whose signature already
escaped; this is the reasoning already applied to the journal's rollover slots.
Trailing bytes, partial slots, swapped slots, gaps and every single-byte mutation
fail closed. The format does not carry a signature, an operator identity, a
timestamp, or any history beyond the latest two witnessed decisions, and it is not
an audit log.

## Pairing rules and failure behavior

The journal is written first and the anchor second, so the journal is at or exactly
one decision ahead of the anchor. On `open_with_anchor`:

- an anchor sequence greater than the journal's record count is the
  restored-older-journal case and fails with `StalePosition`;
- an equal sequence requires the whole recorded state — position, digest and
  chained tip — to match exactly, or the pair fails with `ConflictingSign`;
- a sequence exactly one behind is the interrupted anchor write, and the journal's
  retained predecessor state must equal the anchor's recorded state before the
  anchor catches up durably;
- any larger gap fails with `StalePosition`.

Because the recorded tip is the chained checksum over every retained record, a
journal rewound below a sequence and advanced again cannot reproduce the anchor's
state at that sequence. After a protected journal rolls over, the chained tip stops
advancing and the binding at post-rollover sequences rests on the sequence, position
and digest alone.

Both files are held under exclusive OS locks for the lifetime of the signer, so a
second process and a hard-link alias contend on the same locks. Opening never
creates a missing anchor, and `create_anchor` opens an existing journal and refuses
to overwrite an existing anchor. Each decision writes its slot and calls `sync_all`
before an Ed25519 signature is returned. Any uncertain anchor write poisons the
instance exactly as the journal does: the next decision returns
`DurabilityUnknown`, and reopening must validate both slots again. Unix also
synchronizes the containing directory on creation and reopening; Windows
initial directory-entry durability under power loss remains filesystem-dependent.
Automatic repair, slot deletion, anchor re-provisioning for a live identity and any
fallback to an older anchor value are deliberately absent. Tests establish
process-restart and restored-file behavior, not hardware power-loss guarantees.

## Encrypted consensus-key custody

`keystore::vault` now encrypts consensus and VRF seeds under the same fixed profile
as wallet vaults: Argon2id v19 with 65,536 KiB, three passes, one lane and a 32-byte
derived key, then XChaCha20-Poly1305 with an independent 16-byte salt and 24-byte
nonce from the operating system CSPRNG for every encryption. The exact 144-byte
layout, the authenticated 96-byte header, the parameter validation performed before
any KDF memory is allocated, and the decrypted-public-key check are unchanged from
[the wallet vault](31-rust-sdk-and-wallet-vaults.md).

File byte 8 carries the purpose: 1 for a wallet vault, 2 for a consensus vault. It
is authenticated as associated data and checked before key derivation, so
`decrypt_wallet_seed` rejects a consensus vault and `decrypt_consensus_seed` rejects
a wallet vault without performing any work. `vault_purpose` reports the declared
purpose of a vault-framed file without a password. `WALLET_VAULT_BYTES` and the
wallet functions are byte-compatible with vault v1, and the frozen
`crates/keystore/tests/fixtures/wallet-v1.bin` vector still decrypts.

Passwords remain 12..1024 opaque bytes read as one line from a private stdin pipe;
an interactive terminal is refused to avoid echo, and passwords never appear in
`argv`. Passwords, derived keys, seed buffers and the entire Argon2 workspace are
zeroized when released. There is no plaintext export command and no key-recovery
path. This protects a consensus seed at rest. It does not provide hardware
isolation, a non-exporting signing device, threshold or multi-party custody, key
rotation, or any protection for a seed already loaded into process memory, and an
encrypted seed does not by itself prevent the holder from provisioning a second
journal.

## Release authority and detached manifest signatures

`keystore::release` signs a release manifest with the project's existing strict
Ed25519 under the domain `astrolune.release.manifest.v1`. No new dependency is
introduced. The signed object is the manifest rather than a single archive digest:
the manifest commits to the archive bytes through `archive_sha256` and to every
packaged file through `files`, so one signature transitively covers the whole
artifact set, including a file substituted inside the archive.

`.github/scripts/package-build.py` writes `MANIFEST.json` beside the archive and
`SHA256SUMS`. Its bytes are the in-archive `BUILD.json` provenance record plus the
archive name and digest, serialized with sorted keys and an LF terminator, so equal
inputs produce an equal manifest and therefore an equal signature. The `release`
flag is now driven by an explicit `--release` option instead of being hardcoded; it
appears in both `BUILD.json` and `MANIFEST.json`, so setting it changes the archive
digest. The script still performs no signing, no key handling and no upload, and
`SHA256SUMS` keeps its original single-line content and LF-only framing.

Verification requires an explicitly supplied authority public key. The key embedded
in the signature artifact is compared with the supplied key and disagreement is an
authentication failure; the artifact never establishes its own authority. This
repository defines no maintainer identity, commits no real or placeholder authority
key, and performs no key ceremony, no key distribution, no transparency log, no
revocation, no expiry, no countersignature or threshold policy, and no publication.
Which key is authoritative, and how it is held and retired, is **not** established
here. Nothing in this mechanism weakens the statement in `RELEASING.md` that the
repository does not invent signing identities or keys.

## Release signature format version 1

The detached signature is exactly 136 bytes, exported as
`RELEASE_SIGNATURE_BYTES`. Manifests above `MAX_RELEASE_MANIFEST_BYTES`
(1,048,576 bytes) and empty manifests are rejected before any hashing.

| Bytes | Meaning |
| --- | --- |
| 0..8 | ASCII `ALRS0001` |
| 8..40 | signing authority Ed25519 public key |
| 40..72 | manifest digest |
| 72..136 | strict Ed25519 signature over the manifest digest |

```text
manifest_digest = H("astrolune.release.manifest.v1", exact_manifest_bytes)
```

Verification recomputes the digest from the supplied manifest bytes, requires the
embedded key to equal the supplied authority key, requires the embedded digest to
match, and requires a valid strict Ed25519 signature. Every single-byte mutation,
every truncation and any trailing byte fail closed. The format carries no
timestamp, no revision binding beyond the manifest's own contents, no certificate
chain and no countersignatures, and verifying a signature establishes only that the
holder of that key signed those exact manifest bytes.

## Operator workflow

Journals and anchors are provisioned separately, and the anchor belongs on storage
that the journal's storage cannot restore:

```text
cli init-validator genesis.bin validator.vault node-data
cli signing-anchor-create genesis.bin validator.vault node-data/signing.journal /mnt/anchor/signing.anchor
cli verify-signing-anchor genesis.bin validator.vault node-data/signing.journal /mnt/anchor/signing.anchor
```

Consensus keys are encrypted with the same password handling as wallets, and
`init-validator`, `admission-approve`, `governance-approve` and `vrf-prove` accept
either a raw 32-byte seed or a consensus vault:

```text
cli consensus-vault-create validator.vault
cli consensus-vault-encrypt validator.seed validator.vault
```

Release manifests are signed and verified offline, with the authority key supplied
explicitly on verification:

```text
python .github/scripts/package-build.py x86_64-unknown-linux-gnu --release
cli release-sign target/ci-artifacts/MANIFEST.json authority.vault target/ci-artifacts/MANIFEST.json.sig
cli verify-release target/ci-artifacts/MANIFEST.json <authority-public-key> target/ci-artifacts/MANIFEST.json.sig
```

On 2026-10-07 the anchor and release commands acquire exclusive file locks, so a
running validator must be stopped before `verify-signing-anchor` is used, and that
command completes an interrupted anchor update rather than being purely read-only.
The reference daemon still opens journals through `DurableSigner::open` and has no
anchor option, so anchored signing is reachable through `keystore` and the CLI but
is **not** yet part of the daemon's startup path. Operator procedure for a detected
rollback, identity fencing, key rotation and release key handling is not defined
here.

## Verification

On 2026-10-07, on Windows 11 Home 10.0.26200 with Rust 1.99.0 and Python 3.11.9,
`cargo test -p keystore -p cli` and
`python -B -m unittest discover -s .github/scripts -p 'test_*.py'` pass.

Anchor coverage includes independent Python BLAKE2s header and physical-slot
vectors, noncanonical absent positions and unsupported phases, every slot
truncation and single-byte mutation, checksummed gaps and slot swaps, provisioning
that refuses overwrites, opening that never creates a missing file, cross-process
lock exclusion, and a child process that signs and exits without destructors. The
rollback attack is exercised directly: an older complete journal prefix is restored,
the journal alone is shown to accept it and sign a different digest at a height it
already voted on, and the same restored file beside a current anchor fails with
`StalePosition` without rewriting either file. A journal rewound and advanced again
to the anchor's own sequence fails with `ConflictingSign`. The interrupted-anchor
case is reproduced by signing through an anchor-free signer, and catch-up succeeds
at a lag of one decision and fails at a lag of two.

Vault coverage adds the frozen wallet-v1 fixture, consensus round-trips, both
cross-purpose rejections, every header parameter byte, all truncated lengths, and
password bounds. Release coverage adds an independent Python digest vector,
deterministic signing, foreign-authority rejection, manifest mutation including the
`release` flag, every signature mutation and truncation, and real CLI subprocesses
that confirm passwords and seeds never appear in output, that outputs are never
overwritten, and that a consensus vault and its raw seed produce byte-identical
signatures. Python coverage adds manifest determinism, the archive binding, the
explicit release flag, and the absence of any signature artifact.

No independent audit, no hardware-backed test, no power-loss test, no multi-host
anchor-separation test and no published release exist. Nothing here establishes a
maintainer identity or a production release.
