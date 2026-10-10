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
authentication failure; the artifact never establishes its own authority. The
ceremony that decides which key is authoritative, the identity and transcript
formats that record that decision, the expiry and revocation documents that retire
it, and the offline verifier that checks all of them are specified in the three
sections below. What remains is a maintainer executing that ceremony with their own
key on their own hardware. This repository still defines no maintainer identity,
commits no real or placeholder authority key, has performed no ceremony,
distributes nothing and publishes nothing, and it still has no transparency log, no
countersignature and no threshold policy. Nothing here weakens the statement in
`RELEASING.md` that the repository does not invent signing identities or keys.

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

## Release authority identity format version 1

Three documents record a release authority: an identity document binding one key to
one scope, one validity window and one ceremony; a ceremony transcript recording
what was done and witnessed; and a revocation statement withdrawing an identity.
Each is canonical sorted-key LF-terminated JSON, exactly like `MANIFEST.json`, and
each is signed as a whole with the frozen 136-byte `ALRS0001` artifact above.

JSON was chosen over a fixed-width framed binary record, and the choice is not a
matter of taste. An identity document is read aloud and compared by witnesses
during the ceremony, and by verifiers who have no Rust toolchain, so what is signed
has to be what a person can read without a decoder. A transcript carries
variable-length operator text — the witnesses, the custody locations, the steps
performed — which a fixed-width record cannot hold at all. And the signable object
has to be arbitrary bytes under the existing domain, because `ALRS0001` and
`astrolune.release.manifest.v1` are frozen: a framed binary record would need a new
keystore format, a new domain and a new CLI verb, changing cryptography that is
already qualified in exchange for nothing. `MANIFEST.json` already establishes that
a canonical JSON document is a signable object here.

The canonical form is exact. A document that is not in it is refused before any
signature is examined, because the signature commits to the bytes, and bytes that
cannot be re-derived from the document's own fields could never be reproduced by a
later reader.

| Rule | Value |
| --- | --- |
| serialization | `json.dumps(document, indent=2, sort_keys=True)` plus one `\n` |
| separators | `", "` between items, `": "` between key and value |
| key order | lexicographic at every depth, including nested objects |
| encoding | UTF-8 with no byte-order mark |
| line ending | LF only, exactly one terminating the file |
| maximum length | 1,048,576 bytes, inherited from `MAX_RELEASE_MANIFEST_BYTES` |
| key set | exactly the keys the schema declares; an extra or absent key is refused |

```text
document_digest = H("astrolune.release.manifest.v1", exact_document_bytes)
```

`H` is the same length-framed domain-separated BLAKE2s-256 function, and the
detached signature is the same 136-byte `ALRS0001` record, so `cli release-sign`
and `cli verify-release` sign and check these documents unchanged. The signing
domain is therefore shared with release manifests. Type confusion is prevented by
content rather than by domain separation: the three schemas below are pairwise
distinct in their key sets, `MANIFEST.json` carries no `schema` key at all, and
every reader requires both the exact `schema` value and an exact match of the whole
key set before it will read a document as that type, so no one of the four signable
objects can be read as another. A future format version should take its own domain;
this one deliberately does not change frozen cryptography.

`astrolune.release-authority/1`, the identity document:

| Key | Form | Meaning |
| --- | --- | --- |
| `authority_public_key` | 64 lowercase hex | the Ed25519 key this document names |
| `ceremony` | 64 lowercase hex | digest of the transcript that produced the key |
| `not_after` | `YYYY-MM-DDTHH:MM:SSZ` | last instant the key is authoritative |
| `not_before` | `YYYY-MM-DDTHH:MM:SSZ` | first instant the key is authoritative |
| `predecessor` | 64 lowercase hex or `null` | digest of the identity this one rotates |
| `schema` | `astrolune.release-authority/1` | the document type |
| `scope` | object | `artifacts`, `revisions`, `targets` |
| `serial` | integer, 1 or greater | position in the rotation chain |

`scope.targets` is a sorted list of distinct supported native targets.
`scope.artifacts` is a sorted list of distinct plain file names the authority may
sign, `MANIFEST.json` by default. `scope.revisions` is either the string `any` or a
sorted list of distinct full lowercase commit hashes. Timestamps are exactly twenty
characters, UTC, with no fractional seconds and no offset, and are validated by a
round trip rather than a pattern, so an impossible date is refused.
`not_before` must precede `not_after`. Serial 1 must carry a `null` predecessor and
every higher serial must name one.

`astrolune.release-ceremony/1`, the transcript:

| Key | Form | Meaning |
| --- | --- | --- |
| `authority_public_key` | 64 lowercase hex | the key the ceremony produced |
| `custody` | sorted distinct lines | where each copy of the key material is held |
| `date` | `YYYY-MM-DD` | UTC date the ceremony was performed |
| `entropy` | one line | how the seed was produced |
| `hardware` | one line | the machine the ceremony ran on |
| `schema` | `astrolune.release-ceremony/1` | the document type |
| `steps` | ordered lines | every action performed, in the order performed |
| `verification` | ordered lines | every check performed and its observed result |
| `witnesses` | sorted distinct lines | who observed, with their role |

`steps` and `verification` keep the order they were given, because the order of a
procedure is part of the evidence. `custody` and `witnesses` are sets and are
sorted, so the same ceremony recorded twice produces the same bytes. Every list
must be non-empty: a ceremony with no witness, no recorded custody or no performed
check is refused rather than recorded as an unwitnessed one.

`astrolune.release-authority-revocation/1`, the revocation statement:

| Key | Form | Meaning |
| --- | --- | --- |
| `authority_public_key` | 64 lowercase hex | the key being withdrawn |
| `date` | `YYYY-MM-DD` | UTC date of the withdrawal |
| `identity` | 64 lowercase hex | digest of the identity document withdrawn |
| `reason` | `compromise`, `retirement` or `rotation` | why |
| `schema` | `astrolune.release-authority-revocation/1` | the document type |
| `successor` | 64 lowercase hex or `null` | the key that replaces this one |

`.github/scripts/release-authority.py` composes all three from explicit inputs and
verifies them offline, emitting an `astrolune.release-authority-verification/1`
record in the same canonical form. Its Ed25519 verifier is an independent
standard-library implementation of RFC 8032 with `verify_strict` semantics,
matching `crypto::blake2s::ed25519_verify`: a non-canonical key or commitment
encoding, a small-order key or commitment, and a scalar at or above the group order
all fail, and verification is cofactorless. It introduces no dependency, it is not
constant-time, it never reads, derives or holds a secret, and it must never be
given one. The script never signs; signing stays with `cli release-sign`.

These formats establish what a verifier can check offline against a key it already
holds. They establish no mechanism for learning that key, no certificate chain, no
transparency log, no countersignature, no threshold or multi-party policy, and no
automated distribution. `successor` is informational and is never authenticated by
the revocation that names it, because a document that could appoint its own
replacement would let a compromised key appoint an attacker. Nothing in the format
can verify that the custody locations are genuinely separate, that the machine was
genuinely offline, or that the named witnesses exist: the transcript records the
operator's claim and the witnesses' observation, not a fact the tooling checks.

## The release authority key ceremony

The ceremony is performed once per authority key, on a machine disconnected from
every network for its whole duration, with two witnesses present throughout. In
order:

- convene, with both witnesses, the offline machine, and two separately held
  sealable containers;
- generate the key with `cli consensus-vault-create authority.vault`, which takes
  its seed from the operating-system CSPRNG and reads its password from a private
  stdin pipe, so the seed is never written in plaintext and has no export path;
- read the derived public key back and have both witnesses confirm it
  independently against the value the command printed;
- compose the transcript with `release-authority.py transcript`, recording the
  date, the entropy source, the hardware, every custody location, both witnesses,
  every step performed verbatim, and every check performed before signing with its
  observed result;
- compose the identity with `release-authority.py identity`, which binds that
  transcript's digest, the validity window and the scope of targets, revisions and
  artifact names;
- sign the transcript and then the identity with `cli release-sign`, on the same
  machine, before it is reconnected;
- verify both offline with `release-authority.py verify`, supplying the public key
  by hand, and retain the emitted verification record as the ceremony's own
  post-signing check — it is a separate artifact precisely because it cannot be
  inside the transcript it checks;
- have both witnesses read the identity digest aloud and write it down
  independently;
- seal custody, one vault copy per container at the locations the transcript names,
  with each password held apart from the copy it opens; and
- distribute the identity, the transcript and both signatures with the release
  artifacts, and publish the 64-hex identity digest through at least two channels
  under different administrative control.

What is witnessed is the generation, the read-back of the derived public key, and
the identity digest. What is recorded is the signed transcript, the signed
identity, the verification record, and each witness's independent note of the
digest. Where the key material lives is the two sealed containers the transcript
names, with passwords held apart from the vaults they open and no plaintext seed
surviving on the machine.

How the public key reaches verifiers is deliberately split. The identity document
and its signature travel with the artifacts, so a verifier always has the bytes.
The identity digest travels separately, through at least two channels under
different administrative control, so an attacker who controls the host serving the
artifacts does not also control the value a verifier compares against. A verifier
obtains the digest out of band, recomputes `H` over the identity document it
received, compares, and only then trusts the key the document names. A digest
obtained from the same place as the document establishes nothing.

Running this ceremony is still the remaining step. No ceremony has been performed,
no identity document or transcript is committed here, no maintainer or organisation
is named, no public key in this repository is authoritative, and no release has
been published. The procedure establishes no hardware isolation, no non-exporting
signing device, no threshold or multi-party custody, no attestation that the
machine was offline, no monitoring, and no audit; two witnesses are a procedural
control and not a cryptographic one.

## Rotation, revocation and compromise response

Expiry is the routine mechanism. An identity names a bounded window, so a verifier
refuses it at any instant outside that window without having to learn anything new,
and `release-authority.py verify --at` evaluates the window at an explicit instant.

Rotation is a second full ceremony. It produces an identity with the next `serial`
whose `predecessor` is the digest of the identity it replaces and whose
`not_before` is after the predecessor's, and `release-authority.py verify
--predecessor` checks exactly that continuity: the named digest, a strictly
increasing serial, and a later start. That check establishes continuity, not trust:
it never authenticates the predecessor, because a chain that authenticated its own
root would make the out-of-band digest pointless.

Revocation is a signed statement, not a flag. A revocation document names the
identity digest it withdraws and must be signed by the key it withdraws, so a
verifier authenticates it under exactly the key whose authority it ends. A verifier
given a revocation that names the identity in front of it refuses that identity and
reports the date and the reason.

Compromise response, in order: stop signing, and treat every manifest signature
whose distribution overlaps the exposure window as unverified; compose and sign a
revocation with reason `compromise` while the key is still available, and send it
through every channel that carried the identity; run a new ceremony producing a
successor whose `predecessor` names the compromised identity; publish the
successor's digest through the same two independently controlled channels, naming
the compromised digest explicitly beside it; and re-sign anything that must remain
verifiable, because rotation does not make an old signature valid again and nothing
in these formats back-dates or re-dates anything.

The limits are structural and are not closed by this document. Self-revocation
needs the key, so a key that was lost rather than copied cannot be revoked at all;
that case is handled only by publishing a successor and letting the predecessor's
window expire. A verifier sees only a revocation it is given — there is no
transparency log, no revocation list and no online status protocol — so an attacker
who controls the distribution channel can withhold one, which is why the validity
window is bounded rather than open-ended. There is no monitoring that would detect
a compromise, no key-usage record beyond the signing journal's own scope, and no
mechanism that withdraws a signature a verifier has already accepted offline.

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

The ceremony composes its two documents, signs them with the same command, and is
verified offline before the machine is reconnected:

```text
python .github/scripts/release-authority.py transcript --authority-public-key <hex> --date <YYYY-MM-DD> --entropy <source> --hardware <machine> --custody <location> --witness <name and role> --step <action> --verified <check and result> --output release/TRANSCRIPT.json
python .github/scripts/release-authority.py identity --authority-public-key <hex> --transcript release/TRANSCRIPT.json --not-before <instant> --not-after <instant> --serial 1 --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-msvc --output release/AUTHORITY.json
cli release-sign release/TRANSCRIPT.json authority.vault release/TRANSCRIPT.json.sig
cli release-sign release/AUTHORITY.json authority.vault release/AUTHORITY.json.sig
python .github/scripts/release-authority.py verify --authority-public-key <hex> --identity release/AUTHORITY.json --identity-signature release/AUTHORITY.json.sig --transcript release/TRANSCRIPT.json --transcript-signature release/TRANSCRIPT.json.sig --output release/VERIFICATION.json
```

A verifier checks a manifest against the identity rather than against a bare hex
key, which is what binds the signature to a scope and a window instead of only to
a holder. Rotation adds `--serial`, `--predecessor` and the predecessor's own
document; revocation is composed with `revoke` and supplied to `verify`:

```text
python .github/scripts/release-authority.py verify --authority-public-key <hex> --identity release/AUTHORITY.json --identity-signature release/AUTHORITY.json.sig --transcript release/TRANSCRIPT.json --transcript-signature release/TRANSCRIPT.json.sig --manifest target/ci-artifacts/MANIFEST.json --manifest-signature target/ci-artifacts/MANIFEST.json.sig --at <instant>
python .github/scripts/release-authority.py revoke --authority-public-key <hex> --identity release/AUTHORITY.json --date <YYYY-MM-DD> --reason compromise --output release/REVOCATION.json
```

On 2026-10-07 the anchor and release commands acquire exclusive file locks, so a
running validator must be stopped before `verify-signing-anchor` is used, and that
command completes an interrupted anchor update rather than being purely read-only.
Anchored signing is part of the daemon's startup path: `--signing-anchor PATH` is
declared and parsed in `apps/daemon/src/options.rs`, which rejects it without
`--validator-key` and its existing journal, and `apps/daemon/src/network/role.rs`
selects `DurableSigner::open_with_anchor` when the option is present and
`DurableSigner::open` when it is not. Neither path provisions or recreates a
journal or an anchor; selecting a voting role is open-only, so a journal behind its
anchor fails closed at startup rather than being repaired. An earlier statement
here that the daemon had no anchor option and still opened journals only through
`DurableSigner::open` was true when written and is no longer.

Release key handling is now defined above. Operator procedure for a detected
rollback and for identity fencing is still not defined here.

## Verification

On 2026-10-07, on Windows 11 Home 10.0.26200 with Rust 1.99.0 and Python 3.11.9,
`cargo test -p keystore -p cli` and
`python -B -m unittest discover -s .github/scripts -p 'test_*.py'` pass.

On 2026-10-10, on the same host and Python version, that discovery run passes 125
tests, including the 34 release-authority tests described below. No Rust build was
run on that date, so the Rust-side claims above remain dated 2026-10-07.

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

Release-authority coverage is 34 tests in
`.github/scripts/test_release_authority.py`. The independent Ed25519 verifier is
checked against all four RFC 8032 section 7.1 vectors for key derivation, signing
and verification, against every one of the 64 single-bit mutations of one vector's
signature, and against a mutated message, a foreign key, the order-1 point, a
y-coordinate above the field prime, a scalar at the group order, and every wrong
length; every decoded point is required to re-encode to its own bytes. The
framing is pinned by a frozen digest vector and by refusal of a short, long,
empty or wrongly magicked signature. Document coverage refuses a reversed or empty
validity window, an offset or fractional instant, an impossible calendar day, a
zero serial, serial 1 naming a predecessor, a higher serial naming none, an
unknown or absent target, an unusable artifact name, an uppercase or short key, an
unsorted or non-distinct list, a transcript with no witness, custody entry, step
or check, an unknown revocation reason, and a key naming itself as its own
successor. Verification coverage establishes that a complete signed ceremony
trusts the right key and refuses a foreign one, that a signature from another
holder is refused, that an edited identity cannot keep its signature, that
four-space, compact, unsorted, newline-free and CRLF bytes are refused before any
signature is examined, that a foreign schema and an altered key set are refused,
that a transcript from another ceremony or naming another key breaks the binding,
that both window edges are inside and one second beyond either is outside, that a
manifest is checked against the identity's scope and refused outside it, that a
self-revocation withdraws the authority while a revocation of another identity
withdraws nothing, and that a rotation must name its predecessor's digest,
increase the serial and begin later. The seeds are published RFC 8032 vectors; the
signing side lives in the test file, so the script that verifies an authority
contains no code that could use a secret.

No ceremony has been performed, no identity document or transcript is committed,
no independent audit, no hardware-backed test, no power-loss test, no multi-host
anchor-separation test and no published release exist. Nothing here establishes a
maintainer identity or a production release.
