<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 43. Quorum admission authorization

The selected private-network admission rule is implemented as an independently
verifiable authorization: **strictly more than two thirds of the incumbent
committee's voting power** must explicitly approve a candidate. Signatures from
registered standby validators do not contribute power. A block precommit, a
candidate signature or one administrator's permission cannot replace this quorum.

The request, protected approval, certificate and operator CLI are implemented and
tested. Genesis versions 1 and 2 do not execute admission certificates. The
[separate PoTB producer profile](44-potb-state-transitions.md) implements canonical
system-lane inclusion and active weight/roster transitions. [Live activation](45-live-potb-network.md)
adds candidate provisioning, bounded gossip and explicit RPC submission. Existing
profiles are not silently reinterpreted.

## Signed context

`AdmissionIntent` binds chain ID, genesis commitment, exact inclusion height,
finalized parent, incumbent weighted committee root and candidate public key.
The candidate signs a separate consent domain, proving possession of a strong,
canonical Ed25519 key. Each incumbent signs a second domain containing the complete
signed request commitment and its own validator identity. All signatures use the
existing strict Ed25519 verification rules.

The candidate must be absent from the entire registered roster, including standby
members. The roster must have room under the current 32-identity bound. Requests
cannot select a custom initial weight or grant themselves accumulated membership
age; those values belong to the future activated policy. Terminal u64 heights,
zero coordinates, weak keys, foreign forks and changed genesis are rejected.

Authorization applies only to the exact stated parent and inclusion height. It is
not a reusable permission or evidence that this height is still the live head.
Operators can prepare it at an agreed maintenance height. Future execution must
compare it with its own finalized state, enforce available roster space across all
included requests and publish membership only after finality. Candidate consent
does not demonstrate that the candidate's daemon or transport endpoint is online.

## Canonical envelopes

| Object | Tag | Encoded size |
| --- | --- | --- |
| Signed candidate request | `ALADRQ01` | 212 bytes |
| Detached incumbent approval | `ALADAP01` | 136 bytes |
| Request plus ordered approvals | `ALADCT01` | at most 3,293 bytes |

The certificate stores at most 32 distinct approvals in increasing validator-ID
order. Assembly accepts arbitrary arrival order, but duplicate approvals fail.
Decoders reject alternate ordering, count/body mismatches, oversized inputs,
truncation and trailing data before allocating the approval collection. All
signatures are checked, including surplus signatures after quorum is reached.
Decoding alone does not authenticate membership or establish freshness.

## Protected operator signing

`DurableSigner::approve_admission` keeps key material non-exporting and requires an
existing protected journal. It checks candidate consent, chain/genesis namespace,
the signing watermark, and any recorded committee at the same height. The
consensus wrapper additionally verifies the independently authenticated incumbent
committee and rejects outsiders before requesting a signature.

Admission approval is an explicit operator action, not an automatic consequence
of receiving a valid request. It neither reserves a BFT vote nor modifies the
consensus journal. Approving several candidates is permitted; signatures alone
cannot finalize conflicting blocks or install a committee. Opening a validator's
journal remains exclusive, so the offline CLI requires its daemon to release that
journal. It does not create or substitute a fresh journal to bypass an existing lock.

## CLI workflow

```text
cli admission-request genesis.bin validators.bin candidate.seed 3 request.bin 127.0.0.1:17331
cli admission-inspect genesis.bin validators.bin request.bin
cli admission-approve genesis.bin validators.bin request.bin validator-a.seed signing-a.bin approval-a.bin
cli admission-approve genesis.bin validators.bin request.bin validator-b.seed signing-b.bin approval-b.bin
cli admission-approve genesis.bin validators.bin request.bin validator-c.seed signing-c.bin approval-c.bin
cli admission-assemble genesis.bin validators.bin request.bin certificate.bin approval-a.bin approval-b.bin approval-c.bin
cli admission-verify genesis.bin validators.bin request.bin certificate.bin
```

The number of required approvals depends on trusted voting power, not on this
example's number of files. Request creation authenticates a sequential handoff
stream from the supplied genesis and saves `request.bin.handoffs`. Subsequent
commands use that sidecar offline, with the existing 10,000-transition bound.
Keep the request, certificate and sidecar together. Missing or corrupt history
fails closed. Candidate creation accepts a raw seed or encrypted wallet vault;
validator approval uses the existing raw-seed/protected-journal custody path.
Seed bytes and vault passwords are never command-line arguments.

All output files are created exclusively. Insufficient quorum, duplicate approvals,
wrong membership and invalid history produce no approval/certificate output. The
CLI explicitly reports that authorization has not been included or activated.

## Qualification

Tests exercise unequal weights, exactly two thirds, headcount majorities with
insufficient power, standby/outsider exclusion, full rosters, all certificate
truncations and one-bit mutations, duplicate/foreign requests and surplus corrupt
signatures. Protected signing tests cover journal recovery, unchanged journal
bytes, namespace isolation, stale watermarks and same-height committee conflicts.
A real CLI test obtains two certified handoffs, creates a request, signs with
protected journals and assembles/verifies the quorum entirely offline afterward.

The shared mutation oracle includes the intent and all three envelopes. The
71-seed, one-million-input deterministic campaign passed with 299,954 accepted
decoder paths. This historical count is not coverage-guided fuzz coverage.
The later live PoTB qualification is recorded in [document 45](45-live-potb-network.md).
