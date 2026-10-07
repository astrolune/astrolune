<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 40. Live VRF rotation for a closed network

Genesis version **2** explicitly activates the rotating consensus profile. Version
1 retains its original fixed membership and canonical encoding. The runtime version
is independent: set `runtime_version = 2` to activate contracts in either profile.
Changing genesis creates a different network identity; existing histories and
signing journals are never silently converted.

For a local fixture network:

```sh
cargo run -p cli -- devnet target/rotating-network 4 --vrf --contracts --observer
```

The generated `START.txt` contains process commands. With four registered
validators this creates three rotating seats and one replacement per finalized
block. Height one uses the complete roster to authenticate the first selection.
A one-validator fixture retains one seat. All generated consensus/wallet seeds
are the existing public test fixtures.

## Availability and standby

Every registered validator supplies both role-separated proofs, including a
validator that currently has no voting seat. The daemon obtains proofs from its
protected, non-exporting signer. Proof generation binds chain, genesis, target
height, epoch and round and does not reserve a proposal or vote in the journal.

The bounded gossip message carries the current height and one 280-byte
contribution. A pool accepts at most one verified contribution per registered
identity. Repeated valid messages are idempotent; stale, foreign, malformed or
conflicting messages cannot replace valid entries. The complete batch enters the
reserved system transaction and the resulting committee is part of finalized state.

The closed-network availability policy requires the **entire registered roster**
to remain online. Missing proofs pause fresh production; there is no subset lottery,
new seed, timeout exclusion or fixed-committee fallback. Reconnection resumes
collection. Existing valid proposals and certificates may still complete. This
policy trades offline-validator availability for deterministic complete-roster
selection. Registration changes and active PoTB weights are separate work.

A standby node keeps its protected journal, relays transactions and contributions,
and authenticates/re-executes finalized blocks. It does not issue proposals or
votes while outside the committee. A finalized transition alone can return it to
voting. The round-zero proposer is VRF-selected; later rounds walk the committed
seat order. Existing BFT locks, journal reservations and durable available-value
rules still apply.

Validators and observers recover from independently supplied genesis by checking
old quorums and replaying system/application execution. Persisted committee bytes
cannot bootstrap authority. Stored equivocation proofs are checked against their
historical committee. Fixed-profile verifiers refuse rotating authority after
bootstrap instead of treating the original roster as the active committee.

## Persisted handoffs and RPC

Rotating commits atomically retain the next-committee membership witness with
receipts, block, certificate and state delta. `ALEFF002` adds this bounded witness;
records without it preserve the exact original `ALEFFECT` bytes. Both formats can
be read. Old records lacking a witness return unavailable rather than inventing one.

`committee_handoff` accepts a decimal `height` (string or nonnegative integer) and
returns one canonical `ALHAND01` bundle as hexadecimal, or `null` when unavailable.
The server reads retained block metadata without replaying the chain on each query.
Local corruption discovered through this read stops validator signing as other
history-read corruption does. Neither a successful RPC response nor `null` establishes
committee authority or authenticated absence.

`TcpRpcClient::advance_handoffs` verifies a sequential stream from the caller's
`HandoffVerifier`, with explicit step and whole-operation time limits. Its target
is the height of the next header to verify. To authenticate a proof at height H,
apply handoffs 1 through H-1, then verify that proof with `verify_with_handoffs`.
Only fully authenticated progress survives a failed request; callers can resume
from that prefix. Skipped/replayed heights, changed ancestry, insufficient old
quorums, incomplete VRF batches and incorrect state witnesses are rejected.

## CLI and DNS

State-proof, receipt and finality-wait commands automatically select the profile
from trusted genesis. For rotating proofs they fetch at most 10,000 transitions
under a 60-second history deadline, authenticate the proof, and save a
`<proof-file>.handoffs` sidecar. Verification commands read this sidecar offline.
Keep the two files together. `ALHIST01` binds the sidecar to genesis and target
height; each length-prefixed handoff is bounded and verified before advancing.
Truncation, trailing bytes and substituted anchors fail verification. Existing
files are not overwritten. Genesis-only state proofs need no sidecar.

The DNS resolver checks both registry code and record proofs through the same
handoff stream. It retains verified authority and the accepted freshness floor
between requests, limits history catch-up to 10,000 transitions per proof under a
shared 30-second deadline, and rejects rollback, mismatched code and invalid records.

## Qualification

Tests exercise a withheld contribution, resumption, multiple seat changes, standby
exit/re-entry, payment finality, stale proofs, validator and observer restart,
both storage backends, failed publication and exact legacy-format encoding.
A real four-validator mutual-TLS process test verifies handoff RPC, certified state,
observer catch-up and restart of all roles. CLI tests fetch state/receipt proofs
and verify their sidecars offline, including truncation and anchor substitution. Evidence commands use the same
verified history to authenticate double votes at their actual committee height;
[operator usage](25-potb-evidence.md#operator-commands).
DNS tests cover initial catch-up, authority reuse and rollback rejection.

The shared mutation oracle includes the new gossip message, version-2 genesis and
version-2 receipt metadata, for 16 structured seeds. These tests establish the
implemented closed-network profile, not a formal distributed liveness proof or
independent cryptographic review.

## Repeated verification cost

Each producer retains at most one fully verified VRF batch and its computed next
committee. Only an exact batch match in the same current committee reuses the
result; all other batches take the complete verification path. Incoming proposals,
valid-value restoration, finalized imports and recovery prepare this cache before
repeated execution. Successful finalization clears it. Invalid replacements cannot
destroy a previously verified entry. Neither cache preparation nor cache reuse
publishes state, grants authority or bypasses execution/header/certificate checks.

The equivalence test compares cached and uncached execution, rejects changed
proofs, parent and height, checks failed replacement and prevents cross-height
reuse. `cargo test -p node --test rotation --release measure_verified_transition_cache
-- --ignored --nocapture` measures 20 mixed payment/contract blocks in both paths.
On this Windows host with Rust 1.98.1, the release run took 36,816 microseconds for
revalidation and 9,437 microseconds with reuse; the debug run took 4,531,273 and
234,259 microseconds. These are local execution measurements for that fixture,
not network throughput or a portable performance guarantee. All nine real mutual-TLS
process tests then passed together in debug in 22.38 seconds.

Stored double-vote proofs are sorted by height at recovery and authenticated through
one shared historical handoff stream. At most 32 proofs are retained; the change
avoids verifying the same prefix separately for each proof. Tests include different
rotating committees and a corrupt signature that must prevent recovery.
