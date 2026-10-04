<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 45. Live PoTB reference network

The explicit [PoTB policy profile](44-potb-state-transitions.md) is connected to
daemon startup, protected validator provisioning, contribution and inclusion
gossip, durable handoff serving, RPC, offline CLI verification and the DNS resolver.
Its configuration commitment identifies the network. Genesis-v1 and genesis-v2
keep their existing encodings and execution rules; data directories are not migrated.

## Provisioning

```text
cli devnet potb-devnet 4 --potb --observer --contracts
```

The generated `START.txt` contains each daemon command. This creates public test
consensus/wallet seeds, independent random TLS identities, a funded wallet and
protected journals. `--potb` and `--vrf` are mutually exclusive. The PoTB devnet
policy starts at weight 1, increments once per 100 finalized active blocks and
caps weight at 100. Four initial validators rotate three voting seats.

Operators can wrap an independently reviewed genesis-v2 configuration instead:

```text
cli potb-config genesis-v2.bin 100 1 1 100 potb.bin
cli init-validator potb.bin validator.seed node-data
daemon --genesis potb.bin --validators validators.bin --validator-key validator.seed --data-dir node-data --tls-dir tls --run
```

The four policy arguments are epoch length, initial weight, age increment and
maximum weight. Initial genesis weights must equal the policy's initial weight.
Configuration/provisioning outputs are never overwritten. `--genesis` recognizes
the explicit `ALPTCF01` envelope; local demonstration mode does not accept it.
An observer uses the same public anchors and `--observer`, with no consensus seed.

`validators.bin` remains the **initial** exact public-key registry. Newly admitted
keys are authenticated by finalized transitions, without rewriting that registry.
A PoTB signer outside the roster can start with a separately provisioned protected
journal and synchronize as a standby candidate. It supplies no votes or VRF proofs
until finalized authority permits them. Excluded identities stop contributing.
TLS membership and peer routes still require independent operator provisioning.

Every eligible roster identity, including registered standby validators, must
supply both VRF proofs. A missing proof pauses fresh production; no different
roster is substituted. An offender's contribution is still required for the block
that excludes it. This availability policy does not solve adversarial withholding.

## Admission and evidence

Admission commands accept an explicit PoTB configuration as their genesis argument:

```text
cli admission-request potb.bin validators.bin candidate.seed HEIGHT request.bin RPC
cli admission-inspect potb.bin validators.bin request.bin
cli admission-approve potb.bin validators.bin request.bin validator.seed node-data/signing.journal approval.bin
cli admission-assemble potb.bin validators.bin request.bin certificate.bin approval-a.bin approval-b.bin approval-c.bin
cli admission-verify potb.bin validators.bin request.bin certificate.bin
cli admission-submit potb.bin validators.bin request.bin certificate.bin RPC
```

`HEIGHT` is the inclusion height immediately after the finalized parent. Approvals
remain explicit operator actions against authenticated history. The request's
`.handoffs` sidecar must accompany it for offline inspection and approval. Ordinary
votes and RPC submission do not create admission approvals.

To include a saved double-vote proof from a node's `equivocation` outbox:

```text
cli potb-evidence potb.bin validators.bin double-vote.bin HEIGHT historical-evidence.bin RPC
cli potb-submit-evidence potb.bin validators.bin historical-evidence.bin RPC
```

Preparation authenticates the handoff prefix, captures the offence committee and
constructs its membership path against the requested parent frontier. Work is
bounded to 10,000 transitions. Submission independently verifies the current frontier.

Admission binds an exact parent/height; evidence binds an exact history frontier.
**Pending acceptance is not finality.** If another block wins first, prepare fresh
evidence or collect new consent and approvals. CLI/RPC never automatically re-sign
or retry a stale submission.

Validators retain one pending admission per candidate and one offence per registered
identity. Queues are saved in the consensus cache, revalidated on restart and cleared
on a finalized height change. Expired entries grant no authority. The 32-identity
lifetime registry limit remains in force.

Fresh batches select evidence first and admissions second, each in canonical identity
order. Selection checks policy, surviving committee size, block resources and the
unchanged 64 KiB network transaction limit. An item that does not fit is skipped; it
cannot prevent a valid empty policy transition. Inclusion requires old-quorum finality.
Observers serve finalized history/proofs; pending inclusion uses validator endpoints.

## Wire, storage and clients

The bounded `ALNX` exchange adds blob tag 6 for `AdmissionCertificate` and tag 7 for
`HistoricalEvidence`. Existing tags retain their exact bytes. Namespace and activated
profile are checked separately from decoding. Messages are authenticated before relay.

Storage effects use new tag `ALEFF003` for receipts, genesis membership and a PoTB
next-state witness. `ALEFFECT` and `ALEFF002` bytes are unchanged. Legacy committee
and PoTB witnesses are mutually exclusive. PoTB values are bounded at 7,509 bytes,
encoded witnesses at 12,288 bytes; validation requires the reserved key and the
same certified root. The witness shares the atomic block/certificate/delta commit.

`read_potb_handoff` checks one retained block/effects record and reconstructs its
portable transition. Missing witnesses mean unavailable; legacy metadata is never
reinterpreted. Recovery independently authenticates and executes the complete history.

| RPC method | Input | Result |
|---|---|---|
| `potb_handoff` | exact finalized `height` | canonical handoff hex, or unavailable `null` |
| `submit_potb_admission` | certificate hex in `data` | pending request identifier |
| `submit_potb_evidence` | historical evidence hex in `data` | pending offence identifier |

Decoders bound each envelope and distinguish submission methods. Local storage/cache
failures stop the daemon. These methods use the existing RPC exposure policy.

`TcpRpcClient::advance_potb_handoffs` and its consumer variant authenticate each
transition from independent configuration, under a step count and total deadline.
Wrong heights, parents, quorums, proofs or missing transitions stop the stream.
Only the accepted prefix remains on failure; consumer failure leaves its transition
unapplied. Decoded state cannot bootstrap authority.

State/receipt proofs use authority **for their header**, before applying that header's
own transition. Genesis-only proofs separately reconstruct initial PoTB state. CLI
commands save bounded streaming sidecars with distinct `ALPTHIS1` headers and verify
them offline. Wrong anchors, truncation, trailing data and missing sidecars fail.
History verification/export preserves the explicit configuration and observer namespace.

DNS advances PoTB authority before checking code and name proofs. It retains authority
and its freshness floor only after both proofs pass, rejecting rollback.

## Verification scope

Tests cover five participants with a candidate, admission, exclusion, full-roster
availability, changed weights, cache restart, observer catch-up and role recovery.
A single-member regression covers restoring pending inclusions after proof collection.
Independent daemon processes exercise TLS, payments, handoff RPC and both-role restart.
Additional tests cover pending RPC, hostile handoffs, client failure atomicity,
offline CLI proofs/approvals, DNS rollback and exclusive storage witnesses.

The mutation oracle adds both gossip envelopes and PoTB effects, bringing its
structured corpus to 81 inputs. The original 50 legacy and eight PoTB policy fixtures
remain unchanged. On 2026-10-04, Windows with Rust 1.99.0 passed the complete workspace
test suite, strict Clippy, rustdoc, formatting and standalone fuzz-target compilation.
Twelve focused release tests covered the network, daemon, RPC, CLI, DNS and storage
boundaries. All seven independent Python fixture/archive tests passed. The release
campaign passed one million mutations with 293,326 accepted decoder paths.

[Hostile delivery schedules](46-rotating-network-simulations.md) additionally exercise
both rotating profiles. These bounded checks do not establish formal liveness or
independent security review.
