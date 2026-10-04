<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 1. PoTB Consensus and Fast Finality

## 1.1 Separation of responsibilities

PoTB determines effective validator weight. Weighted VRF sampling uses that weight to select a committee and producer. BFT finality fixes one transaction order. The execution engine separately verifies the resulting state transition.

These responsibilities MUST remain separate interfaces. A faster executor cannot gain consensus weight, a producer cannot commit unverified adaptive measurements, and the consensus state machine must not depend on worker scheduling.

Validator participation is open to operators who satisfy the network's hardware and protocol requirements. Mainnet targets powerful validators: a minimum of 12 CPU cores at 2.8 GHz or higher, 128 GB RAM, and 1 TB NVMe storage; the recommended configuration is 24 cores at 2.8 GHz or higher, 256–512 GB RAM, and 2 TB NVMe. Testnet and local development have a separate minimum of 8 cores, 16 GB RAM, and 50 GB free disk space. See [validator requirements](07-validator-requirements.md) for deployment profiles and calibration. Hardware establishes an operating baseline; it does not directly increase PoTB weight, selection probability, or voting power.

## 1.2 PoTB weight

Each epoch derives an effective non-negative fixed-point weight from finalized evidence:

```text
effective_weight = policy(time_score, behavior_score, trust_score, penalties, caps)
```

Exact scoring constants remain subject to simulation, calibration, governance rules, and independent security review. Weight computation MUST use checked integer or specified fixed-point arithmetic. A tie MUST be resolved by canonical validator identity bytes.

PoTB is an anti-Sybil heuristic, not a proof that coordinated ownership is impossible. Time, trust graphs, network diversity, and correlation analysis can all be manipulated. Documentation and user interfaces MUST not claim otherwise.

## 1.3 Weighted VRF committee selection

For each height, eligible validators evaluate a VRF over a domain-separated input containing at least:

```text
chain_id || epoch || height || parent_finality_randomness || role
```

A proof is valid only when it verifies under the registered validator key and exact protocol domain. Eligibility probability is proportional to effective PoTB weight. Selection MUST:

1. verify every VRF proof;
2. reject zero-weight, banned, duplicate, and ineligible identities;
3. rank eligible outputs with a specified weighted transformation using integer arithmetic;
4. use canonical identity bytes as the final tie-breaker;
5. select without replacement;
6. commit the selected committee and weights in consensus data.

The implemented suite is RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI with complete-roster, weighted sampling without replacement. Canonical proofs, context domains, unbiased rejection sampling and rotation are specified in [document 28](28-vrf-and-weighted-selection.md). Genesis-v2 daemon activation is specified in [document 40](40-live-vrf-network.md); independent review remains separate work.

## 1.4 Partial rotation

The active committee persists across heights. At each height, a deterministic replacement count is computed from the configured rotation ratio, initially approximately 10%. Retained members preserve continuity; replacement seats come from current weighted VRF results.

Safety rules:

- rotation is computed from finalized parent state only;
- no identity occupies more than one seat;
- the outgoing committee finalizes the transition to the next committee;
- committee roots are included in proposal and vote signing bytes;
- parameter changes activate only at an epoch boundary after finalization.

Ten percent is a starting target, not a production constant. Tests must evaluate churn, overlap safety, liveness, and adversarial weight concentration.

## 1.5 Producer selection and pipelining

The producer is selected from the active committee with a separately domain-separated VRF role. While height `h` is voting, eligible producers may prepare height `h + 1` using the latest safe snapshot and mempool view. Preparation is speculative: it MUST be discarded or replayed if the finalized parent, capacity, committee, or transaction order differs.

No proposal for `h + 1` becomes vote-eligible before `h` is finalized. Pipelining saves preparation time; it does not relax height ordering.

## 1.6 Fast BFT finality

Each height may contain multiple timeout-driven rounds. A round has:

1. **proposal** — the designated producer publishes an ordered block proposal;
2. **prevote** — members vote for a valid proposal or nil;
3. **precommit** — members lock after observing a prevote quorum and vote for the locked block or nil;
4. **finalize** — a valid precommit certificate makes the block irreversible.

A quorum is voting power strictly greater than two thirds:

```text
quorum(total) = floor(2 * total / 3) + 1
```

Votes bind chain, height, round, phase, block hash or nil, and committee root. A node MUST persist anti-equivocation decisions before transmitting a proposal, prevote, or precommit. Two different signed values for the same identity, height, round, and phase form slashable evidence.

Lock, unlock, timeout, and certificate rules need a dedicated normative state-machine specification before production implementation.

## 1.7 Consensus/execution decoupling

Consensus validates proposal structure, availability, transaction identities, declared resource bounds, and ordering. It need not wait for all local execution optimizations before exchanging votes, but a node MUST NOT finalize or commit a state root it cannot verify.

The proposal commits:

- ordered transaction root;
- parent state root;
- expected post-state and receipt roots;
- resource usage and active capacity;
- active committee root.

Execution operates against an immutable parent snapshot and produces receipts plus state diffs. The commit stage publishes diffs only after the BFT certificate and execution commitments both validate.

## 1.8 Pipeline

Stages overlap across heights:

```text
height h:     propagation -> prevote -> precommit -> execution check -> commit
height h + 1:              prepare/reconstruct -> speculative execution
height h + 2:                                   transaction prefetch
```

Implementations may overlap execution earlier when safe. The externally visible rule remains simple: transaction order comes from consensus, execution results come from deterministic validation, and canonical state changes only in the commit stage.

## Implemented authentication boundary

[Version-1 vote and certificate formats](15-authenticated-finality.md) implement committee commitments, registered Ed25519 verification, isolated round/phase accounting, and independent weighted precommit quorum verification. The [local BFT guard](17-local-bft-voting.md) implements prevote/precommit locks and timeout events, persisting lock metadata and signing decisions atomically through a protected [durable journal](16-durable-signing.md). [Signed proposal authentication](18-signed-proposals-and-participants.md), monotonic timers, and a reference round-robin participant operate in the [certified fixed-committee network](19-reference-network.md). The separate default local demonstration mode still simulates finality. [Double-vote evidence and experimental PoTB scoring](25-potb-evidence.md) are implemented and tested. The separate [live PoTB profile](45-live-potb-network.md) activates canonical evidence inclusion, capped age weights and incumbent-quorum admission; the offline scoring workbench does not change those rules. Verified weighted VRF selection and explicit genesis-v2 rotating committee activation are implemented; a proof of distributed liveness remains open. Membership must come from trusted finalized state. The demonstration sampler is not a verified weighted VRF implementation.

## 1.9 Safety assumptions and open work

The baseline does not prove PoTB anti-domination, sampler fairness, BFT safety under rotating weighted committees, or liveness under partial synchrony. [Bounded delivery-fault simulations](46-rotating-network-simulations.md) cover both rotating profiles. Required work includes formal modeling, broader Byzantine/churn simulations, VRF selection analysis, persistent anti-double-sign testing, timeout calibration, and independent review.
