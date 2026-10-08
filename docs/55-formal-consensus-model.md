<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 55. Bounded formal model of fixed-height voting

`crates/consensus/tests/formal_model.rs` explores every reachable state of the
fixed-height `BFT` voting rules inside explicit bounds on validators, rounds and
candidate values. Exploration is a depth-first traversal with a visited set, so
the reported state, transition and terminal counts are exact for a bound that
holds, and the first property violation stops the search with its search stack as
the counterexample trace. This is bounded model checking of a hand-written
transition relation; it is not a proof and not a mechanical extraction of the
implementation.

## Modelled rules

The model re-encodes the transition rules of `LocalBft`: the proposer lock rule,
the prevote lock rule, the nil-vote and timeout transitions, and the round advance
that preserves a held lock. Derived quantities are taken from the production code
rather than restated. `Model::new` resolves the quorum through
`AuthenticatedCommittee::quorum` and asserts it equals `quorum_power(total)` for
that bound, and resolves each round's designated seat through
`round_robin_proposer`. Weights are integers and no floating point participates in
any decision.

Two delivery regimes are modelled. `Asynchronous` permits any interleaving,
including permanently withheld messages. `EventualSynchrony` delivers every honest
message once the regime begins. Two adversaries are modelled. `Silent` omits,
which is the crash-fault case. `MaximalEquivocation` signs inconsistently with the
full weight of the Byzantine seats. Byzantine seats hold no modelled local state,
because a Byzantine operator holds exactly the seat key and nothing else; their
votes and proposals are signed directly with that key when a certificate the model
claims to exist is constructed.

A validator set, its weights, the Byzantine seats, the candidate-value count, the
round count, the regime and the adversary form one `Bound`. The model never
explores outside a bound, and a bound is named in every reported line so a result
can be reproduced exactly.

## Properties and bounds

| Property | Statement |
|---|---|
| Agreement | No two distinct values are ever committed at this height |
| Lock safety | No honest validator prevotes a conflicting value without a strictly newer prevote certificate, and the durable lock survives nil votes and round advances |
| Quorum lock safety | A finality certificate is never followed by a conflicting prevote certificate |
| Validity | Every committed value was proposed by that round's designated proposer |

Accountability is expressed as a threshold rather than as a separate property.
Two quorums intersect in more than `2 * quorum - total` weight, so conflicting
certificates require at least that much equivocating weight, and every signature
in both quorums is authenticated and therefore attributable. The suite checks both
directions of that threshold: below it the properties hold over the whole
reachable space, and at it a conflicting certificate must become reachable.

On 2026-10-08, Windows with Rust 1.99.0 in release explored the ordinary bounds:

| Bound | Quorum | Equivocating | Threshold | States | Transitions | Terminal | Result |
|---|---|---|---|---|---|---|---|
| `uniform-async-v4-f1-k2-r2` | 3 of 4 | 1 | 2 | 419,926 | 1,149,994 | 48,061 | no violation |
| `weighted-async-v4-f1-k2-r2` | 5 of 7 | 1 | 3 | 229,084 | 625,930 | 24,925 | no violation |
| `accountable-async-v4-f2-k2-r2` | 3 of 4 | 2 | 2 | 32 | 31 | 14 | quorum lock safety violated |
| `live-sync-v4-f1-k2-r2-silent` | 3 of 4 | 0 | 2 | 86 | 158 | 2 | decided at round 1 |
| `live-sync-v4-f1-k2-r2-equivocating` | 3 of 4 | 1 | 2 | 367 | 774 | 38 | decided at round 0 |
| `live-sync-weighted-v4-f1-k2-r2` | 5 of 7 | 0 | 3 | 120 | 232 | 6 | decided at round 1 |

The counterexample reported at the threshold is a legal honest round change
combined with the equivocating weight, not an implementation defect:

```text
    0: Prevote { validator: 0, value: 0 }
    1: Precommit { validator: 0, value: 0 }
    2: Finalize { validator: 0, value: 0 }
    3: Prevote { validator: 1, value: 0 }
    4: TimeoutPrevote { validator: 1 }
    5: TimeoutPrecommit { validator: 1 }
    6: Prevote { validator: 1, value: 1 }
```

Validator 1 issues a nil precommit, so it never locks, and may prevote a different
value after the round advance. Only the two equivocating seats sign both values,
which is the attributable offence the threshold predicts.

The asynchronous bounds reach terminal states with no certificate. That is the
regime, not a defect: no bounded exploration of an asynchronous run can decide,
and the suite asserts a decision only under eventual synchrony.

## Conformance with the production voter

A model that silently diverges from the implementation establishes nothing about
the implementation. `modelled_transitions_agree_with_the_production_local_bft`
drives bounded random walks of the modelled transition relation through the real
`LocalBft` over real protected `DurableSigner` journals in a temporary directory,
with real Ed25519 signatures and independently verified certificates. After every
transition it asserts that the production round, step and durable lock equal the
modelled ones. On 2026-10-08 that checked 238, 238 and 134 production transitions
for the three bounds it covers.

The forbidden direction is exercised where the production API can express it: a
modelled nil prevote prefers a lock-forbidden proposal over the timer, so the
production prevote lock rule decides the nil rather than the harness assuming it.
Transitions the model forbids outright are not enumerable through the same API,
because the model never offers them; the hand-written rejection cases in
`crates/consensus/tests/local_bft.rs` and `durable_votes.rs` remain the coverage
for those, including `ConflictingSign` on an attempted equivocation.

## Running the checks

```text
cargo test -p consensus --test formal_model
cargo test --release -p consensus --test formal_model -- --ignored --nocapture
```

The ordinary suite runs the six bounds in the table and the conformance walks. The
extended campaign raises the round bound to three and adds a five-seat and a
three-value bound at two rounds, asserting the same threshold condition on each.

State counts grow sharply with the round bound. On 2026-10-08 in release, the
three-round uniform bound reached 63,066,629 states over 177,717,618 transitions
with 7,565,405 terminal states in 126 seconds and no violation, and the three-round
weighted bound reached 29,386,445 states over 82,948,690 transitions in 60 seconds
with no violation. A four-round asynchronous bound did not complete on that
machine, because the visited set for an exhaustive traversal at that depth exceeds
available memory; four-round exploration therefore remains outside the recorded
evidence rather than being claimed.

## Limits

This is bounded model checking, never a proof. Every result holds only inside the
stated bounds on validators, rounds, candidate values and message reordering;
nothing here establishes a property for an unbounded validator set, an unbounded
round count or an unbounded value space. The round bound is limited by memory
rather than by choice: an exhaustive visited set at four rounds did not fit on the
machine used. The transition relation is hand-written from the documented rules and
conformance-tested against the implementation at sampled transitions, so divergence
outside those samples is possible.

The model covers one height. Committee rotation, `PoTB` weight transitions,
admission, governance and handoff are outside it; delivery-fault behavior across
heights is covered separately by the
[rotating network delivery simulations](46-rotating-network-simulations.md).
Liveness is bounded-round decision reachability under an eventual-synchrony
regime, not an unbounded liveness argument and not a partial-synchrony timing
calibration. Timeout durations, clock skew and real network behavior are not
modelled.

No theorem prover, model-checking toolchain or solver is used, and none is a
dependency. Mechanical extraction of the transition relation from the
implementation, unbounded liveness, partial-synchrony calibration and independent
review of this model remain open.
