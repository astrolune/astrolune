<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 46. Rotating network delivery simulations

`crates/node/tests/adversarial_rotation.rs` drives four actual `NetworkNode`
instances through deterministic hostile delivery schedules. Each uses its own
chain storage, protected signing journal and consensus cache. The same scenarios
run against [genesis-v2 rotation](40-live-vrf-network.md) and the explicit
[PoTB profile](45-live-potb-network.md), with four registered contributors,
three voting seats after the initial height and one replacement per transition.
PoTB weights advance through the configured age epochs.

## Schedule and oracle

The scheduler uses a fixed xorshift seed and a logical 20-millisecond tick. It
controls message delivery through public wire APIs and supplies independent
monotonic node clocks with a fixed 0–9 millisecond offset. It does not replace
signature verification, execution, consensus decisions or durable publication.

| Phase | Behavior |
|---|---|
| Ticks 0–7 | Split the four nodes into isolated pairs; restart one node at tick 4 |
| Ticks 0–39 | Drop selected exchanges, shuffle their messages, delay delivery by 0–7 ticks and duplicate selected exchanges one tick later |
| Ticks 40 onward | Restore every directed peer route with prompt delivery; keep delivering previously queued packets |
| After a second node reaches finalized height 2 | Reopen it from its actual chain, cache and protected journal while keeping the in-flight queue |

The queue has an asserted bound of 216 exchanges. Faults also inject separate
canonically framed messages with corrupted vote/proposal signatures, future-height
VRF contributions or invalid block roots. Such input must leave the destination's
published checkpoint unchanged. Standby nodes may ignore irrelevant voting messages.

The oracle checks each newly committed block at every participant, including
intermediate blocks imported during catch-up. At a given height every published
block hash must agree, and no participant's committed height may regress. Neither
side may publish during the initial partition: the complete-roster VRF rule still
applies. The scenario must exercise a later BFT round and both restart points.

After communication recovers, all four nodes must reach the same height-5
checkpoint within 400 logical ticks. Each retained chain is independently
authenticated and re-executed from its configuration. A late observer must import
the same chain and pass the same recovery check. Failure reports identify the
profile, random seed and schedule counters; no test seed is retried on failure.

## Running the checks

```text
cargo test -p node --test adversarial_rotation
cargo test --release -p node --test adversarial_rotation -- --ignored --nocapture
```

The ordinary workspace suite runs one fixed seed against both profiles. The
explicit extended test runs seeds 1 through 12 against both profiles, for 24
additional scenarios. Both tests use only loopback-free in-process delivery and
temporary local storage; no remote network or GitHub operation is involved.

On 2026-10-04, Windows with Rust 1.99.0 passed the ordinary test in debug and
release, and all 24 extended release scenarios. Their counters reported a later
BFT round in every scenario. The fixed-seed debug and release counters matched.

## Limits

This is bounded delivery-fault simulation, not exhaustive state exploration.
Participants use the production signing guard; the harness injects invalid
messages but does not model a validly signing Byzantine coalition. The separate
PoTB network test covers admission, exclusion, candidate/standby changes and
recovery. This scheduler does not combine those membership changes with every
delivery schedule, exhaust weighted-quorum arrangements or model disk failures.

Formal rotating safety/liveness, valid Byzantine equivocation schedules, extended
membership churn, adverse weight concentration, partial-synchrony calibration,
independent cryptographic review and public-network qualification remain open.
