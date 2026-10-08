<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 46. Rotating network delivery simulations

`crates/node/tests/adversarial_rotation.rs` drives actual `NetworkNode`
instances through deterministic hostile delivery schedules. Each uses its own
chain storage, protected signing journal and consensus cache. A `Profile` names
the authority, roster members, weights, seat count, age increment, candidates,
equivocating seats, governance participation and target height, so a scenario is
not fixed to four uniform nodes. The base scenarios run against
[genesis-v2 rotation](40-live-vrf-network.md) and the explicit
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

The queue bound is derived from the profile as directed routes times one original
plus each duplicate, retained across every tick a drawn delay can still postpone,
and is asserted every tick. Faults inject separate canonically framed messages
with corrupted vote/proposal signatures, future-height VRF contributions, invalid
block roots or corrupted transaction signatures. Quorum-bearing governance,
admission and evidence gossip exposes no publicly mutable authenticated field, so
those kinds are attacked by mangling the framed body instead; every gossip kind is
handled deliberately and no catch-all arm can silently stop attacking. Such input
must leave the destination's published checkpoint unchanged. Standby nodes may
ignore irrelevant voting messages.

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

## Byzantine coalitions, churn and weight concentration

A coalition profile names seats that sign correctly but inconsistently. Their
conflicting votes are signed directly with the seat key, which is exactly the
authority a Byzantine operator holds, rather than by corrupting a field so that
verification trivially rejects it. Before a coalition scenario runs, the profile
asserts that every committee able to seat the whole coalition still requires
strictly more shared weight for two conflicting quorums than the coalition
controls, so the scenario stays below the accountability threshold described in
the [bounded formal model](55-formal-consensus-model.md). The oracle then requires
both outcomes: no conflicting finality at any height, and an attributed offence.
Because `offence_id` nils the voted value, many conflicting votes from one seat
collapse to one offence, and the durable proof must survive restart.

A churn profile drives admission, parameter governance and exclusion from
independently replayed finalized handoffs while the delivery faults continue, so
membership changes and hostile delivery overlap rather than being tested
separately. A blackout isolates one node across a membership change and the
scenario must still converge and re-authenticate. A concentrated profile gives one
seat near-threshold weight, so a weighted quorum is not a seat majority.

## Running the checks

```text
cargo test -p node --test adversarial_rotation
cargo test --release -p node --test adversarial_rotation -- --ignored --nocapture
```

The ordinary workspace suite runs four scenarios: both base profiles, a validly
signing coalition, adverse weight concentration, and membership churn crossed with
delivery faults. The three extended campaigns run multiple seeds for the delivery
schedule, the coalition and the churn schedule. Both use only in-process delivery
and temporary local storage; no remote network or GitHub operation is involved.

On 2026-10-08, Windows with Rust 1.99.0 in release passed all four ordinary
scenarios in 1.55 seconds. The base rotating profile reported 140 dropped, 293
delayed, 90 duplicated and 340 rejected forged exchanges across 5 seat changes,
and the PoTB profile 146, 283, 84 and 334 across 3. The coalition scenario
reported 642 conflicting signed votes collapsing to exactly 1 attributed offence
with 1 retained proof, and the concentrated profile 153 collapsing to 1 with 1
proof. The churn scenario reported 349 dropped, 435 delayed, 123 duplicated, 480
rejected forged exchanges, 86 mangled certificate bodies, 118 blinded exchanges,
18 applied admissions, 18 applied governance changes, one commit during a blackout
and 4 seat changes. The three extended campaigns passed 54 scenarios in 18.67
seconds; every coalition scenario reported exactly one attributed offence, with
one to three retained proofs.

## Limits

This is bounded delivery-fault simulation, not exhaustive state exploration.
Participants use the production signing guard, and coalition seats sign with their
own keys rather than bypassing it. Coalitions are deliberately held below the
accountability threshold, so these scenarios demonstrate attribution and continued
safety, never the behavior of a quorum-sized coalition. Bounded exploration of the
threshold itself is the separate
[formal model](55-formal-consensus-model.md), which covers one height only.

The scheduler does not exhaust every combination of membership change and delivery
schedule, model disk failures or corrupted storage, calibrate partial-synchrony
timeouts, or vary roster sizes beyond the configured profiles. Real network
behavior, bandwidth and adversarial peer selection are outside it.

Partial-synchrony calibration, disk-failure modelling, independent cryptographic
review and public-network qualification remain open.
