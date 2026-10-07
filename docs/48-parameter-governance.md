<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Quorum parameter governance

The explicit PoTB configuration version two implements the selected governance
rule: **strictly more than two thirds of the current committee's voting weight**
must approve an exact capacity/fee update. Inclusion is finalized by the ordinary
outgoing committee. Parameters become active at the first height of the next
governance epoch. Epochs contain heights 1 through E, E+1 through 2E, and so on.
For E=2, an update included at height 1 or 2 starts at height 3.

An intent binds chain ID, configuration commitment, inclusion height, finalized
parent, incumbent committee commitment, activation height, four capacity dimensions
and four prices. Every approval is checked, including signatures after quorum.
Duplicate voters, standby voters, stale parents, foreign networks, out-of-policy
parameters and an existing pending update are rejected. At most one finalized
future update exists. Changing the committee does not reset a pending update.

The immutable configuration specifies the epoch length, capacity floor/ceiling
and price ceiling. Zero prices are allowed. The minimum capacity must be at least
`500000,131072,16384,65536` in compute/memory/IO/bandwidth order, ensuring room for
the complete maximum roster and its governance certificate. Local timing or
adaptive-capacity observations do not change these consensus parameters.

The boundary block executes applications using its parent's active prices and
capacity. Its system transaction commits the parameters for the next height.
Publication updates the producer only after storage succeeds. Recovery re-executes
the same sequence. Payment, contract, serial, speculative and fallback paths all
receive the same authenticated execution policy; signed transaction prices must
match exactly. Fees burn actual usage times the active prices, with checked
arithmetic and reservation against declared resource limits.

## Explicit activation and compatibility

`ALPTCF02` adds a 104-byte immutable policy and uses the configuration hash domain
`astrolune.potb.configuration.v2`. This creates a separate network identity; it
does not upgrade an existing network. Version-one profiles preserve their bytes,
commitments, resource charges and behavior. Unknown versions fail closed.

| Envelope | Tag | Maximum bytes |
|---|---|---:|
| Intent | `ALGVRQ01` | 188 |
| Approval | `ALGVAP01` | 136 |
| Certificate | `ALGVCF01` | 4549 |
| Active/pending state | `ALGVST01` | 249 |
| PoTB authority with governance | `ALPTST02` | 7762 |

`ALPTBT02` carries a governance certificate; empty governance batches retain
`ALPTBT01`. The handoff envelope continues to frame exact versioned children.
Network message tag 8 relays one bounded certificate for the current parent.
Pending submissions survive the existing durable consensus cache and are cleared
on height advancement. Acceptance over `submit_governance` does not imply finality.
Observers verify finalized inclusion but do not accept operator submissions.

## Operator workflow

```text
cli governance-config <potb-configuration> <epoch-blocks> <minimum-capacity> <maximum-capacity> <maximum-prices> <output>
cli governance-request <configuration> <validators> <height> <capacity> <prices> <request> [rpc-address]
cli governance-inspect <configuration> <validators> <request>
cli governance-approve <configuration> <validators> <request> <validator-seed> <journal> <approval>
cli governance-assemble <configuration> <validators> <request> <certificate> <approval>...
cli governance-verify <configuration> <validators> <request> <certificate>
cli governance-submit <configuration> <validators> <request> <certificate> [rpc-address]
cli reprice-transaction <transaction> <seed-or-vault> <prices> <new-transaction>
```

Resource vectors are four comma-separated unsigned integers. Files are never
overwritten. Requests carry an independently authenticated `.handoffs` sidecar;
inspect, approve, assemble and verify work offline. Use the normal provisioning
and daemon commands with the new configuration before creating the network.

Approval requires a protected signer in the exact namespace and checks its
height/committee watermark. Stop the daemon before opening its exclusive journal.
An explicit parameter approval neither reserves a BFT vote nor rewrites the
journal. Operators may approve competing requests; consensus inclusion and the
single pending slot select one. Approval is not a new slashing offence.

The original payment/deployment/call signing commands retain reference prices.
`reprice-transaction` re-signs an inspected transaction with explicit prices and
the matching wallet, displays the checked maximum fee and writes a new file.
Choose prices from authenticated parameter state; an old signed transaction is
rejected once its prices no longer match the active epoch.

## Qualification

Tests cover the exact two-thirds rejection, every-signature validation, parent and
namespace replay, malformed framing, pending-slot rejection, epoch activation,
mixed contract/payment fee equivalence, both storage backends, gossip and role
restart, real daemon RPC, protected CLI signing and damaged offline sidecars.
The original 50 legacy and eight PoTB fixtures are unchanged. Eighteen separate
[governance fixtures](../tests/integration/fixtures/governance-v1/README.md) cover
the request, certificate, gossip and three handoffs spanning activation.

This local qualification does not replace independent cryptography/consensus
review, long sanitizer campaigns or Linux/independent-machine release checks.
