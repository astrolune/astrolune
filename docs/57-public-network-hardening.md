<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 57. Public-network hardening and bounded admission control

A listener reachable by anyone must bound what one caller can spend before any
authentication, decoding or history read happens. The `p2p::admission` module
decides three things for one process: whether a connection may occupy a slot,
whether a received message may be charged against the budget its traffic class
was given, and whether a source address has misbehaved often enough to be
refused for a bounded period. Every decision is a pure function of a
caller-supplied millisecond tick, so a test replays an entire admission history
deterministically.

This is local resource admission. It is not authentication, not authorization
and not evidence. Transport authentication under the configured network CA and
the registered signature, genesis and committee checks on every consensus
message are unchanged and still mandatory. Nothing described here enters block
validity, voting power, committee membership, finality or the content of any
signed message.

## Integer token buckets

A `TokenBucket` holds whole tokens, a sustained refill rate expressed per second,
a burst capacity and a carried sub-token remainder. Refill is exact integer
arithmetic over the supplied tick:

```text
scaled    = elapsed_ms * per_second + remainder
tokens    = min(capacity, tokens + scaled / 1000)
remainder = scaled % 1000
```

Carrying `remainder` is what removes precision drift. Discarding it would lose up
to one token per advance, so a caller polled every few milliseconds would be
metered far more harshly than one polled once a second. With the carry, a
sequence of short advances accrues exactly as many whole tokens as one advance of
the same total length, and both equal `elapsed_ms * per_second / 1000`. The
product is formed at double width, so no multiplication wraps, and every
subtraction saturates at zero.

The module reads no clock of its own. The transport and the daemon each read one
monotonic origin at startup and supply milliseconds elapsed since it. A tick at
or below the highest tick already observed accrues nothing: a caller whose clock
moves backwards receives no refund, no panic and no overflow, and refill later
resumes from the highest observed tick rather than from the backwards one. There
is no floating-point arithmetic anywhere in the module. A bucket is not a queue
and not a delay line; a refused charge is refused, never deferred, and admission
never reorders or paces work it did admit.

## Traffic classes and budget tiers

A cheap message and an expensive one do not share a budget. Each `MessageKind`
maps to one `MessageClass`: `Hello` to `Handshake`, `Transactions` to
`Transactions`, `CompactBlock` to `Blocks`, and `Proposal`, `Vote` and `Finality`
to `Consensus`. Each class carries its own message-count limit and its own
byte-volume limit, so exhausting one class never starves another. The grouping is
a local cost judgement; it is not part of the wire protocol, and no peer can
observe or select its own class.

Each class budget exists at three tiers. The peer tier bounds one connection,
keyed by its full socket address. The source tier bounds one remote host across
every connection it holds concurrently and every connection it reopens, keyed by
its source address; this is the tier a caller churning connections cannot reset.
The process tier bounds this node's total exposure. A charge is all-or-nothing:
`charge_message` checks the message-count and byte-volume buckets of the class at
all three tiers before deducting anything, so a refusal at one tier leaves the
other two untouched. A refused charge also records a `RateLimitBreach` offence,
so a caller that keeps pushing past its budget eventually earns a ban rather than
an unbounded stream of cheap refusals.

The tiers bound aggregate volume per address. They do not identify a sender, do
not detect a coordinated flood spread across many addresses, and do not make any
statement about fairness between peers beyond the per-connection ceiling.

## Misbehaviour scoring and bounded bans

Offence classes are derived from failures this stack actually reports, not from
invented categories. `NetworkError::InvalidFrame` becomes `InvalidFrame`,
`NetworkError::LimitExceeded` becomes `OversizedPayload`,
`NetworkError::IncompatiblePeer` becomes `ProtocolViolation`, an exhausted budget
becomes `RateLimitBreach`, and a genesis, committee or signature rejection
reported by the node layer becomes `UnauthenticatedMessage`.
`NetworkNodeError::offence` performs that last mapping and returns nothing for a
local durability failure, which is this node's problem and never a peer offence.

Each offence adds its configured weight to a capped per-source score. The score
decays over the supplied tick with the same exact carried remainder as refill, so
decay is drift-free too. Reaching the threshold applies a ban that expires at
exactly `tick + ban_duration_ms` and clears the score, so a source that serves
its ban starts again from zero. A ban is one node's local refusal to spend
resources on one address for a bounded time. It is not a protocol penalty, it is
never gossiped, it never survives a restart, and it is not evidence of anything.
Ban duration does not escalate for a repeat offender.

The score and ban table is bounded at `max_tracked_sources` records. When it is
full, records that owe nothing and remember nothing are dropped first. If every
slot is still occupied, the least penalised record without a live connection is
evicted, ordered by ban expiry, then score, then retained tokens, then address. A
record holding a live connection is never evicted, and the total connection cap
keeps that set far smaller than the table. The per-connection bucket table is
bounded the same way: debt-free records first, then the record holding the most
tokens in the class being charged. Evicting a per-connection record buys no extra
allowance, because the source tier of that host keeps its own debt. A caller
cannot grow either table, and neither holds payload bytes, keys or message
contents.

Because the table is bounded, an attacker controlling many source addresses can
evict earlier records, and the earliest-expiring ban is the first to go. That is
stated rather than hidden: a bounded table cannot retain every offender, and no
configuration of these parameters changes that.

## Per-source connection caps

The historical transport ceiling was a single flat count, so one remote host could
occupy every slot. Admission keeps that total and adds a per-source concurrent
cap and a per-source connection-attempt bucket. The attempt bucket is charged
whether or not a slot is then granted, so a caller that is refused cannot retry
for free, and opening and closing connections repeatedly is bounded by the same
machinery as message volume.

The source address is parsed out of the existing `PeerId.addr` string by
`source_address`, which accepts `address:port`, a bare address, and the bracketed
`[::1]` and `[::1]:port` IPv6 forms. An IPv4-mapped IPv6 address is reduced to its
IPv4 form, so one host cannot claim two allowances by alternating
representations. A scoped address such as `fe80::1%eth0`, a DNS name and the
placeholder used when a socket reports no peer all fail to parse and are refused
outright rather than admitted unmetered. No lookup of any kind is performed and
nothing is contacted.

A source address is not an identity. Hosts behind one address share one
allowance, a host with many addresses receives many, and nothing here reasons
about network topology, address ownership, reflection or amplification.

## Transport and daemon integration

`PeerManager::connect` and `PeerManager::accept` now consult admission before a
connection exists. The earlier order established the connection first and only
then compared the peer count against the limit, so a manager already at capacity
still completed a handshake and immediately discarded it; that defect is fixed in
both directions. A refused dial creates no socket, a refused inbound connection
has its stream dropped where it was accepted, and `PeerManager::disconnect`
returns the slot. `PeerManager::receive` refuses a banned peer before reading,
records the offence a malformed or oversized frame names, and charges an accepted
frame to its class at all three tiers. `PeerManager::admission` exposes the shared
controller so a caller that observes an offence the transport cannot see records
it against the same state, and `PeerManager::tick_ms` supplies the tick.

The certified daemon keeps its own listener. Its accept loop builds a `PeerId`
from the accepted socket's peer address and calls `refuse_inbound`; a refused or
banned source has its stream closed there, before a TLS handshake, a worker
thread or the node mutex is spent on it, and the drop is counted as a
session-limit drop. The admitted slot is held by the session's `ConnectionSlot`
and returned when its worker finishes. Inside a session, every inbound request is
charged to the `Blocks` class before any history is read, because a catch-up
request obliges this node to read and encode finalized history. A refused charge
ends that session. A malformed envelope or request body is scored as
`InvalidFrame`, and a request carrying a foreign genesis namespace is scored as
`UnauthenticatedMessage`, which honest current input cannot produce. On the
outgoing side, a banned address is not dialled at all; the polling worker treats
that like any other failed exchange, so the existing backoff bounds the retry
rate, and a malformed response is scored against the responder.

Stale, duplicate and out-of-order gossip is deliberately not scored. Ordinary
catch-up and propagation overlap produce those rejections routinely, and scoring
them would ban correct peers. Responses to requests this node initiated are also
not charged: their volume is bounded by the exchange codec's existing limits and
by the poll spacing this node chooses, not by a peer. Admission therefore bounds
what an inbound caller can spend; it does not bound what this node chooses to
fetch.

## Configuration and defaults

Every limit is an explicit named constant, and `AdmissionConfig::default` is
exactly those constants with no value read from the environment, a file or a
peer. `PeerManager::with_limit` keeps every default except the total cap, and the
daemon replaces the total cap with its configured `max_peers`.

| Bound | Constant | Default |
|---|---|---|
| Total concurrent connections | `DEFAULT_MAX_TOTAL_CONNECTIONS` | 128 |
| Concurrent connections per source | `DEFAULT_MAX_CONNECTIONS_PER_SOURCE` | 32 |
| Connection attempts per source | `DEFAULT_CONNECTION_ATTEMPTS_PER_SECOND` / `DEFAULT_CONNECTION_ATTEMPT_BURST` | 32 per second, burst 128 |
| `Handshake` messages | `DEFAULT_HANDSHAKE_MESSAGES_PER_SECOND` / `DEFAULT_HANDSHAKE_MESSAGE_BURST` | 8 per second, burst 16 |
| `Handshake` bytes | `DEFAULT_HANDSHAKE_BYTES_PER_SECOND` / `DEFAULT_HANDSHAKE_BYTE_BURST` | 65,536 per second, burst 131,072 |
| `Transactions` messages | `DEFAULT_TRANSACTION_MESSAGES_PER_SECOND` / `DEFAULT_TRANSACTION_MESSAGE_BURST` | 64 per second, burst 128 |
| `Transactions` bytes | `DEFAULT_TRANSACTION_BYTES_PER_SECOND` / `DEFAULT_TRANSACTION_BYTE_BURST` | 4,194,304 per second, burst 8,388,608 |
| `Blocks` messages | `DEFAULT_BLOCK_MESSAGES_PER_SECOND` / `DEFAULT_BLOCK_MESSAGE_BURST` | 64 per second, burst 128 |
| `Blocks` bytes | `DEFAULT_BLOCK_BYTES_PER_SECOND` / `DEFAULT_BLOCK_BYTE_BURST` | 16,777,216 per second, burst 33,554,432 |
| `Consensus` messages | `DEFAULT_CONSENSUS_MESSAGES_PER_SECOND` / `DEFAULT_CONSENSUS_MESSAGE_BURST` | 128 per second, burst 256 |
| `Consensus` bytes | `DEFAULT_CONSENSUS_BYTES_PER_SECOND` / `DEFAULT_CONSENSUS_BYTE_BURST` | 2,097,152 per second, burst 4,194,304 |
| Source-tier factor | `DEFAULT_SOURCE_RATE_MULTIPLIER` | 32 |
| Process-tier factor | `DEFAULT_GLOBAL_RATE_MULTIPLIER` | 128 |
| `InvalidFrame` weight | `DEFAULT_WEIGHT_INVALID_FRAME` | 32 |
| `OversizedPayload` weight | `DEFAULT_WEIGHT_OVERSIZED_PAYLOAD` | 48 |
| `UnauthenticatedMessage` weight | `DEFAULT_WEIGHT_UNAUTHENTICATED_MESSAGE` | 16 |
| `RateLimitBreach` weight | `DEFAULT_WEIGHT_RATE_LIMIT_BREACH` | 8 |
| `ProtocolViolation` weight | `DEFAULT_WEIGHT_PROTOCOL_VIOLATION` | 24 |
| Ban threshold | `DEFAULT_BAN_THRESHOLD` | 128 |
| Score ceiling | `DEFAULT_SCORE_CEILING` | 1,024 |
| Score decay | `DEFAULT_SCORE_DECAY_PER_SECOND` | 4 per second |
| Ban duration | `DEFAULT_BAN_DURATION_MS` | 600,000 milliseconds |
| Retained source records | `DEFAULT_MAX_TRACKED_SOURCES` | 1,024 |
| Retained connection records | `DEFAULT_MAX_TRACKED_PEERS` | 1,024 |

The source-tier and process-tier budgets are the per-peer budgets multiplied by
their factors, which equal the per-source and total connection caps. One host's
concurrently admitted connections are therefore not penalised for sharing an
address, while that host keeps one source budget across every connection it
reopens. The per-source concurrent cap of 32 is one quarter of the total of 128
and is large enough for the 32 route workers a private-network profile may run
behind one address, as described in the
[private-network operations guide](36-private-network-operations.md).

These defaults are chosen so that the existing private-network and
compact-transport profiles described in the
[execution pipeline specification](54-compact-blocks-and-execution-pipeline.md)
operate unchanged. They are deliberately loose for a hostile public deployment
and are a starting point for operator tuning, not a calibrated setting. No
default here has been validated against a measured attack.

## Verification

Tests supply every tick explicitly and use exhaustive loops rather than
randomized property generation. Refill exactness is checked across ten rates and
five step sizes by comparing 97 short advances against one advance of the same
total length and against the closed-form integer accrual; score decay is checked
the same way. Further tests cover burst clamping at every elapsed tick, backwards
ticks against both the attempt budget and a message budget, a zero-rate bucket,
the complete `MessageKind` to `MessageClass` mapping, class isolation under an
exhausted budget, byte-before-message refusal, all-or-nothing deduction across
tiers, source-tier debt surviving a reconnection from a new port, process-tier
refusal, every offence weight and every `NetworkError` mapping, exact ban onset
and expiry, decay below the threshold, score saturation, scored rate-limit
breaches leading to a ban, refusal of a banned source on both inbound admission
and outbound dialling, per-source and total connection caps, slot release and
double release, attempt bounding under connect and disconnect churn, twelve
accepted and twelve rejected endpoint forms including bracketed and IPv4-mapped
IPv6, independent caps per IPv4 and IPv6 source, both bounded tables under floods
of thousands of addresses, eviction ordering, pruning, and agreement between
`AdmissionConfig::default` and every named constant.

Transport tests check that a refused dial creates no socket, that an unparsable
endpoint is refused, that a connection past the per-source cap is not retained in
the managed set, that `disconnect` returns the slot for reuse, and that a ban
recorded through the shared controller refuses a real accepted stream. Daemon
tests check the per-source cap and slot reuse through `refuse_inbound`, that
repeated malformed requests over real authenticated sessions score their source
until it is refused, that a served session charges every request and ends once its
block budget is spent, and that a banned address receives no connection at all.
The existing private-network, compact-transport, discovery, recovery and
multi-process TLS suites remain active and unchanged.

These are deterministic single-process replay tests. They establish arithmetic
exactness, bounded tables and bounded bans. They establish nothing about
throughput, latency, behaviour under a real distributed flood, or any consensus
outcome.

## Limits

Admission is local and bounded, and that is the whole of its claim. It is not a
defence against a distributed attack: a caller with many source addresses
receives many allowances and can evict bounded records, and no parameter here
changes that. It is not a congestion-control or fair-queueing algorithm, offers
no anti-amplification or anti-reflection argument, and provides no shared
reputation: scores and bans are process-local, are never gossiped, and do not
survive a restart.

Remaining work is separate. Ban duration does not escalate for a repeat offender,
and there is no operator allow-list, deny-list or manual ban command. Admission
state is not exported to the metrics endpoint, so a refused connection is visible
only as a session-limit drop and a refused charge only as the same counter;
per-offence and per-refusal counters, and the fixed metric names they would need,
belong to the telemetry surface rather than to this module. Prefix-level grouping,
so that a `/24` or a `/64` shares an allowance rather than each address receiving
its own, is not implemented. Per-source caps are not configurable from
`config::NetworkConfig`; only the total cap is, through `max_peers`. Stale and
out-of-order gossip is not scored, so a peer that sends only useless but
well-formed current-namespace data is bounded by rate limits alone. Responses to
requests this node initiated are not charged. Calibration of every default
against a measured hostile load, and qualification on a public network, are
external work that these tests do not perform.
