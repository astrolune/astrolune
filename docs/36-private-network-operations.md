<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 36. Private-network discovery, sessions and operations

## Scoped discovery

Certified validators and observers can start with a small set of bootstrap peers
and learn additional routes through mutually authenticated TLS exchanges:

```text
daemon --observer --run --genesis genesis.bin --validators validators.bin \
  --data-dir observer-data --tls-dir observer-tls \
  --p2p-listen 10.20.0.5:18000 --rpc-listen 127.0.0.1:19000 \
  --peers 10.20.0.1:18000 --discover-in 10.20.0.0/24 \
  --metrics-listen 127.0.0.1:19001
```

`--discover-in` is opt-in and requires TLS. Its canonical IPv4 CIDR must be wholly
inside RFC 1918 private space or loopback. The listening IP and bootstrap addresses
must be inside that subnet; zero, subnet and broadcast dial targets are rejected
(`/31` and `/32` support point-to-point/host scopes). IPv6 discovery is not part of
this profile. Fixed configured IPv6 peers remain supported without discovery.

Routing hints are not validator identities. Every connection authenticates under
the configured network CA, and every consensus message still undergoes registered
signature/genesis verification. A CA member can suggest only bounded in-scope
addresses. Choose a subnet dedicated to the network: authentication prevents data
exchange with unauthorized endpoints, while the CIDR bounds attempted connections.
Transport admission never adds voting power or changes genesis membership.

Each directory retains at most 32 remote routes. Only ourselves and endpoints
whose authenticated exchange succeeded are re-advertised. Discovered endpoints
are removed after eight consecutive failures; configured seeds remain available
for reconnection. No unbounded labels, DNS lookups or network-wide scans occur.
Routes are volatile and rediscovered after restart, so retain at least one working
bootstrap address. Incoming requests advertise their caller's listening endpoint,
allowing reciprocal polling and observer transaction gossip.

Discovery wraps the unchanged sync protocol in `ALDISC01 || genesis:32 ||
count:u8 || count*(ipv4:4,port:u16) || payload_length:u32 || payload`. Integers are
little-endian; addresses must be sorted and unique, count is at most 32, and inner
frames keep their existing bounds. Other genesis values, trailing bytes and
noncanonical frames fail closed. Discovery-enabled servers also accept legacy
48-byte sync requests, returning the original response without discovering routes.
Outgoing discovery requires the contacted node to enable this profile too.

## Sessions and reconnects

Peer workers reuse authenticated connections for at most 128 exchanges or 30
seconds. Incoming sessions have a two-second idle/packet deadline and the same
lifetime/message bounds. Every reconnect performs a fresh TLS handshake; TLS
resumption remains disabled. Legacy one-exchange peers are still usable with
fixed routing: a closed connection is retried without changing protocol validity.

Outgoing failures use exponential backoff from 100 ms to five seconds, reset
following a successful exchange. Success polls are spaced by 50 ms. There are
at most 32 route workers, 32 incoming session slots and four queued responses;
full mailboxes drop redundant responses for the next poll. The node execution
mailbox retains at most four additional exchanges. Each driver iteration accepts
at most eight connections, transfers at most four responses into that mailbox
when it has room, and processes up to 32 messages plus a completed execution job
before its consensus step. Peer shutdown is bounded by current connect/packet
deadlines; the execution worker joins its one current computation.
These are local service policies, not consensus timing guarantees.
Optional compact transport and bounded next-height fetching are described in
the [execution pipeline specification](54-compact-blocks-and-execution-pipeline.md).

## Metrics and incident diagnosis

`--metrics-listen IP:port` enables an optional loopback-only HTTP endpoint. It
serves `GET /metrics` as Prometheus text. Requests have a 2 KiB header bound and a
500 ms absolute read deadline; writes have a separate 500 ms deadline. The
single exporter worker has bounded memory and no access to signing secrets.
Metrics have fixed names and no peer/key/user-controlled labels. They reset on
restart and never enter block validity, weight or capacity decisions.

Useful observations include:

- `astrolune_finalized_height`, `astrolune_finalized_blocks_total` and
  `astrolune_finality_age_seconds` for durable advancement;
- `astrolune_p2p_known_peers`, incoming/outgoing sessions and successful exchanges
  for reachability and connection reuse;
- connection/exchange failures, queue/session-limit drops and rejected messages
  for overload or incompatible peers;
- accepted/rejected RPC submissions and `astrolune_local_failures_total`.

A rising finality age means no new durable head was observed; it does not identify
the cause. Check reachable voting power, TLS validity, the common genesis/registry,
round timeouts, and local error output. Successful connections to observers do not
supply quorum. Exchange failures include orderly session rotation. Metrics are
best-effort concurrent observations, not authenticated chain facts. Use state or
receipt proofs when an application needs independent finality verification.

## Authenticated recovery and observer export

Stop the source node before using these exclusive commands:

```text
cli verify-history <genesis> <validators> <directory> <minimum-height>
cli export-history <genesis> <validators> <directory> <minimum-height> <new-directory>
```

Both commands require an existing regular `chain.bin`, acquire its writer lock,
perform storage replay/root validation, and verify complete ancestry and every
certificate against the independently supplied fixed genesis committee. Opening a
log may discard an unpublished crash tail, exactly as daemon recovery does; it
never fabricates a missing head or repairs committed bytes. Missing history,
conflicting writers, forged finality and checkpoints below the supplied minimum
height are rejected. Keep that minimum outside the data directory if rollback
is a concern; a consistent old backup is otherwise still valid history.

Export creates an exclusive new directory, copies the published chain and log
head while holding the source lock, synchronizes files, reopens/authenticates the
copy, and compares its exact checkpoint. It writes public genesis/registry files,
`observer.mode` and `RECOVERY.txt`. Archive and append-only backends are supported;
one chain file is bounded at 1 TiB for this operator command. An existing output
directory is never reused. A failed export remains for inspection and is not
reported as a ready recovery bundle.

The result is an observer data directory. Start it with `daemon --observer`, the
exported `genesis.bin` and `validators.bin`, a separately provisioned TLS identity,
and reachable peers. Consensus seeds, signing journals, consensus caches, TLS keys
and pending transactions are excluded. This tool does not restore validator
signing authority. Preserve a validator's original protected journal/locks and
external anti-rollback records when recovering that identity; never create a new
journal for an old key to bypass a recovery error.

If committed bytes are corrupt, retain the damaged files for diagnosis and recover
an observer from a verified consistent copy or synchronize a new observer from
trusted peers. Do not delete a published head, overwrite a journal, or downgrade
the daemon to demonstration mode to make startup succeed.

## Verification and remaining limits

Tests exercise CIDR boundaries, forged namespaces, all envelope truncations,
canonical mutation roundtrips, directory caps and route eviction. A five-process
TLS test bootstraps through one observer, establishes direct validator routes,
checks connection reuse, removes the bootstrap node, continues finalizing and
restarts a validator. Existing TLS/payment/corruption/restart tests remain active.
HTTP tests cover read-only routing and trickle deadlines. Recovery tests cover
both storage formats, writer exclusion, stale checkpoints, forged certificates,
non-overwrite and observer restart without copied authority.

This completes the operational discovery/session/metrics/recovery software for
the described private-network profile. Internet discovery, IPv6 gossip, remote
metrics authentication, physical history retention and rotating committee
recovery are separate work. Platform power-loss and long-running deployment
qualification are not established by these process tests.
