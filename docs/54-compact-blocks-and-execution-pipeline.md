<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 54. Compact blocks and the reference execution pipeline

The daemon combines bounded peer propagation, structural decoding, detached
execution, node-thread voting and sequential durable publication. These stages
overlap without changing signed block contents or the existing finality rules.
The synchronous node APIs remain available for deterministic callers and tests.

## Compact transport

`--compact-blocks` requests compact responses. It is optional and defaults off;
servers accept both compact and legacy requests. The caller retains an owned
dictionary of at most 256 pending transactions and 2 MiB of canonical transaction
bytes for one exchange. Changing its live mempool does not invalidate that
dictionary. Full 32-byte transaction IDs avoid a separate short-ID collision
protocol. Transactions absent from the advertised dictionary travel inline.

The compact request is `ALCQ\x01\0\0\0`, the unchanged genesis and height,
a little-endian `u16` count, and strictly sorted full transaction IDs. Its maximum
size is 8242 bytes. `ALRQ` requests remain unchanged. Discovery can wrap either
request; unwrapped legacy requests still receive unwrapped legacy responses.

For proposals, finalized blocks and retained available values, the response can
replace transaction bodies with references to advertised IDs. Its `ALCX\x01\0\0\0`
envelope contains a length-prefixed legacy exchange skeleton with empty block
transaction vectors, followed by the transaction slots for each block in message
order. A slot contains either tag `0` and a full ID, or tag `1` and a
length-prefixed canonical transaction. Block slot counts use `u16`; blob lengths
use `u32`; all integers are little-endian. Other message contents are unchanged.

Reconstruction restores the complete ordered transaction vectors before the
ordinary message-processing path. The original limits still apply: 512 messages,
256 transactions per decoded block, 64 KiB per transaction, 1 MiB per block and
8 MiB per expanded exchange. Expansion is charged before copying referenced
transactions. Empty dictionaries and encodings without a size reduction use the
unchanged `ALNX` response. Signed transaction, block and certificate encodings
and the existing compatibility fixtures are unchanged.

A connected compact exchange that fails is retried over a fresh legacy session.
The peer worker keeps that legacy preference for its lifetime, including session
rollover, so an older peer is not repeatedly probed. Ordinary connection failures
retain the existing backoff. This fallback changes transport representation only.

## Detached execution and publication

Both node roles support `enable_execution_pipeline`, `can_receive` and
`poll_execution`. Enabling creates one persistent worker with one outstanding
job or uncollected result. A job owns a private producer snapshot without a
signer or storage writer. The daemon enables this path after opening/recovering
the node. Recovery-only startup does not create a worker.

The main thread queues complete decoded exchanges, starts block execution, and
continues to serve propagation, RPC and consensus timer work. On a subsequent
poll, it offers the opaque completed result to the producer and invokes the
ordinary message handler. That handler retains its envelope, committee, transition,
voting and publication checks. Results can only supply execution work for the
exact block and producer context: parent, height, state root, execution settings,
and applicable committee and transition batch. Mutating a public proposal's
outputs does not create a matching result.

There is one reusable execution result per producer. It prevents repeating the
same deterministic work during proposal validation and commit. State/height
changes invalidate it; publication errors retain the original state and permit
an ordinary retry. Imported-block execution is independent of later mempool
admissions. Changing a consensus round alone does not invalidate the execution
of an otherwise current finalized block.

Local candidate preparation also runs on the worker before a proposal is signed.
The candidate freezes the pending selection at submission time. Later admissions
remain pending for a later candidate; they cannot indefinitely restart this work.
The public `accept_execution` API remains strict about its captured admission
sequence. Internally offered candidates still require the exact execution
snapshot and current committee root. Imported results cannot masquerade as local
candidate selections. A busy receive stream cannot prevent an idle worker from
being given a local candidate turn.

## Queue and height bounds

| Work | Bound |
|---|---|
| Peer response mailbox | Four fully decoded exchanges |
| Node receive mailbox | Four exchanges, including the current imported job's remaining messages |
| Node message processing per poll | 32 ordinary messages, plus a completed job |
| Execution worker | One submitted or uncollected result |
| Retained producer execution result | One exact snapshot/block result |
| Speculative peer request | At most four heights ahead of the node's committed next height |

After a single finalized response enters the response mailbox, that peer can
request the next height before the current block has been published locally.
Thus propagation of a later block overlaps execution and commit of the current
block. A full mailbox does not advance this cursor; live or empty responses reset
it, and advancement of the local head clamps it. Failed or stale input never
advances committed state. The node consumes imported messages in their original
receive order, with the ordinary sequential-height checks.

These are reference pipeline and speculative candidate/fetch implementations.
They do not execute or vote on an uncommitted descendant state, overlap canonical
storage commits, add a new consensus protocol or establish a throughput target.
The rotating profiles still wait for their existing full-roster transition data.
Dropping a worker joins its one current computation; it does not publish the
result. Process-level termination retains the existing durable recovery behavior.

## Verification and operation

Tests compare compact reconstruction to legacy exchange bytes, exercise real
legacy/compact TLS packet exchange and fallback, and retain request dictionaries
across pool changes. Detached execution tests compare synchronous outputs,
configuration/parent changes, publication retry, worker bounds and rotating
profiles. Node tests cover queued catch-up, local production and restart; daemon
process tests exercise the enabled pipeline.

Use the [operations runbook](52-network-operations.md) to record exact revisions,
launch options, hardware, topology and raw samples for comparisons. Functional
equivalence and reduced encoded response sizes are not distributed throughput
or latency measurements. Cross-host calibration and independent-machine release
reproducibility remain external qualification work.
