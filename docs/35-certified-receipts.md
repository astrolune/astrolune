<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 35. Certified receipts and finality waiting

## Publication and trust

Account-backed block execution publishes the ordered execution receipts and a
post-state genesis witness atomically with the block, certificate and state delta.
Storage verifies transaction IDs, receipt order, the receipt Merkle root, checked
aggregate resources and the state witness before publication. Recovery validates
the same metadata. Older blocks without receipt metadata remain readable.

The `receipt` RPC returns a bounded proof containing the certified header, its
precommit certificate, the complete receipt list and the genesis membership
witness. `CertifiedReceiptProof::verify` requires independently supplied genesis
and its exact public-key registry. It verifies the fixed genesis committee's
quorum, header and receipt commitment, genesis binding, requested transaction ID
and a caller-supplied minimum height. The requested ID must appear exactly once.
This profile does not authenticate future rotating committees.

The result includes success, consumed resources and the committed output root.
Raw event bodies and contract return bytes are not retained by this endpoint.
A receipt is proof of finalized execution; an RPC admission response is not.

## Queries and commands

The JSON method is `receipt`, with `id` (32-byte hex) and an optional `height`
(decimal string or unsigned JSON integer). The result is proof bytes as hex or
`null`. `null` means unavailable: pending, unknown, absent receipt metadata,
pruned history, or an ID outside the recent index. It is not proof of rejection
or non-inclusion. All network input and response sizes are bounded.

```text
cli receipt <genesis> <validators> <tx-id> <minimum-height> <output> [rpc-address] [block-height]
cli verify-receipt <genesis> <validators> <tx-id> <minimum-height> <file>
cli wait-finality <genesis> <validators> <tx-id> <timeout-seconds> <output> [rpc-address]
```

Fetch and wait commands authenticate the proof before creating a new output file;
existing files are never overwritten. Offline verification checks the same trust
anchors. Finality waiting polls only receipt queries, at most once per 250 ms,
within one absolute deadline (1–3600 seconds). Each RPC call is also bounded by
that deadline. Network/authentication errors are reported; timeout preserves the
ambiguous outcome and never resubmits a transaction. Retain the signed transaction
and its ID when deciding how to retry an application operation.

## Storage compatibility and bounds

Each backend rebuilds a recent transaction index from finalized bodies on open.
The index retains at most 100,000 positions. A known block height bypasses this
index, allowing queries for older retained blocks. Eviction affects lookup only;
it does not delete disk history or change consensus.

Append-only logs retain `ASTLOG01` framing. Payload tag 1 is the previous batch
without receipts. Tag 2 appends an effects blob after the existing ordered deltas.
Whole-chain archives read version 2 and version 3; archives containing receipt
metadata are written as version 3, with presence tag 2 for a body plus effects.
Older binaries cannot read the new records. Back up consistently and upgrade all
local readers before enabling receipt-producing writers. Peer block/certificate
encodings are unchanged: catching up nodes execute bodies and derive receipts.

The effects encoding is `ALEFFECT || count:u32 || receipts:count*97 ||
genesis_length:u32 || genesis_proof`. Integers are little-endian. At most 16,384
receipts and a 2 KiB witness are accepted. Proof framing is `ALRCPT01 || header:200
|| certificate_length:u32 || certificate || effects_length:u32 || effects` and
is limited to 2 MiB. Lengths, canonical receipt flags and trailing bytes are checked
before independent authentication.

## Verification

Tests cover genuine quorum certificates, wrong transaction/order/commitment,
insufficient quorum, genesis and minimum-height mismatches, truncations, bounded
index eviction (including repeated IDs), RPC before and after process restart,
legacy/archive and log recovery, offline CLI verification, delayed finality and
an absolute timeout without resubmission. Physical log retention and bounded
historical replay remain separate storage work.
