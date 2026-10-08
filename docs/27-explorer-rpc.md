<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Explorer integration

The Rust daemon exposes length-prefixed JSON-RPC over TCP, not HTTP. A browser
must use a server-side gateway. The gateway must keep the node endpoint private,
allow only intended read methods, bound connections, responses and deadlines,
and distinguish an unavailable node from an empty chain.

## Wire framing

Each request and response is a four-byte unsigned little-endian payload length
followed by UTF-8 JSON. Requests are bounded to 1 MiB and responses to 4 MiB.
An explorer should close its connection after one response. The reference node
RPC server processes connections sequentially and is intended for a trusted
local gateway, not direct public Internet exposure.

## Finalized block lookup

```json
{"jsonrpc":"2.0","id":1,"method":"block","params":{"height":"1"}}
```

`height` accepts an unsigned decimal string covering the entire u64 range or a
non-negative JSON integer representable by the node parser. Use strings in web
applications. Unknown, unavailable/pruned, and genesis-only heights return null.
Storage failures return an RPC error. A returned block contains:

| Field | Encoding |
| --- | --- |
| height | unsigned decimal string |
| hash, parent | canonical block-header commitment and parent commitment, 64 hex characters |
| state_root, transactions_root, receipts_root, committee_root | 64 hex characters |
| transactions | ordered array of retained transactions |

Each transaction has `id`, `sender`, `nonce`, `expires_at`, `chain_id`, and `payload`.
`sender` uses the address display format: `0x` followed by 64 hex characters.
The identifier uses the existing canonical transaction-ID domain. Nonce and expiry
are decimal strings. Payload is hexadecimal. Large blocks exceeding the bounded
response estimate fail explicitly; there is no truncated success response.

`chain_status` returns numeric `chain_id` and `finalized_height`, and a hexadecimal
`finalized_block`. JavaScript clients must reject unsafe numeric heights instead
of silently rounding. Account data is null for absence, or 16 canonical bytes
encoded as hex: little-endian u64 next nonce followed by little-endian u64 balance.
Balances use integer units; a decimal token scale is not assumed.

## Display guarantees and limits

The daemon authenticates finalized history when operating in certified network
mode. This RPC does not deliver a complete independent light-client proof and
does not identify the node's operating mode. A web UI must describe results as
the contacted node's reported finalized state. The node may instead be in local
demonstration mode; operators must select a certified endpoint when required.

No timestamp, market price, transaction-per-second claim, address activity index,
transaction-hash index, contract runtime or live rotating validator registry is
provided by this endpoint. Do not infer or fabricate these fields. A transaction
can be linked using its block height and index. The browser must never receive
wallet seeds or the ability to select arbitrary upstream hosts or methods.
