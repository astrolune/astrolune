<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 13. Signed Native Payments

For offline signing, saved-transaction inspection and real account/submission
commands, see the [CLI wallet guide](24-wallet-and-rpc-client.md).

## Activation and compatibility

Genesis-backed node services and `daemon --genesis genesis.bin` execute native payments against committed account state. The sender's public key travels inside the signed payment payload, and its derived address must match the transaction sender. No separate key registration is required for wallet accounts. Validator-key registration and authenticated consensus remain separate work.

Payments use the [version-1 transaction envelope](14-versioned-transactions.md), with signed expiry, an explicit payment lane, and prices equal to `PAYMENT_PRICES`. Account encoding and genesis commitments are unchanged. Native payment payloads have their own version tag. Genesis-backed proposals containing the previous arbitrary demonstration payloads are now rejected. Archive version 2 is required; version-1 archives are rejected without rewriting. Recovered history is not retroactively authenticated or re-executed. Genesis-free demonstration chains retain their previous behavior and expose no account or submission RPC.

## Payload version 1

`transaction::Payment` encodes exactly 80 bytes:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | ASCII `ALPAY001`, including the version |
| 8 | 32 | Sender Ed25519 public key |
| 40 | 32 | Nonzero recipient address |
| 72 | 8 | Positive native amount, little-endian `u64` |

Unknown tags, zero amounts, zero recipients, truncations, and trailing bytes are rejected. The enclosing transaction signs all fields, including the complete payload, version, chain ID, nonce, expiry, lane, access list, resource limits, and prices, using the existing signing domain with new canonical bytes. `address_from_public_key`, `signing_hash`, and `compute_tx_id` retain their specified cryptographic behavior.

The access list must contain both `state::account_key(sender)` and `state::account_key(recipient)`. A self-transfer requires one key. Additional declared keys do not authorize arbitrary writes. The observed lease is the normalized set of account keys actually accessed. Payments cannot change genesis metadata, validator weights, or unrelated state keys.

## Resource and fee rules

The reference payment schedule is fixed by payload version 1; local measurements never change it:

| Resource | Actual usage |
|---|---|
| Compute | 1 |
| Memory | 32 account-value bytes |
| IO | 4 operations |
| Bandwidth | Complete canonical signed transaction length |

Self-transfers use the same schedule. `execution::payment_resources` calculates usage. Every actual dimension must fit the signed limit, every signed limit must fit block capacity, and accumulated actual usage must fit block capacity. Proposal selection uses actual usage after successful execution.

`PAYMENT_PRICES` charges one balance unit per compute unit and zero for the other dimensions. The sender must cover **amount + maximum authorized fee**, where maximum fee is the signed compute limit. The successful transition burns only the actual fee, exactly one unit; unused authorization is not deducted. There is no fee beneficiary or validator reward yet. These are reference payment rules, not the final production fee/governance policy.

For a distinct recipient, execution debits amount plus one, increments the sender nonce once, and credits the amount without changing the recipient nonce. An absent recipient is created with nonce zero. A self-transfer requires the same balance reserve and changes only the sender nonce and one-unit fee. Nonce exhaustion, fee/amount arithmetic overflow, insufficient funds, and recipient balance overflow reject the transaction.

## Admission, ordering, and publication

Admission authenticates the signature against the durable account view without advancing its nonce or deducting money. Only the currently committed nonce is admitted; the pool admits at most one transaction for each sender/nonce. Clients wait for commitment before submitting a subsequent nonce. Pending transactions are not persisted.

`PaymentSession` executes sequentially against an immutable snapshot plus a private account overlay. Later transactions see earlier credits and nonce changes. Failed execution changes neither the overlay nor accumulated resources. A received block is revalidated in order regardless of whether its transactions were admitted locally. Any invalid transaction rejects the complete block before publication; version 1 has no fee-charging failed receipts.

Proposal construction skips pool entries invalidated by earlier transfers and scans later candidates without reserving capacity for skipped entries. Skipped entries remain pending and can become valid again after later account changes while their expiry permits inclusion. Once a successful commit advances the next height past an entry's expiry, that entry is removed and its byte budget is released. Repeated proposal construction preserves the committed state and pool. Commit re-executes signatures and transitions, verifies output/state/receipt commitments, then atomically publishes the archive. A failed storage write preserves the proposal, pool, balances, nonce, and checkpoint for retry.

## Daemon RPC

Start a persistent local payment node:

```sh
cargo run -p daemon -- --genesis genesis.bin --data-dir node-data --run
```

RPC uses a TCP frame consisting of a four-byte little-endian JSON byte length followed by JSON-RPC 2.0 JSON. It is not HTTP. Existing methods now connect to the node:

- `chain_status`, parameters `{}`: durable chain ID, height, and block ID.
- `account`, parameters `{"address":"<64 hexadecimal characters>"}`: canonical account bytes as hex (`nonce: u64 LE`, then `balance: u64 LE`), or `null` for an absent account.
- `submit_transaction`, parameters `{"data":"<canonical signed transaction bytes as hex>"}`: canonical transaction ID after successful mempool admission. Acceptance does not promise inclusion or finality.

The transport bounds JSON to 1 MiB, so hex transactions must fit within that frame including JSON overhead. Malformed canonical input and invalid signatures/accounts are rejected. Account reads and admission share the node lock with commit, so callers never observe speculative balances or a partly published block. Restart loads account changes from the archive and rejects already committed nonces. Genesis-free daemon account/submission calls continue to return unavailable.

Executable signing, TCP, and restart examples are exercised by [`payments_rpc.rs`](../apps/daemon/tests/payments_rpc.rs); sequential transitions and rejection cases by [`payments.rs`](../crates/execution/tests/payments.rs).

Consensus certificates remain demonstrations. Network authentication, general contracts, dynamic fee governance, durable pending queues, and production-scale storage remain unfinished.
