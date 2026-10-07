<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 30. Signed contracts and mixed execution

## Activation and compatibility

Genesis `runtime_version = 2` activates signed ABI-v2 contracts and payments.
Materialization adds `astrolune/runtime/v2 = u32le(2)` to committed state. Version 1
keeps its existing initial state bytes, payment semantics and receipts. Unsupported
runtime versions fail validation. There is no implicit upgrade of existing chains.

`cli devnet target/contracts 4 --contracts --observer` provisions a local profile-2
network. The flags can appear in either order. Normal devnets select profile 1.
The execution profile recovers from authenticated state on restart and when a
late node imports certified history.

## Signed payload

The existing version-1 transaction envelope signs the explicit `Contracts` lane,
chain, sender, nonce, expiry, resource prices, limits, access list and payload.
The payload begins with `ALCON002`, a 32-byte Ed25519 public key and an action byte.
Lengths/counts inside this payload are fixed little-endian u32 values:

- Action 0: code length and exact WebAssembly bytes (1..1,000,000 bytes).
- Action 1: 32-byte contract address, input length and bytes (at most 64 KiB),
  key count (at most 1024), then length and bytes for each local key. Keys are
  strictly increasing, unique and 1..256 bytes long.

Decoding rejects truncation, trailing bytes, unknown actions and oversized fields
before allocation. The complete payload is bounded to 1,000,045 bytes. The current
network additionally limits the entire transaction to 64 KiB; the deployment CLI
limits code to 60 KiB to leave envelope space.

Deployment addresses are `H("astrolune.contract.address.v2", u32le(chain) ||
sender32 || u64le(nonce))`. Code is immutable at
`astrolune/contract/code/v2/ || address32`. Contract-local values are stored at
`astrolune/contract/state/v2/ || address32 || H("astrolune.contract.key.v2", key)`.
Contracts cannot address wallet, genesis, code or another contract's state through
the host API. There are currently no cross-contract calls or native-value transfers.

Every transaction declares its sender account and code key. Calls also declare
every scoped local key listed in their payload. The runtime checks each actual
host access against that list. A call sees preceding successful writes in its
block. Deployment followed by a call can execute in one received block; mempool
admission requires code to exist in finalized state.

## Resources, receipts and failure

Admission verifies the sender key/address, exact nonce, signature, expiry,
activation and signed prices. The fixed profile burns one balance unit per
compute unit; other prices are zero. Balance must cover the maximum authorized
compute budget. Success increments nonce once and burns actual compute usage.
Arithmetic is checked.

Deploy usage is `compute = 100 + code bytes`, `memory = io = 32 + code bytes`,
and bandwidth equal to encoded transaction size. Calls add an overhead of 100
compute, 32 memory bytes, `32 + code bytes` I/O and encoded transaction size as
bandwidth. Loading existing declared values charges their key/value bytes as
compute and I/O before the sandbox receives the remaining budgets. The loaded
view is bounded to 1 MiB, with values at most 64 KiB. Runtime fuel, linear memory,
I/O and output/event bandwidth are added to these overheads.

Contract receipts commit `H("astrolune.contract.result.v2", diff_hash || result)`.
Deploy result is the derived address. Call result is canonical length-prefixed
return bytes, canonical event count, then each topic32 and length-prefixed body.
This result encoding uses the existing codec's compact lengths. Revalidation
recomputes the whole receipt, including events and return data. Return/event bodies
are not yet exposed by a receipt-query RPC.

Traps, invalid access, insufficient resources and nonzero contract status reject
the transaction. They produce no included failure receipt and consume no nonce
or balance. A received block containing such a transaction is rejected as a
whole. Proposal admission skips rejected candidates without changing its private
overlay. Publication occurs in one atomic state/storage commit.

## Parallelism and operators

`execute_signed_parallel` plans mixed payment/contract waves after checking the
required account/code/local declarations. Independent transactions run against
private snapshots, and dependent waves observe earlier results. Worker failures
and invalid speculative results replay through the serial reference path. The
node uses up to eight local workers; tests compare 1, 2, 3, 8 and 32 workers,
including invalid batches. System transactions remain reserved.

```text
cli sign-deploy <genesis> <seed-file> <wasm> <nonce> <expires-at> <output>
cli sign-call <genesis> <seed-file> <contract> <input-file> <keys-file> <nonce> <expires-at> <max-compute> <output>
cli inspect-transaction <file>
cli submit <file> [rpc-address]
```

Signing is offline and refuses to overwrite files. Calls take raw input bytes and
one hex-encoded local key per line (an empty file declares no local keys). The
caller supplies the maximum compute/fee authorization; other budgets are capped
by genesis and the ABI. Submission sends retained signed bytes once and preserves
ambiguous-outcome handling. Acceptance is not finality.

Tests cover canonical payloads, forged/expired transactions, missing leases,
insufficient budgets, namespace isolation, atomic rollback, mixed-wave parity,
real CLI subprocesses, three-of-four certified inclusion, signer/state restart,
late-node catch-up and replay rejection.

The [Rust host SDK](31-rust-sdk-and-wallet-vaults.md) is implemented and tested. Package/source verification, alternate runtime backends, DNS contracts and receipt/proof RPC remain tracked in ROADMAP.
