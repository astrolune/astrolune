<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 31. Rust SDK and encrypted wallet custody

## Allocation-free Rust contracts

`cargo contract build` bundles and compiles the exact `contract-sdk` and
`contract-abi` sources, then makes `contract_sdk` available to the standalone
Rust contract. No checkout or registry access is needed by the built tool.
The contract still needs the pinned Rust 1.99.0 wasm32 standard library.

`contract_sdk::Guest` exposes all ABI-v2 host operations on wasm32: input length
and copying, return data, local get/put/delete, events, authenticated caller and
block height. Methods accept borrowed slices and perform no allocation. Reads
distinguish an absent key from an empty value. Invalid lengths return `AbiError`;
runtime traps abort the enclosing transaction.

The SDK's optional `alloc` feature retains the existing simulation helpers.
The bundled standalone build disables that feature, so a contract using `Guest`
needs neither an allocator nor `std`. The old `Host`/`MeteredHost` interfaces are
simulation helpers; their balance, transfer and timestamp methods are not ABI-v2
imports. The runtime remains the authority for actual metering.

```text
cargo contract build examples/contracts/counter.rs counter.wasm
cli sign-deploy genesis.bin wallet.vault counter.wasm 0 1000 deploy.bin
```

The [counter example](../examples/contracts/counter.rs) increments a checked u64,
stores it under local key `counter`, emits an event and returns little-endian
bytes. Calls declare hex key `636f756e746572`.

Rust external calls are isolated to the dedicated wasm32 binding crate. The
workspace-wide unsafe prohibition remains unchanged; see the exact exception,
borrow/pointer invariants and implementation review in
[contract-abi/SAFETY.md](../crates/contract-abi/SAFETY.md). This is not an external
audit. The compiler/runtime integration test exercises every import using an
actual Rust-generated module, including absence, empty values, deletion, caller, events, full-width height and invalid offsets. Both native and wasm32
Clippy checks are part of local validation.

## Wallet vault v1

Wallet vaults encrypt one 32-byte Ed25519 seed using fixed Argon2id v19 parameters
(65,536 KiB, three passes, one lane, 32-byte derived key) and XChaCha20-Poly1305.
Each encryption obtains an independent 16-byte salt and 24-byte nonce from the
operating system CSPRNG. Newly created wallets also use OS-generated seeds.

The exact 144-byte file is:

| Bytes | Meaning |
| --- | --- |
| 0..8 | ASCII `ALVAULT1` |
| 8..12 | wallet purpose 1, algorithm profile 1, two zero reserved bytes |
| 12..24 | memory KiB, passes, lanes as three little-endian u32 values |
| 24..40 | salt |
| 40..64 | extended nonce |
| 64..96 | Ed25519 public key |
| 96..128 | encrypted seed |
| 128..144 | authentication tag |

The entire 96-byte header is authenticated as associated data. Decryption checks
length, purpose, reserved bytes and the exact KDF parameters before allocating
KDF memory; an untrusted file cannot request more work. The decrypted public key
must match the authenticated header. Wrong passwords and modified ciphertext,
salt, nonce, public key or tag fail authentication.

Passwords contain 12..1024 opaque bytes. The CLI consumes one line from a private
stdin pipe, removing a terminal LF or CRLF only. It rejects an interactive terminal
to avoid echoing a password, and never accepts passwords in arguments. Feed stdin
from a secret manager or protected input source. Passwords, derived keys, seed
buffers and the full Argon2 memory workspace are zeroized when released.

```text
cli wallet-create <new-vault>
cli wallet-encrypt <raw-seed-file> <new-vault>
```

Commands refuse overwrites and do not delete the original seed. Existing wallet
identity, payment and contract-signing commands accept either a raw 32-byte seed
or a vault; vault input triggers password reading from stdin. There is no plaintext
export command. Files are created with mode 0600 on Unix; Windows uses the parent
directory's ACL. Keep backups of vault and password separately. This protects keys
at rest; it does not provide hardware isolation or prevent rollback of consensus
journals. Consensus/VRF provisioning continues to use its separate raw-key workflow.

Tests cover random salts/nonces, valid unlock, all header parameter bytes, wrong
passwords, authenticated-field changes, all truncated lengths, oversized input,
real CLI unlock/signing equivalence, non-overwrite behavior and secret-free output.
