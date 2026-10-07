<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Native-payment wallet and RPC client

The CLI now reads the contacted node's finalized status and accounts and signs
real version-1 Ed25519 native payments. The previous offline status placeholder
and mock-key demonstration have been removed. This is a reference command-line
wallet, not a production custody product.

## Commands

Build both executables with `cargo build --release -p cli -p daemon`.
Use `target/release/cli` below (on Windows, `target\release\cli.exe`).

| Command | Behavior |
| --- | --- |
| `status [rpc-address]` | Read chain ID, finalized height and block hash |
| `account <address> [rpc-address]` | Read finalized balance and next sender nonce; report absence explicitly |
| `wallet-address <seed-file>` | Derive the wallet address and Ed25519 public key offline |
| `keys <seed-file>` | Alias of `wallet-address`; no mock identities are created |
| `sign-payment <chain-id> <seed-file> <recipient> <amount> <nonce> <expires-at> <output>` | Sign offline and create a new canonical transaction file |
| `inspect-payment <file>` | Check the native-payment policy and signature and display signed fields |
| `submit <file> [rpc-address]` | Check chain/expiry, then submit the exact saved transaction once |

RPC addresses must be numeric IPv4 or bracketed IPv6 socket addresses. The
explicit argument overrides `ASTROLUNE_RPC_ADDR`; otherwise the default is
`127.0.0.1:17331`. Invalid configuration causes an error rather than a fallback.
`ASTROLUNE_CHAIN_ID` is no longer used to fabricate a status: chain identity comes
from the node, and the signing command always requires an explicit chain ID.
Extra or missing arguments to the wallet commands fail.

Amounts and fees use integer smallest balance units; there is no assumed decimal
token scale. The current execution policy burns **one unit per successful payment**.
`nonce` is the account's next sender nonce. `expires-at` is the last block height
at which the transaction may execute, inclusive. Zero amounts, zero recipients,
exhausted nonces and amount-plus-fee overflow are rejected before saving.
Self-payments use one canonical account access key and still incur the fee and
advance the nonce.

## Local test network example

Create a fresh devnet with `cli devnet ./wallet-devnet 4 --observer` and start its
five commands in `START.txt`. These are **public test wallet and consensus keys**;
only the separately generated TLS identities are random secrets.

New devnets now fund the domain-separated wallet address used by signed-payment
execution. Older devnet generators allocated to a raw public-key hash, whose
balance cannot be spent by this wallet. Create a fresh devnet in a new directory
to use the corrected allocation; existing genesis, chain files and signing
journals must not be rewritten or mixed with the new genesis.

1. Run `cli wallet-address ./wallet-devnet/wallet.seed` and copy the displayed
   address into the account command.
2. Run `cli status 127.0.0.1:19000` and
   `cli account <sender-address> 127.0.0.1:19000`. The fresh devnet has chain ID 42,
   balance 1,000,000,000 and nonce 0.
3. Choose a nonzero destination address and an expiry height above the current
   head. For a fresh devnet, an example is:

   `cli sign-payment 42 ./wallet-devnet/wallet.seed <recipient-address> 123 0 10000 ./payment.bin`

4. Run `cli inspect-payment ./payment.bin`, then
   `cli submit ./payment.bin 127.0.0.1:19000`.
5. Query both accounts as blocks finalize. After this single payment the sender
   has balance 999,999,876 and nonce 1, and a fresh recipient has balance 123.

The commands work against validator and observer RPC endpoints. Submission via an
observer uses the existing payment gossip and certified execution path.

## Signing, persistence and retries

The seed file must contain exactly 32 raw bytes. Seed bytes are never accepted on
the command line or printed. Temporary seed buffers use zeroization; this does
not promise removal of every compiler/OS copy, memory locking, encryption at rest
or hardware-backed custody. Wallet key generation, encrypted keystores, backup
and recovery UX remain separate work.

Signing is offline: nonce, chain and expiry are explicit, and the current account
balance is not checked. The transaction contains the derived sender, public key,
recipient, amount, sorted/deduplicated account access list, deterministic resource
limits/prices, expiry and signature. Inspection checks the exact supported payment
policy and signature; it does not assert that the account is funded or the nonce
is currently usable.

Output creation is exclusive and never overwrites a seed or existing transaction.
The complete file is flushed before success is reported (with parent-directory
sync on Unix). A failed write can leave an incomplete file; inspect it before use.
Files read for submission/inspection are bounded to 64 KiB and decoded strictly.
Submission reads and validates once, so later filesystem changes do not replace
the transaction being sent.

Submission first reads the node's status and refuses a different chain ID or an
already expired payment. It then sends the saved bytes exactly once and compares
the returned transaction ID with the locally computed ID. There are **no automatic
retries, nonce increments or replacement signatures**. A matching remote error is
reported as rejection. A dropped connection, malformed reply or mismatched ID
after submission is an **unknown outcome**; retain the signed file and investigate
the node before retrying that same file.

`accepted (not finalized)` is admission, not a payment receipt. Account RPC reads
finalized state, but balance/nonce changes alone do not prove inclusion of a
particular transaction. There is not yet a transaction receipt/proof RPC, pending
nonce reservation, parallel sender workflow or finality-wait command. Other
transactions from the same sender can make an explicitly chosen nonce stale.

## Client and parser boundaries

`rpc::TcpRpcClient` implements the daemon's 4-byte little-endian length-prefixed
JSON-RPC framing, not HTTP. Each call opens one connection and uses a single
deadline across connection, request write and response read. The CLI uses five
seconds per call; the library accepts positive deadlines up to 60 seconds.
Numeric addresses avoid blocking DNS resolution. Responses are limited to 4 KiB,
and submitted canonical transactions to the network's 64 KiB limit.

Responses require JSON-RPC 2.0, the matching request ID and exactly one result or
error. Status, hashes and 16-byte canonical account states are type checked.
The shared integer-only JSON parser limits nesting to 32 levels and rejects
duplicate keys, leading zeros, invalid whitespace, raw control characters and
invalid Unicode escapes/surrogates. Supplementary Unicode characters round-trip.
Remote error messages are escaped before printing to a terminal.

RPC remains unauthenticated and unencrypted. Use a trusted local endpoint or a
separately secured tunnel. P2P mutual TLS does not authenticate RPC. Status and
account replies are claims of the contacted node, not light-client proofs.
The existing RPC server still needs public-network concurrency, deadlines,
authentication and rate-limit hardening. None of this change claims production
readiness or completes PoTB/VRF, rotating committees, contracts or independent
security review.

## Verification

CLI subprocess tests cover real devnet allocation and payment execution,
nonce replay rejection, self-payment access, malformed input, non-overwrite,
chain/expiry refusal, dropped replies and mismatched transaction IDs. Client
tests cover exact framing and canonical account decoding, malformed envelopes,
oversized/truncated input, terminal controls and slow-drip deadline enforcement.
The shared parser has depth, ambiguity and Unicode regression tests.

A local release-binary smoke test submitted a saved payment through an observer
to four mutually authenticated TLS validators. All five nodes exposed the same
finalized balances and nonces before and after process restart; replay was
rejected and the signed file remained byte-for-byte unchanged. These are local
reference-network checks, not public-network load or custody qualification.
