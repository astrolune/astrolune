<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Authenticated closed-network names

The registry is the ordinary ABI-v2 contract in
[`examples/contracts/name_registry.rs`](../examples/contracts/name_registry.rs).
It uses the allocation-free `contract_sdk::registry` transition function, which
is also the native reference for differential tests. No validator signing key
is needed by the resolver. Deployments require genesis `runtime_version: 2`.

## Names, ownership and expiry

Canonical names contain 1–63 lowercase ASCII letters, digits and internal
hyphens. Dots, controls, Unicode and leading/trailing hyphens are rejected.
The client normalizes outer whitespace and ASCII case; the contract accepts
only canonical names. Reserved system names and their numeric confusables
cannot be registered. The local state key is `dns/v1/` plus the name skeleton
(`0→o`, `1→l`, `3→e`, `5→s`, `8→b`). The lease stores its exact spelling, so an
occupied `alice` prevents registration of `a1ice` without making the second
spelling an alias during resolution.

Free or expired names are registered first-come by the authenticated transaction
sender. A live lease can be updated, renewed, transferred or released only by
its current owner. Transfer requires a nonzero destination. Expiration is
exclusive: a lease with expiry 100 is inactive at block 100. All durations use
finalized block heights, not seconds or local clocks. Each duration and the
remaining period after renewal are capped at 1,000,000 blocks; overflow fails.
Expired owners must register again and cannot renew or transfer an expired
lease. Release deletes the record immediately.

Records contain either a nonzero 32-byte account/contract address or 1–256
printable ASCII bytes describing an application service. Names are not public
Internet DNS names; the service does not implement recursive Internet DNS,
UDP port 53 or automatic fallback. No separate rent token is introduced;
ordinary contract execution fees apply.

## Deploy and use

```
cargo contract build examples/contracts/name_registry.rs registry.wasm
cli sign-deploy genesis.bin owner.vault registry.wasm <nonce> <tx-expiry> deploy.bin
cli submit deploy.bin <rpc-address>
```

Retain the displayed deployment address and artifact code hash as independent
trust anchors. The operator must wait for deployment finality before resolving.
The tool builds twice with the pinned compiler, explicit target features and
compressed linker relocations, then validates identical output bytes.

```
dns prepare register Alice 10000 service https://service.internal register-call
cli sign-call genesis.bin owner.vault <registry-address> register-call/input.bin register-call/keys.txt <nonce> <tx-expiry> 1000000 register.bin
cli submit register.bin <rpc-address>
dns resolve genesis.bin validators.bin <registry-address> <code-hash> alice <minimum-height> <rpc-address>
dns serve genesis.bin validators.bin <registry-address> <code-hash> 127.0.0.1:17553 <minimum-height> <rpc-address>
```

`dns prepare` also supports `update`, `renew`, `transfer` and `release`; see its
help for arguments. It creates a new directory with `input.bin` and `keys.txt`
and refuses to overwrite an existing directory. Key declarations are derived
from the same canonical name rules as the contract.

## Resolver authentication

The resolver fetches two [certified state proofs](32-certified-state-proofs.md):
one for the immutable deployed code and one for the contract-scoped name key.
Both must authenticate to the supplied genesis and validator registry. The code
must match the independently pinned code hash. The name proof must be at least
as recent as the code proof and the configured minimum height. Exact spelling,
record encoding, issuance height and expiration are checked before returning a
record. A confusable but differently spelled lease resolves as absent.

The running resolver remembers the highest verified height and rejects older
responses. On restart, supply the last accepted height as the minimum to retain
that protection. A valid proof does not establish the globally newest head;
freshness beyond the configured floor requires a reachable up-to-date peer.
Resolver TCP responses are convenience data; remote consumers needing their
own trust boundary should use the certified RPC proofs directly.

The local TCP service accepts one UTF-8 name plus LF per connection and returns
one JSON line. Names are bounded before allocation and read under a three-second
whole-request deadline. RPC calls have independent five-second whole-call
deadlines. Errors never trigger an unauthenticated/public-DNS fallback. Heights
and expirations are decimal JSON strings; record data is hexadecimal.

## Validation

Tests exercise canonical maximum sizes, every truncation, reserved/confusable
names, unauthorized mutations, transfers, renewals, expiry and overflow.
The actual Rust wasm32 contract is built and compared with native transitions
across successful and rejected calls. Resolver tests use real Ed25519 quorum
certificates and a running resolver process with framed RPC responses, including
wrong-code, wrong-name and stale-proof rejection.

The older `InMemoryResolver` remains a timestamp-based simulation API. The
operational binary exclusively uses `certified::CertifiedResolver` and the
versioned on-chain registry described here.
