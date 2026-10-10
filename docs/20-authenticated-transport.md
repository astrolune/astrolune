<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 20. Authenticated Peer Transport

## Implemented profile

The [certified reference daemon](19-reference-network.md) exchanges its existing version-1 packets over **TLS 1.3 with mandatory mutual certificate authentication**. Both outgoing and incoming connections require a certificate issued by the configured network CA. The implementation uses [rustls](https://docs.rs/rustls/0.23.45/rustls/) with its explicit ring provider and standard certificate verification. TLS 1.2, anonymous clients, session resumption, and early application data are disabled. No unverified certificate acceptance or automatic plaintext fallback is provided.

Transport admission and consensus authority are separate. A transport certificate admits a connection to this configured trust domain; it does not identify a genesis validator or grant voting power. Proposals, votes, transactions, and finalized certificates still pass their existing independent signature, genesis, committee, and execution checks. The fixed-committee reference deployment uses a provisioned CA; permissionless public peer admission remains a separate design task.

## Identity files and startup

Each peer supplies `--tls-dir <directory>` containing:

| File | Contents |
| --- | --- |
| `ca.der` | One trusted network root certificate in DER form |
| `cert.der` | One directly issued client/server leaf certificate in DER form |
| `key.der` | The corresponding private key in DER PKCS#8 form |

Each file is nonempty and bounded to 64 KiB. PEM files and intermediate certificate bundles are not accepted by this profile. Only the explicit root is trusted; the operating system's public root store is not used. The local certificate's chain, current validity, client/server usages, DNS service name, and private-key match are checked during startup, including `--dry-run`, before opening the signing journal or listeners. Certificate validity depends on the host's clock.

All peer certificates use the DNS SAN `astrolune-peer`. This is a network service identity; IP socket addresses select routes, not individual certificate identities. An authenticated member of the same CA domain can serve at any configured peer address. Per-address certificate pinning is not implemented. Certificate common names are operator labels with no consensus meaning.

Peers negotiate the exact ALPN value `astrolune/p2p/1` before application packets are accepted. Missing or mismatched ALPN, failed authentication, or incompatible TLS versions close the connection. Certificate and transport failures cannot authorize a chain change.

## Provisioning and migration

`cli devnet <new-directory> [validators]` now creates `node-N/tls` identities and includes `--tls-dir` in every generated start command. Its consensus and wallet seeds remain public deterministic test fixtures. Transport keys and the temporary CA key are independently generated with cryptographic randomness; transport private keys must remain secret. Certificates expire one year after generation.

To add transport security to an existing reference network without replacing its chain, consensus seeds, or signing journals:

```sh
cargo run -p cli -- init-network-tls target/network-tls 4
```

The command creates a new directory with `peer-1` through `peer-4`. Give each operator only its own peer directory and add `--tls-dir <peer-directory>` to that node's existing command. Preserve the original genesis, public validator registry, seed, data directory, and journal. Coordinate the restart of the configured peers. Existing output directories and files are never overwritten. Files are created with mode 0600 on Unix; Windows inherits the destination directory's ACL, which the operator must restrict.

The temporary issuing key is never saved by this command. Adding peers, renewing certificates, or replacing a compromised identity therefore requires a new bundle and a coordinated trust-root replacement, or an externally managed CA issuing compatible identities. Automated renewal, revocation lists, live reload, and overlapping trust-root rotation are not implemented. Restart is required to load replacement files. Changing transport keys does not reset consensus signing state.

For explicit local transport debugging only, `--allow-plaintext` can replace `--tls-dir`. These options are mutually exclusive. Both the listener and all configured peers must use loopback IP addresses; accepted sockets are also checked. Plaintext is never enabled because TLS setup or authentication failed. The separate local demonstration mode keeps its own behavior and is not a certified network.

## Bounds and integration

TCP connection establishment has a two-second timeout. The TLS handshake has its own absolute two-second deadline. Each request or response then has a separate absolute two-second deadline covering the length prefix, payload, record processing, and final flush. Partial reads, TLS records, and partial writes cannot reset these deadlines. Worker sockets explicitly use blocking I/O with deadlines, including sockets accepted by a nonblocking listener on Windows.

The existing 48-byte request, 8 MiB response, four-packet mailbox, 32 configured peers, 32 concurrent inbound workers, and eight accepts per consensus-loop iteration remain bounded. TLS handshakes execute outside the node mutex and count against the inbound worker bound. Polling reconnects every 50 ms and reauthenticates each new session. Persistent multiplexed sessions and public-network denial-of-service qualification remain open. RPC is unchanged and does not inherit P2P TLS; its default listener remains loopback.

Tests cover mutual authentication and multi-record transfer; unrelated CAs; missing and untrusted client identities; malformed, expired, wrong-name, wrong-usage and mismatched-key configuration; missing/wrong ALPN; plaintext rejection; stalled handshakes; trickled TLS records; inherited nonblocking sockets; provisioning without overwrite; and actual daemon quorum/payment/restart/late-join behavior over TLS. These checks do not constitute an independent security audit or public-network qualification.
