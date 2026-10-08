<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Wallet v1 compatibility vector

`wallet-v1.bin` is a 144-byte public test fixture generated with the original
Argon2 0.5.3 and chacha20poly1305 0.10.1 providers. It is not a real wallet.
The seed/public key are RFC 8032 test vector 1. Password:
`astrolune-vault-fixture-v1`. The 40-byte random block occupies file bytes
24..64: the 16-byte salt is file bytes 24..40 (block bytes 0..16) and the
24-byte extended nonce is file bytes 40..64 (block bytes 16..40).
Argon2id v19 uses 65536 KiB, three iterations, one lane and a 32-byte key.
The first 96 bytes are XChaCha20-Poly1305 associated data. File byte 8 is the
wallet purpose; a consensus vault uses the same layout with a different value.

This fixture prevents a dependency upgrade from silently abandoning previously
created vaults. Never reuse its seed, salt, nonce or password for a real wallet.
