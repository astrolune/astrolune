<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Certified state queries

`state_proof` takes a hexadecimal state key (at most 256 bytes) and returns a
hexadecimal `ALSTATE1` bundle. The daemon takes both witnesses and the finalized
header/certificate under the same publication lock. A bundle contains membership
or absence for the requested key, the same-state genesis commitment witness, and
the head's canonical header and precommit certificate. At height zero, the exact
materialized genesis root replaces the certificate.

`rpc::CertifiedStateProof::verify` authenticates the bundle against independently
supplied genesis, validator public keys, the exact requested key and a minimum
height. The reference verifier requires the complete fixed genesis committee.
An RPC response alone does not establish trust. A valid older certificate can be
replayed; callers must persist their last accepted height or choose a suitable
minimum. A proof does not establish that no newer block exists.

The binary envelope is bounded to 3 MiB. It uses explicit lengths, strict flags,
the canonical 200-byte block header and bounded versioned state witnesses.
Truncation, trailing bytes, altered witnesses, foreign genesis and insufficient
or forged certificates fail verification. JSON responses are bounded to 8 MiB;
the typed client enforces a whole-call deadline. Empty values and absent keys
remain distinct.

```
cli state-proof genesis.bin validators.bin <key-hex> <minimum-height> proof.bin 127.0.0.1:17331
cli verify-state-proof genesis.bin validators.bin <key-hex> <minimum-height> proof.bin
```

The fetch command verifies before creating its output file and never overwrites
an existing file. Validator files contain consecutive 32-byte Ed25519 public
keys. Proofs from the uncertified local demonstration mode cannot authenticate
post-genesis finality. A normal account query remains a convenience response;
use its `state::account_key` with a certified proof for independent verification.

Tests cover hostile framing and context changes, CLI offline verification, and
real certified daemon RPC queries before and after observer restart.
