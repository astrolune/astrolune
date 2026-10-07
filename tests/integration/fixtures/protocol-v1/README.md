<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Protocol compatibility corpus 1

Frozen on 2026-10-02 with Rust 1.98.1. These 50 binary fixtures cover two finalized
payment blocks for genesis versions 1 (four fixed seats) and 2 (four registered
validators, three rotating seats). Both use chain ID 7 and runtime version 2.
Validator seeds are the public test values `[1; 32]` through `[4; 32]`; the funded
wallet uses `[99; 32]`. The recipient is `[77; 32]`, the absent address `[78; 32]`.
Each payment transfers 123 units. All resource capacities are 100,000. These keys
are test data, not operator credentials.

`MANIFEST.blake2s` records unkeyed BLAKE2s-256, length and relative path in sorted
order. Binary files must not undergo newline conversion. The tests never overwrite
this directory. To produce a separate review candidate:

```text
cargo run -p integration --example export_compatibility --release -- target/compatibility-review
cargo test -p integration --test compatibility
python -B -m unittest discover -s .github/scripts -p test_protocol_fixtures.py -v
```

The output directory must not already exist. Compare candidate bytes and semantic
changes before adding a separately versioned corpus; do not refresh expected files
just to make a compatibility failure pass. Preserve this corpus for old-profile
read/replay tests when adding a new protocol profile. Detailed scope is in
[document 41](../../../../docs/41-protocol-compatibility.md).
