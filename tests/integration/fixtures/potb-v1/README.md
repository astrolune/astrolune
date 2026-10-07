<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# PoTB profile compatibility fixtures

Eight literal binary objects freeze the explicit library/producer profile in
[document 44](../../../../docs/44-potb-state-transitions.md). They are separate
from the 50 genesis-v1/v2 fixtures. All keys are deterministic public test material.

The configuration uses chain 71, four initial keys, three target seats, one
replacement seat, and policy `(epoch=2, initial=10, increment=3, cap=20)`.
Height one ages and rotates the committee. Height two includes historical
double-vote evidence against seed 1 and incumbent-quorum admission of seed 99.
This yields a permanent exclusion, four eligible registered keys and a candidate
waiting until the next draw. Handoffs use a one-leaf policy-state tree; application
execution is tested independently in `crates/node/tests/potb.rs`.

`MANIFEST.blake2s` records each exact file's raw BLAKE2s-256 hash and byte count.
The Rust suite reproduces bytes and separately replays literal handoffs from the
trusted configuration. Python tests independently check framing, namespaces,
batch/history commitments and membership-age weights. Neither the manifest nor
Python framing tests substitute for signature/VRF verification.

To produce candidates for a new version in a **new** directory:

```text
cargo run -p integration --example export_potb -- target/potb-candidate
```

The exporter refuses an existing directory. Normal tests never regenerate or
rewrite fixtures. Changes to policy or canonical bytes require an explicitly
versioned compatibility decision, not refreshing expected bytes to pass a test.
