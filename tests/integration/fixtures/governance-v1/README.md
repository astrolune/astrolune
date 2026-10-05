<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# Governance compatibility corpus

Eighteen literal objects freeze the explicit PoTB configuration-v2 namespace,
quorum intent/approval/certificate, network tag 8 and three transitions spanning
the first governance epoch. All signing keys are public deterministic test keys.

`MANIFEST.blake2s` records the exact size and unkeyed BLAKE2s-256 of each object.
The Rust compatibility test regenerates the objects, compares exact bytes and
authenticates the handoff chain from the supplied configuration. Changes require
an explicit compatibility decision; never automatically regenerate these files
to make a failing test pass.

The `export_governance` example writes candidates into a new directory only.
See [parameter governance](../../../../docs/48-parameter-governance.md).
