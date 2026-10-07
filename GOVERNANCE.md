<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Governance

AstroLune is currently in an early contributor-driven phase. No foundation, council, token vote, binding on-chain governance system, or guaranteed maintainer group is declared by this repository.

## Current decision process

- Routine implementation decisions are made through reviewed pull requests.
- Public interface, dependency, and operational changes require relevant component review.
- Consensus, cryptography, canonical encoding, state commitments, runtime semantics, fees, adaptive capacity, and wallet authorization require a written design update before implementation is treated as normative.
- A merged interface is not automatically a frozen protocol standard.

## Design records

Material protocol decisions should state context, alternatives, safety/liveness implications, compatibility, activation, test vectors, and rollback limitations. Until a dedicated proposal directory is introduced, the relevant numbered document under `docs/` is the source of engineering intent.

## Conflicts and appeals

Contributors should first seek a technically testable resolution. If maintainers disagree, the conservative choice is to preserve existing compatibility and defer the change rather than silently split behavior. Conduct concerns follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md); vulnerabilities follow [`SECURITY.md`](SECURITY.md).

## Future governance

Before a public network, governance must define maintainers and review authority, protocol proposal lifecycle, emergency response, release signing, parameter changes, upgrade activation, validator admission and evidence appeals, conflicts of interest, and transparent decision records.
