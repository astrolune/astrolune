<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 41. Frozen protocol compatibility

The checked-in [corpus](../tests/integration/fixtures/protocol-v1/README.md)
contains 50 literal binary fixtures. It freezes two consecutive finalized payment
blocks in both supported network profiles, including the first rotating handoff
and a block finalized by the resulting smaller committee. Generation uses public
test seeds and fixed integer inputs; no clock, OS randomness or private material
enters the expected bytes.

| Boundary | Frozen coverage |
| --- | --- |
| Genesis | Versions 1 and 2, runtime 2, exact complete key registries |
| Transactions | Signed payment envelope, sequential nonces and transaction IDs |
| Finality | Headers, votes, quorum certificates and double-vote evidence |
| Networking | Complete finalized-block exchanges with genesis binding |
| Rotation | Current committee bytes, complete role-paired batches and handoffs |
| Execution metadata | Original `ALEFFECT` and rotating `ALEFF002` payloads |
| RPC proofs | Certified receipts plus state membership and absence |

Three Rust tests compare freshly executed output with every frozen file, verify
all signatures and proof authority from independently loaded genesis, and re-execute
both histories through the uncached reference path. They also check every truncation
of the certificate/evidence/handoff/network envelopes, trailing data and foreign
network identity. A fixed-profile receipt verifier must refuse rotating authority.
The generator only writes a new candidate directory; tests never update fixtures.

Two Python standard-library tests independently compute BLAKE2s hashes, parse
little-endian framing, derive genesis and block identities, and check parent,
transaction and receipt commitments. They do not invoke Rust or import its codecs.
This provides an independent commitment/framing check, not a second signature,
VRF or execution implementation. The manifest also rejects missing, unlisted or
duplicate binary files.

```text
cargo test -p integration --test compatibility
python -B -m unittest discover -s .github/scripts -p test_protocol_fixtures.py -v
cargo test -p integration --test mutations --release million_extension_mutations -- --ignored --nocapture
```

The 48 protocol objects (excluding the two raw key lists) also seed the shared
stable/libFuzzer decoder oracle. Together with the existing 16 seeds this gives
64 structured inputs. The oracle now also round-trips transactions, headers,
votes, certificates and evidence, and exercises network namespaces as untrusted
framing data. Authentication remains a separate test against trusted anchors.
On Windows/Rust 1.98.1, the deterministic one-million-input campaign completed
without failure and reached 299,431 accepted decoder paths. These paths are not
a coverage percentage. Coverage-guided sanitizer campaigns and Linux execution
remain separate qualification work.

## Change policy

Geneses 1 and 2, their signing domains and committed histories retain the behavior
captured here. New PoTB weights, admission rules and capacity/fee governance require
an explicitly activated protocol profile with its own fixtures; local observations
or an updated executable cannot reinterpret old committee authority. A change to
expected bytes must identify its new version and retain decoding/replay tests for
existing supported profiles. API type names alone do not provide wire compatibility.

Both CI test profiles execute the Rust suite. The native Linux/Windows build jobs
run the Python tests through the existing script-test gate. This change configures
those checks locally and does not claim that hosted runs have completed.

The [explicit PoTB producer profile](44-potb-state-transitions.md) now has eight
additional literal fixtures in `tests/integration/fixtures/potb-v1`, with its own
manifest, authenticated replay and independent Python framing/commitment checks.
Those objects do not replace or reinterpret this document's 50 legacy fixtures.
