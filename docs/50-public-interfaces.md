<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 50. Public interface naming and compatibility

The 0.1 interface baseline was reviewed after live governance and checkpoint
recovery were implemented. The following names describe the supported boundaries;
they do not certify production readiness or alternate runtime implementations.
Rust crate versions remain 0.1. Wire compatibility is tracked separately through
explicit profile versions and frozen binary fixtures.

| Boundary | Public entry points | Meaning |
|---|---|---|
| Wire data | `codec::CanonicalDecode`, envelope `from_bytes`/`decode` | Bounded canonical decoding; callers still authenticate authority |
| Transaction admission | `transaction::SignedValidator` | Registered keys, signed prices, nonce and account checks |
| State | `state::StateDatabase`, `StateSnapshot`, `StateValueProof` | Atomic state transitions, immutable reads and membership/absence proofs |
| Persistence | `storage::ChainStorage`, `NodeStorage`, `Checkpoint` | Local durable chain state; a stored checkpoint is not a trust decision |
| Recovery authority | `node::network::RecoveryCheckpoint`, `StaticNetwork::with_checkpoint` | Independent pin and explicit trusted recovery boundary |
| Committee authority | `consensus::rotation::HandoffVerifier`, `potb_transition::PotbVerifier` | Sequential authenticated authority changes; application execution is separate |
| Governance | `GovernanceIntent`, `GovernanceApproval`, `GovernanceCertificate`, `GovernanceState` | Typed request, individual signature, incumbent quorum and delayed activation |
| Live contracts | `runtime::WasmRuntime`, `WasmCall`, `WasmOutput`, `WASM_VERSION` | Integer ABI-v2 validation, metering and staged host effects |
| Execution | `execution::ExecutionPolicy`, `execute_parallel`, `SignedSession` | Parent-authorized prices/capacity and deterministic signed execution |
| Network roles | `node::network::NetworkNode`, `node::observer::ObserverNode` | Voting participant and independently verifying non-voter |
| Signing | `keystore::DurableSigner` | Protected signing identity and durable anti-equivocation state |

## Demonstration compatibility

The original ABI-v1 byte transformation now has explicit names:
`DemoByteTransformBackend`, `DemoModuleValidator` and `DEMO_VERSION`. The existing
`InterpreterBackend`, `BasicModuleValidator` and `DEFAULT_VERSION` names remain
source-compatible aliases. Their behavior and old bytes do not change. They do
not validate or execute WASM and are not alternatives to the active `WasmRuntime`.
`RuntimeBackend` remains the legacy stateless interface; its `Aot`/`Jit` classes
are reserved declarations, not implemented backends. `FullNodeService` similarly
remains a local demonstration, as specified in the implementation status.

## Naming rules

- `decode`/`from_bytes` establish framing and canonical shape. Authentication is
  performed by `verify`, authenticated constructors or sequential verifier APIs.
  `RecoveryCheckpoint::from_bytes` additionally requires a caller-supplied pin.
- `sign`/`approve` state the signed action. `assemble` canonicalizes a collection
  and verifies its authority. A quorum certificate always authenticates every
  included signature, including signatures beyond the threshold.
- `stage`, proposal execution and runtime outputs describe private effects.
  `commit` publishes only after the corresponding durability boundary succeeds.
- Heights name finalized block positions; a verifier's current committee governs
  its next block. Epoch activation is specified explicitly, never inferred from
  wall-clock time or method names.
- Profile-specific names remain explicit (`Potb`, `Vrf`, `Wasm`). Changes to wire
  bytes, trust assumptions or metering require a new version/profile and fixtures.
- Future source renames retain aliases where semantics permit. Names must not
  imply a demonstration or merely declared optimization is operational.

The legacy codec method families are retained to preserve callers; superficial
method renaming must not change wire commitments. New public APIs must document
input authority, bounds, errors and whether they mutate durable or private state.
