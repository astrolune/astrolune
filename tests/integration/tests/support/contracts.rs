// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Shared differential oracle for the bounded WebAssembly contract surface.
//!
//! The same source is compiled into the stable-toolchain contract mutation
//! campaign in `tests/integration/tests/contracts.rs` and into the
//! `execute_contract` libFuzzer target through `#[path]` source inclusion.
//! It is a differential oracle, not a crash-only harness: accepted modules must
//! validate to a recomputable commitment, execute identically twice on the same
//! finalized context and on a freshly built engine, reject forged modules and
//! reject every documented out-of-range call context.

use runtime::{
    ContractModule, MAX_HOST_IO, MAX_HOST_VALUE, MAX_INPUT_SIZE, MAX_OUTPUT_SIZE, MAX_WASM_MEMORY,
    ModuleValidator, RuntimeError, RuntimeVersion, WASM_VERSION, WasmCall, WasmRuntime,
    wasm_code_hash,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use types::{Address, Resources};

/// Candidate bound, matching the shared extension oracle's WASM gate.
const MAX_CANDIDATE: usize = 64 * 1024;
/// Largest fuel grant this oracle issues; far below the 10,000,000 call bound.
const MAX_FUEL: u64 = 100_000;
/// One unit above the largest accepted fuel grant.
const OVER_FUEL: u64 = 10_000_001;
/// Largest derived call input, keeping every round bounded.
const MAX_DERIVED_INPUT: u64 = 97;
/// Largest state or access cardinality accepted by the host.
const MAX_CONTEXT_KEYS: usize = 1024;
/// Largest state or access key accepted by the host.
const MAX_CONTEXT_KEY: usize = 256;
/// Contract-local key declared by the structured state and delete modules.
const CONTRACT_KEY: &[u8] = b"key";

/// A runtime identity that must never validate or execute anything.
const OTHER_VERSION: RuntimeVersion = RuntimeVersion {
    abi: WASM_VERSION.abi + 1,
    metering: WASM_VERSION.metering,
};

/// Returns the number of accepted contract oracle paths for `bytes`.
///
/// One path is counted for an accepted module and one more for an accepted
/// execution. Rejected candidates count zero; every assertion inside is a
/// property of the host boundary, not of a particular module.
pub fn check(bytes: &[u8]) -> usize {
    let runtime = shared_runtime();

    // The runtime identity gate precedes every other check, on every candidate.
    assert_eq!(
        runtime.validate(bytes, OTHER_VERSION),
        Err(RuntimeError::Unsupported),
        "a foreign runtime identity must never validate a module"
    );

    if bytes.len() > MAX_CANDIDATE || !bytes.starts_with(b"\0asm") {
        return 0;
    }

    let Ok(module) = runtime.validate(bytes, WASM_VERSION) else {
        return 0;
    };

    assert_eq!(module.version, WASM_VERSION);
    assert_eq!(module.code, bytes);
    assert_eq!(module.code_hash, wasm_code_hash(bytes));
    // The same commitment is recomputed inside execute_call; keep both agreeing.
    assert_eq!(module.code_hash, wasm_code_hash(&module.code));

    let plan = Plan::derive(bytes);
    let call = plan.call();

    // `WasmCall` is `Copy` and `WasmOutput` is `Eq`, so the identical finalized
    // context can be replayed and compared without reconstructing it.
    let first = runtime.execute_call(&module, call);
    assert_eq!(
        first,
        runtime.execute_call(&module, call),
        "a replayed call must return an identical output or error"
    );
    assert_eq!(
        first,
        WasmRuntime::new().execute_call(&module, call),
        "a freshly built engine must return an identical output or error"
    );

    assert_forgeries_rejected(runtime, &module, call);
    assert_bounds_rejected(runtime, &module, call);

    1 + usize::from(first.is_ok())
}

/// Lazily builds the process-wide engine once, as the extension oracle does.
fn shared_runtime() -> &'static WasmRuntime {
    static RUNTIME: OnceLock<WasmRuntime> = OnceLock::new();
    RUNTIME.get_or_init(WasmRuntime::new)
}

/// Asserts that a forged module is rejected rather than trusted.
fn assert_forgeries_rejected(runtime: &WasmRuntime, module: &ContractModule, call: WasmCall<'_>) {
    let mut forged = module.clone();
    forged.code_hash.0[0] ^= 1;
    assert_eq!(
        runtime.execute_call(&forged, call),
        Err(RuntimeError::InvalidModule),
        "a forged code commitment must not be trusted"
    );

    let mut forged = module.clone();
    forged.code.push(0x00);
    assert_eq!(
        runtime.execute_call(&forged, call),
        Err(RuntimeError::InvalidModule),
        "code substituted under a retained commitment must not be trusted"
    );

    let mut forged = module.clone();
    forged.version = OTHER_VERSION;
    assert_eq!(
        runtime.execute_call(&forged, call),
        Err(RuntimeError::Unsupported),
        "a foreign runtime identity must not execute"
    );
}

/// Asserts that every documented call bound rejects before the module runs.
fn assert_bounds_rejected(runtime: &WasmRuntime, module: &ContractModule, call: WasmCall<'_>) {
    let over = |value: usize| u64::try_from(value).unwrap() + 1;

    for limits in [
        Resources {
            compute: 0,
            ..call.limits
        },
        Resources {
            compute: OVER_FUEL,
            ..call.limits
        },
        Resources {
            memory: over(MAX_WASM_MEMORY),
            ..call.limits
        },
        Resources {
            io: MAX_HOST_IO + 1,
            ..call.limits
        },
        Resources {
            bandwidth: over(MAX_OUTPUT_SIZE),
            ..call.limits
        },
    ] {
        assert_eq!(
            runtime.execute_call(module, WasmCall { limits, ..call }),
            Err(RuntimeError::LimitExceeded),
            "an out-of-range resource grant must not execute"
        );
    }

    let rejected = rejections();
    assert_eq!(
        runtime.execute_call(
            module,
            WasmCall {
                input: &rejected.input,
                ..call
            }
        ),
        Err(RuntimeError::LimitExceeded),
        "an oversized call input must not execute"
    );
    for state in &rejected.states {
        assert_eq!(
            runtime.execute_call(module, WasmCall { state, ..call }),
            Err(RuntimeError::LimitExceeded),
            "an out-of-range state context must not execute"
        );
    }
    for access in &rejected.accesses {
        assert_eq!(
            runtime.execute_call(module, WasmCall { access, ..call }),
            Err(RuntimeError::LimitExceeded),
            "an out-of-range access declaration must not execute"
        );
    }
}

/// Deterministic, bounded call parameters derived from the candidate bytes.
struct Plan {
    /// Derived call input, at most [`MAX_DERIVED_INPUT`] bytes.
    input: Vec<u8>,
    /// Derived authenticated caller.
    caller: Address,
    /// Derived finalized height.
    height: u64,
    /// Derived contract-local state.
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Derived access declaration, deliberately a non-superset at times.
    access: BTreeSet<Vec<u8>>,
    /// Derived in-range resource grant.
    limits: Resources,
}

impl Plan {
    /// Derives one bounded context from the candidate's own commitment bytes.
    ///
    /// Deriving from the candidate makes each mutated input explore a different
    /// point in the accepted bound space while staying reproducible.
    fn derive(bytes: &[u8]) -> Self {
        let digest = crypto::blake2s_hash(bytes).0;
        let word =
            |index: usize| u64::from_le_bytes(digest[index * 8..index * 8 + 8].try_into().unwrap());
        let (selector, sizes, budget, height) = (word(0), word(1), word(2), word(3));

        let length = usize::try_from(selector % MAX_DERIVED_INPUT).unwrap();
        let input = (0..length)
            .map(|index| digest[index % digest.len()] ^ u8::try_from(index % 251).unwrap())
            .collect();

        let mut state = BTreeMap::new();
        for index in 0..usize::try_from(sizes % 5).unwrap() {
            let value = vec![digest[31 - index]; usize::try_from(sizes % 7).unwrap()];
            state.insert(vec![digest[index], u8::try_from(index).unwrap()], value);
        }

        let mut access = BTreeSet::new();
        if sizes & 1 == 0 {
            access.extend(state.keys().cloned());
        }
        if sizes & 2 == 0 {
            access.insert(CONTRACT_KEY.to_vec());
        }
        if sizes & 4 == 0 {
            state.insert(CONTRACT_KEY.to_vec(), vec![digest[0]; 3]);
        }

        Self {
            input,
            caller: Address(digest),
            height,
            state,
            access,
            limits: Resources {
                compute: 1 + budget % MAX_FUEL,
                memory: (budget / MAX_FUEL % 40) * 65_536,
                io: budget % 2_048,
                bandwidth: budget % 1_024,
            },
        }
    }

    /// Borrows the derived context as one finalized call.
    fn call(&self) -> WasmCall<'_> {
        WasmCall {
            input: &self.input,
            caller: self.caller,
            height: self.height,
            state: &self.state,
            access: &self.access,
            limits: self.limits,
        }
    }
}

/// Out-of-range contexts, built once because several are large.
struct Rejections {
    /// One byte above the accepted call input size.
    input: Vec<u8>,
    /// State contexts violating cardinality, key and value bounds.
    states: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Access declarations violating cardinality and key bounds.
    accesses: Vec<BTreeSet<Vec<u8>>>,
}

/// Lazily builds the out-of-range contexts shared by every round.
fn rejections() -> &'static Rejections {
    static REJECTIONS: OnceLock<Rejections> = OnceLock::new();
    REJECTIONS.get_or_init(Rejections::build)
}

impl Rejections {
    /// Builds one instance of every documented out-of-range context.
    fn build() -> Self {
        let keys: Vec<Vec<u8>> = (0..=MAX_CONTEXT_KEYS)
            .map(|index| u16::try_from(index).unwrap().to_le_bytes().to_vec())
            .collect();
        // Enough maximum-size values to exceed the combined I/O bound.
        let bulk = usize::try_from(MAX_HOST_IO).unwrap() / MAX_HOST_VALUE + 1;

        Self {
            input: vec![0; MAX_INPUT_SIZE + 1],
            states: vec![
                keys.iter().map(|key| (key.clone(), Vec::new())).collect(),
                BTreeMap::from([(Vec::new(), Vec::new())]),
                BTreeMap::from([(vec![1; MAX_CONTEXT_KEY + 1], Vec::new())]),
                BTreeMap::from([(vec![1], vec![0; MAX_HOST_VALUE + 1])]),
                (0..bulk)
                    .map(|index| (vec![u8::try_from(index).unwrap()], vec![0; MAX_HOST_VALUE]))
                    .collect(),
            ],
            accesses: vec![
                keys.into_iter().collect(),
                BTreeSet::from([Vec::new()]),
                BTreeSet::from([vec![1; MAX_CONTEXT_KEY + 1]]),
            ],
        }
    }
}
