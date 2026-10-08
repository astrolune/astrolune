// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Differential qualification oracle for the alternate engine profiles behind
//! the `RuntimeBackend` seam.
//!
//! Compiled into the stable-toolchain backend qualification campaign in
//! `tests/integration/tests/backends.rs` through `#[path]` source inclusion.
//! Each candidate is validated and executed by the reference interpreter and by
//! every profile in `EngineProfile::ALTERNATES`, and the complete ABI-v2
//! outputs are compared field by field: acceptance, error variant, return data,
//! events in order, staged writes, actually accessed keys and all four charged
//! resource classes. The narrower `RuntimeBackend` seam is compared separately
//! and is additionally pinned to the projection of the interpreter path.
//!
//! Every profile is the same Wasmi interpreter under a different value-stack
//! allocation strategy. None of them is an ahead-of-time compiler, a
//! just-in-time compiler, a SIMD backend or an independent implementation of
//! WebAssembly, and no such backend exists in this workspace. The campaign
//! therefore establishes configuration independence across the seam, nothing
//! about native code generation and nothing about throughput.

use runtime::{
    ContractModule, EngineProfile, ModuleValidator, RuntimeBackend, WASM_VERSION, WasmBackend,
    WasmCall, WasmRuntime, project_wasm_output, runtime_difference, wasm_difference,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use types::{Address, Resources};

/// Candidate bound, matching the contract oracle's WASM gate.
const MAX_CANDIDATE: usize = 64 * 1024;
/// Largest fuel grant this oracle issues; far below the 10,000,000 call bound.
const MAX_FUEL: u64 = 100_000;
/// Largest derived call input, keeping every round bounded.
const MAX_DERIVED_INPUT: u64 = 97;
/// Contract-local key declared by the structured state and delete modules.
const CONTRACT_KEY: &[u8] = b"key";

/// Differential counters accumulated across a whole campaign.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Compared {
    /// Candidates offered to the oracle.
    pub candidates: usize,
    /// Candidates the reference validator accepted.
    pub accepted_modules: usize,
    /// Validation results compared against the reference validator.
    pub validations: usize,
    /// Complete ABI-v2 executions compared against the reference interpreter.
    pub executions: usize,
    /// Compared executions the reference interpreter accepted.
    pub accepted: usize,
    /// Compared executions the reference interpreter rejected.
    pub rejected: usize,
    /// `RuntimeBackend` seam executions compared against the reference seam.
    pub seams: usize,
}

/// Compares every alternate engine profile against the reference interpreter
/// for one candidate module, accumulating into `totals`.
///
/// Rejected candidates still contribute compared validation results, because a
/// profile that accepts what the reference rejects is a consensus split.
pub fn check(bytes: &[u8], totals: &mut Compared) {
    totals.candidates += 1;

    if bytes.len() > MAX_CANDIDATE || !bytes.starts_with(b"\0asm") {
        return;
    }

    let reference = reference_runtime();
    let expected = reference.validate(bytes, WASM_VERSION);

    for alternate in alternate_runtimes() {
        assert_eq!(
            alternate.validate(bytes, WASM_VERSION),
            expected,
            "{:?} must agree with the reference validator",
            alternate.profile()
        );
        totals.validations += 1;
    }

    let Ok(module) = expected else {
        return;
    };
    totals.accepted_modules += 1;

    let plan = Plan::derive(bytes);
    let call = plan.call();
    let first = reference.execute_call(&module, call);
    if first.is_ok() {
        totals.accepted += EngineProfile::ALTERNATES.len();
    } else {
        totals.rejected += EngineProfile::ALTERNATES.len();
    }

    for alternate in alternate_runtimes() {
        assert_eq!(
            wasm_difference(&first, &alternate.execute_call(&module, call)),
            None,
            "{:?} must execute identically on module {:?}",
            alternate.profile(),
            module.code_hash
        );
        totals.executions += 1;
    }

    check_seam(&module, &plan, totals);
}

/// Compares the narrower `RuntimeBackend` seam and pins it to the projection of
/// the interpreter path, which is the only comparison `RuntimeOutput` supports.
fn check_seam(module: &ContractModule, plan: &Plan, totals: &mut Compared) {
    let (state, access) = (BTreeMap::new(), BTreeSet::new());
    let reference = WasmBackend::new(EngineProfile::Reference, plan.limits);
    let expected = reference.execute(module, &plan.input);

    let complete = reference
        .runtime()
        .execute_call(module, reference.seam_call(&plan.input, &state, &access));
    assert_eq!(
        expected,
        match &complete {
            Ok(output) => Ok(project_wasm_output(output)),
            Err(error) => Err(*error),
        },
        "the seam must return the projected interpreter output for {:?}",
        module.code_hash
    );

    for profile in EngineProfile::ALTERNATES {
        assert_eq!(
            runtime_difference(
                &expected,
                &WasmBackend::new(profile, plan.limits).execute(module, &plan.input)
            ),
            None,
            "{profile:?} must agree across the seam on module {:?}",
            module.code_hash
        );
        totals.seams += 1;
    }
}

/// Lazily builds the process-wide reference engine once.
fn reference_runtime() -> &'static WasmRuntime {
    static RUNTIME: OnceLock<WasmRuntime> = OnceLock::new();
    RUNTIME.get_or_init(WasmRuntime::new)
}

/// Lazily builds one engine per alternate profile, once for the whole campaign.
fn alternate_runtimes() -> &'static [WasmRuntime] {
    static RUNTIMES: OnceLock<Vec<WasmRuntime>> = OnceLock::new();
    RUNTIMES.get_or_init(|| {
        EngineProfile::ALTERNATES
            .into_iter()
            .map(WasmRuntime::with_profile)
            .collect()
    })
}

/// Asserts that the configurations measured to change charged compute are kept
/// out of the qualified set, so a future engine bump cannot silently admit one.
pub fn assert_disqualified_profiles_stay_excluded() {
    for profile in EngineProfile::DISQUALIFIED {
        assert!(
            !profile.is_consensus_neutral(),
            "{profile:?} must stay disqualified"
        );
        assert!(
            !EngineProfile::QUALIFIED.contains(&profile),
            "{profile:?} must not be listed as qualified"
        );
    }
    for profile in EngineProfile::ALTERNATES {
        assert!(
            profile.is_consensus_neutral() && EngineProfile::QUALIFIED.contains(&profile),
            "{profile:?} must be qualified before it is compared"
        );
    }
}

/// Deterministic, bounded call parameters derived from the candidate bytes.
///
/// Deriving from the candidate makes each mutated input explore a different
/// point in the accepted bound space while staying reproducible. Declarations
/// are withheld for some candidates so the trapping host paths are compared too.
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
    /// Derives one bounded context from the candidate's own digest.
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
