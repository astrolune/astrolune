// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Differential qualification oracle for the alternate engine profiles behind
//! the `RuntimeBackend` seam, and for the ahead-of-time artifact cache.
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
//! The same candidates then go through one process-wide `ArtifactCache` twice,
//! so every candidate is compared once as a cache miss and once as a cache hit.
//! The cache's bounds are far smaller than the number of distinct modules a
//! long campaign accepts, so generation retirement is exercised continuously
//! and is required to leave every compared field unchanged.
//!
//! Every engine profile is the same Wasmi interpreter under a different
//! value-stack allocation strategy, and the ahead-of-time path is that same
//! interpreter with translation hoisted out of the metered call. Neither is a
//! just-in-time compiler, a SIMD backend or an independent implementation of
//! WebAssembly, and no such backend exists in this workspace. The campaign
//! therefore establishes configuration independence across the seam and cache
//! transparency across the ahead-of-time path, nothing about native code
//! generation and nothing about throughput.

use runtime::{
    AotBackend, ArtifactCache, BackendKind, ContractModule, EngineProfile, ModuleValidator,
    RuntimeBackend, RuntimeError, WASM_VERSION, WasmBackend, WasmCall, WasmOutput, WasmRuntime,
    project_wasm_output, runtime_difference, wasm_difference,
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
/// Artifacts one cache generation retains during the campaign.
///
/// Deliberately far below the number of distinct modules a long campaign
/// accepts, so retirement happens thousands of times and every comparison
/// after it is a comparison across a fresh engine.
const CAMPAIGN_ARTIFACTS: usize = 64;
/// Canonical module bytes one cache generation retains during the campaign.
const CAMPAIGN_CODE_BYTES: usize = 1024 * 1024;

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
    /// Ahead-of-time validation results compared against the reference.
    pub aot_validations: usize,
    /// Ahead-of-time executions compared against the reference interpreter.
    pub aot_executions: usize,
    /// Ahead-of-time executions served from an artifact already held.
    pub aot_hits: usize,
    /// Ahead-of-time seam executions compared against the reference seam.
    pub aot_seams: usize,
    /// Generations the process-wide cache has retired so far.
    ///
    /// Cumulative across every campaign that ran in this process, because the
    /// cache is, so two campaigns in one process report the later one's figure
    /// including the earlier one's retirements.
    pub aot_retirements: usize,
}

/// Compares every alternate engine profile and the ahead-of-time artifact
/// cache against the reference interpreter for one candidate module,
/// accumulating into `totals`.
///
/// Rejected candidates still contribute compared validation results, because a
/// profile that accepts what the reference rejects is a consensus split, and
/// because an artifact must never be retained for a module the reference
/// rejects.
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
    assert_eq!(
        artifact_cache().validate(bytes, WASM_VERSION),
        expected,
        "the ahead-of-time cache must agree with the reference validator"
    );
    totals.aot_validations += 1;

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

    check_aot(&module, &plan, &first, totals);
    check_seam(&module, &plan, totals);
}

/// Compares the ahead-of-time path against the reference interpreter, once with
/// the artifact already held and once without.
///
/// A cold cache supplies the miss, so translating for this candidate is
/// compared on the complete `WasmOutput` and not only through the narrower
/// seam. The shared campaign cache then supplies the hits, and because its
/// bounds are far below the number of distinct modules a campaign accepts it
/// retires generations continuously while doing so.
fn check_aot(
    module: &ContractModule,
    plan: &Plan,
    expected: &Result<WasmOutput, RuntimeError>,
    totals: &mut Compared,
) {
    let cold = ArtifactCache::new();
    assert!(!cold.contains(&reference_runtime().artifact_key(module)));
    assert_eq!(
        wasm_difference(expected, &cold.execute(module, plan.call())),
        None,
        "the ahead-of-time path must execute identically on a cache miss for \
         module {:?}",
        module.code_hash
    );
    totals.aot_executions += 1;

    let cache = artifact_cache();
    let key = reference_runtime().artifact_key(module);
    for _ in 0..2 {
        let held = cache.contains(&key);
        assert_eq!(
            wasm_difference(expected, &cache.execute(module, plan.call())),
            None,
            "the ahead-of-time path must execute identically on module {:?}",
            module.code_hash
        );
        totals.aot_executions += 1;
        totals.aot_hits += usize::from(held);
    }

    let stats = cache.stats();
    assert!(
        stats.artifacts <= CAMPAIGN_ARTIFACTS,
        "the cache must stay inside its artifact bound"
    );
    assert!(
        stats.code_bytes <= CAMPAIGN_CODE_BYTES,
        "the cache must stay inside its byte bound"
    );
    totals.aot_retirements =
        usize::try_from(stats.retirements).expect("retirement count fits in a usize");

    // A fresh backend per candidate, matching `check_seam`, so the seam is
    // compared under the candidate's own derived grant, once cold and once warm.
    let backend = AotBackend::with_bounds(
        EngineProfile::Reference,
        plan.limits,
        CAMPAIGN_ARTIFACTS,
        CAMPAIGN_CODE_BYTES,
    )
    .expect("the reference profile translates ahead of the call");
    assert_eq!(backend.kind(), BackendKind::Aot);
    assert_ne!(
        backend.kind(),
        WasmBackend::new(EngineProfile::Reference, plan.limits).kind()
    );
    let seam = WasmBackend::new(EngineProfile::Reference, plan.limits).execute(module, &plan.input);
    for repeat in 0..2 {
        assert_eq!(
            runtime_difference(&seam, &backend.execute(module, &plan.input)),
            None,
            "the ahead-of-time seam execution {repeat} must agree with the \
             recompiling seam on module {:?}",
            module.code_hash
        );
        totals.aot_seams += 1;
    }
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

/// Lazily builds the process-wide ahead-of-time cache once.
///
/// One cache for the whole campaign is the point: a per-candidate cache would
/// only ever be compared cold, and would never exercise retirement or the reuse
/// of an artifact across unrelated candidates.
fn artifact_cache() -> &'static ArtifactCache {
    static CACHE: OnceLock<ArtifactCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        ArtifactCache::with_bounds(
            EngineProfile::Reference,
            CAMPAIGN_ARTIFACTS,
            CAMPAIGN_CODE_BYTES,
        )
        .expect("the reference profile translates ahead of the call")
    })
}

/// Asserts that the configurations measured to change charged compute are kept
/// out of the qualified set, so a future engine bump cannot silently admit one,
/// and that none of them can back the ahead-of-time cache.
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
        assert!(
            !profile.translates_ahead_of_the_call(),
            "{profile:?} defers translation into the call"
        );
        assert!(
            ArtifactCache::with_profile(profile).is_none(),
            "{profile:?} must not be allowed to back an artifact cache"
        );
        assert!(
            AotBackend::with_profile(profile, Resources::ZERO).is_none(),
            "{profile:?} must not be allowed to back the ahead-of-time backend"
        );
    }
    for profile in EngineProfile::ALTERNATES {
        assert!(
            profile.is_consensus_neutral() && EngineProfile::QUALIFIED.contains(&profile),
            "{profile:?} must be qualified before it is compared"
        );
        assert!(
            profile.translates_ahead_of_the_call(),
            "{profile:?} must translate ahead of the call before it is compared"
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
