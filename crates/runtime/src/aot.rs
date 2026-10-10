// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Ahead-of-time compiled contract artifacts: translation hoisted out of the
//! metered call, cached under [`ArtifactKey`], and executed by a backend that
//! reports [`BackendKind::Aot`].
//!
//! "Ahead of time" here means exactly one thing. A module is validated and
//! translated to Wasmi bytecode strictly before the call budget exists, so the
//! work cannot be charged to any call, and the resulting artifact is reused by
//! later calls so that no call translates anything at all. That is the exact
//! inverse of [`EngineProfile::LazyTranslation`] and [`EngineProfile::Lazy`],
//! which Wasmi 2.0.0 charges to the executing call's own fuel and which this
//! workspace measured and disqualified for that reason. Moving translation
//! earlier than the fuel budget is consensus-safe in the same way that moving
//! it later is not.
//!
//! This emits no native machine code. It is not a just-in-time compiler, not a
//! SIMD backend and not a second independent implementation of WebAssembly. The
//! executed code is the same pinned Wasmi 2.0.0 interpreter under the same
//! engine policy the reference profile pins: the same rejected proposals,
//! the same fuel schedule, the same 128-frame recursion cap and the same
//! 16,384-byte value stack cap. What changes is when translation happens and
//! how often, never what a call observes. A native-codegen backend is
//! impossible in this workspace, because `unsafe_code` is forbidden
//! workspace-wide and no safe interface can hand control to generated code.
//!
//! What this does NOT establish: a second WebAssembly implementation to
//! differentially test the first against, since both sides of every comparison
//! here share one interpreter, one translator and one fuel schedule; agreement
//! with a hypothetical native backend; a changed runtime version, accepted
//! instruction set, fuel schedule or charged compute, all of which are pinned
//! to be bit-identical to the reference interpreter; a bound on engine memory
//! across distinct modules beyond one cache generation; or any throughput
//! figure, which only `crates/runtime/benches/runtime.rs` measures and which
//! gates nothing.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use types::{Address, Hash256, Resources};
use wasmi::{Engine, Module};

use crate::alternate::project_wasm_output;
use crate::backend::{BackendKind, RuntimeBackend};
use crate::error::RuntimeError;
use crate::validator::ModuleValidator;
use crate::version::{ArtifactKey, ContractModule, RuntimeOutput, RuntimeVersion};
use crate::wasm::{
    EngineProfile, WASM_VERSION, WasmCall, WasmOutput, WasmRuntime, target_identity, validate_call,
    wasm_code_hash,
};

/// Artifacts one cache generation retains before it is retired.
pub const DEFAULT_CACHE_ARTIFACTS: usize = 256;

/// Canonical module bytes one cache generation retains before it is retired.
pub const DEFAULT_CACHE_CODE_BYTES: usize = 16 * 1024 * 1024;

/// A module validated and translated ahead of any metered call.
///
/// The artifact owns translated Wasmi bytecode belonging to one `Engine`
/// instance. It is cheap to clone, because the translated code is shared rather
/// than copied, and it carries the [`ArtifactKey`] it was produced under so a
/// caller can never mistake it for an artifact of another module, engine
/// configuration or target.
#[derive(Clone)]
pub struct CompiledArtifact {
    /// Cache identity: code hash, runtime version, compiler and target.
    key: ArtifactKey,
    /// Canonical module byte length, which the cache's byte bound counts.
    code_len: usize,
    /// Translated bytecode, bound to the engine that produced it.
    module: Module,
}

impl CompiledArtifact {
    /// Returns the cache identity this artifact was compiled under.
    #[must_use]
    pub fn key(&self) -> ArtifactKey {
        self.key
    }

    /// Returns the hash of the canonical module bytes.
    #[must_use]
    pub fn code_hash(&self) -> Hash256 {
        self.key.code_hash
    }

    /// Returns the canonical module byte length.
    ///
    /// This is the length of the WebAssembly input, not the size of the
    /// translated bytecode, which Wasmi does not expose.
    #[must_use]
    pub fn code_len(&self) -> usize {
        self.code_len
    }
}

impl fmt::Debug for CompiledArtifact {
    /// Prints the identity and the input length, never the translated bytecode.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledArtifact")
            .field("key", &self.key)
            .field("code_len", &self.code_len)
            .finish_non_exhaustive()
    }
}

impl WasmRuntime {
    /// Validates and translates `module` ahead of any metered call.
    ///
    /// This performs the same acceptance decision as
    /// [`ModuleValidator::validate`] and keeps the translated result. Under an
    /// eager profile every function body is translated here, so a later
    /// [`WasmRuntime::execute_artifact`] translates nothing and charges nothing
    /// for translation.
    ///
    /// # Errors
    /// Rejects forged module hashes and versions, malformed modules, forbidden
    /// imports or features, and modules exceeding the configured bounds, with
    /// the same [`RuntimeError`] variant [`WasmRuntime::execute_call`] returns.
    pub fn compile_artifact(
        &self,
        module: &ContractModule,
    ) -> Result<CompiledArtifact, RuntimeError> {
        if module.version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if module.code_hash != wasm_code_hash(&module.code) {
            return Err(RuntimeError::InvalidModule);
        }
        let compiled = self.compile(&module.code)?;
        Ok(CompiledArtifact {
            key: self.artifact_key(module),
            code_len: module.code.len(),
            module: compiled,
        })
    }

    /// Executes a prepared artifact without translating anything.
    ///
    /// The artifact must have been produced by this runtime's own engine. A
    /// runtime built from the same profile reports the same
    /// [`WasmRuntime::compiler_identity`] while holding a different `Engine`,
    /// and translated code cannot cross engines, so engine ownership is checked
    /// in addition to the compiler and target identities.
    ///
    /// # Errors
    /// Returns [`RuntimeError::Unsupported`] for an artifact of another runtime
    /// version, another engine configuration, another target or another engine
    /// instance, and otherwise the same variants as
    /// [`WasmRuntime::execute_call`] for exhausted resources, invalid pointers,
    /// undeclared accesses, nonzero returns and traps.
    pub fn execute_artifact(
        &self,
        artifact: &CompiledArtifact,
        call: WasmCall<'_>,
    ) -> Result<WasmOutput, RuntimeError> {
        if artifact.key.version != WASM_VERSION
            || artifact.key.compiler != self.compiler_identity()
            || artifact.key.target != target_identity()
            || !Engine::same(self.engine(), artifact.module.engine())
        {
            return Err(RuntimeError::Unsupported);
        }
        validate_call(&call)?;
        self.run(&artifact.module, call)
    }
}

/// Counters describing one cache's work, read under its lock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactCacheStats {
    /// Artifacts the live generation holds.
    pub artifacts: usize,
    /// Canonical module bytes the live generation holds.
    pub code_bytes: usize,
    /// Lookups served by an artifact already held.
    pub hits: u64,
    /// Lookups that had to translate a module.
    pub misses: u64,
    /// Translations performed, which equals the misses that were accepted.
    pub compilations: u64,
    /// Generations retired to stay inside the configured bounds.
    pub retirements: u64,
}

/// The live generation: one engine and the artifacts translated into it.
struct Generation {
    /// The engine every artifact in this generation belongs to.
    runtime: Arc<WasmRuntime>,
    /// Artifacts held, keyed by the identity they were compiled under.
    artifacts: HashMap<ArtifactKey, CompiledArtifact>,
    /// Canonical module bytes held.
    code_bytes: usize,
    /// Accumulated counters, which survive retirement.
    stats: ArtifactCacheStats,
}

impl Generation {
    /// Retires this generation in full and installs a fresh engine.
    ///
    /// Partial eviction would bound the map and not the memory. Wasmi 2.0.0's
    /// code map allocates translated function bodies into the engine and offers
    /// no removal, so dropping one artifact leaves its bytecode in the engine
    /// forever. Dropping the engine together with every artifact built on it is
    /// the only rule that actually reclaims translated code, which is why
    /// retirement is all-or-nothing.
    fn retire(&mut self, profile: EngineProfile) {
        self.artifacts = HashMap::new();
        self.code_bytes = 0;
        self.runtime = Arc::new(WasmRuntime::with_profile(profile));
        self.stats.retirements += 1;
    }
}

/// A bounded, generational cache of modules compiled ahead of any metered call.
///
/// The cache is keyed on [`ArtifactKey`], so an artifact is reused only for the
/// same canonical code under the same runtime version, the same engine
/// configuration and the same target. Two of those four fields exist precisely
/// to stop reuse across a change that a code hash cannot see.
///
/// Its contents depend only on the sequence of translations, never on the order
/// of hits or on how concurrent callers interleave: a hit mutates counters and
/// nothing else, and a miss either inserts or retires-then-inserts according to
/// the configured bounds alone. Calls execute outside the lock, so a retired
/// generation stays alive until the last call holding one of its artifacts
/// finishes.
///
/// A cache may only be built on a consensus-neutral profile. Under
/// [`EngineProfile::DISQUALIFIED`] Wasmi defers translation into the call, so a
/// first call through a fresh artifact would be charged for translating a body
/// that a later call through the same artifact finds already translated; the
/// charge would then depend on cache state. `crates/runtime/tests/aot.rs`
/// measures that difference and this constructor refuses those profiles.
pub struct ArtifactCache {
    /// Profile every generation's engine is built with.
    profile: EngineProfile,
    /// Artifacts one generation retains before it is retired.
    artifacts: usize,
    /// Canonical module bytes one generation retains before it is retired.
    code_bytes: usize,
    /// The live generation and the accumulated counters.
    state: Mutex<Generation>,
}

impl Default for ArtifactCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactCache {
    /// Creates a cache on [`EngineProfile::Reference`] with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::build(
            EngineProfile::Reference,
            DEFAULT_CACHE_ARTIFACTS,
            DEFAULT_CACHE_CODE_BYTES,
        )
    }

    /// Creates a cache on one profile with the default bounds.
    ///
    /// Returns [`None`] for a profile that does not translate ahead of the
    /// call, because such a profile would make a charge depend on cache state.
    #[must_use]
    pub fn with_profile(profile: EngineProfile) -> Option<Self> {
        Self::with_bounds(profile, DEFAULT_CACHE_ARTIFACTS, DEFAULT_CACHE_CODE_BYTES)
    }

    /// Creates a cache on one profile with explicit bounds.
    ///
    /// Returns [`None`] for a profile that does not translate ahead of the
    /// call, or for a zero bound, which would retire a generation on every
    /// translation.
    #[must_use]
    pub fn with_bounds(
        profile: EngineProfile,
        artifacts: usize,
        code_bytes: usize,
    ) -> Option<Self> {
        if !profile.translates_ahead_of_the_call() || artifacts == 0 || code_bytes == 0 {
            return None;
        }
        Some(Self::build(profile, artifacts, code_bytes))
    }

    /// Builds a cache without checking the profile, for the infallible entry.
    fn build(profile: EngineProfile, artifacts: usize, code_bytes: usize) -> Self {
        Self {
            profile,
            artifacts,
            code_bytes,
            state: Mutex::new(Generation {
                runtime: Arc::new(WasmRuntime::with_profile(profile)),
                artifacts: HashMap::new(),
                code_bytes: 0,
                stats: ArtifactCacheStats::default(),
            }),
        }
    }

    /// Returns the engine tuning profile every generation is built with.
    #[must_use]
    pub fn profile(&self) -> EngineProfile {
        self.profile
    }

    /// Returns the artifact count and module byte bounds of one generation.
    #[must_use]
    pub fn bounds(&self) -> (usize, usize) {
        (self.artifacts, self.code_bytes)
    }

    /// Returns the accumulated counters and the live generation's occupancy.
    #[must_use]
    pub fn stats(&self) -> ArtifactCacheStats {
        let state = self.state();
        ArtifactCacheStats {
            artifacts: state.artifacts.len(),
            code_bytes: state.code_bytes,
            ..state.stats
        }
    }

    /// Returns whether the live generation holds an artifact for `key`.
    #[must_use]
    pub fn contains(&self, key: &ArtifactKey) -> bool {
        self.state().artifacts.contains_key(key)
    }

    /// Retires the live generation, dropping its engine and every artifact.
    ///
    /// A call already executing keeps the artifact and engine it started with,
    /// so retirement cannot change a result in flight or any result at all.
    pub fn retire(&self) {
        self.state().retire(self.profile);
    }

    /// Translates `module` ahead of any call and retains the artifact.
    ///
    /// Use this at deployment, so the first call to a contract is already a
    /// cache hit. Returns the identity the artifact is held under.
    ///
    /// # Errors
    /// Returns the same variants as [`WasmRuntime::compile_artifact`].
    pub fn prepare(&self, module: &ContractModule) -> Result<ArtifactKey, RuntimeError> {
        self.resolve(module).map(|(_, artifact)| artifact.key)
    }

    /// Executes one finalized call against a cached or newly built artifact.
    ///
    /// The result is identical on a hit and on a miss, which is the property
    /// that makes the cache invisible to consensus. Translation happens before
    /// the call's fuel budget is installed in either case.
    ///
    /// # Errors
    /// Returns the same variants as [`WasmRuntime::execute_call`], in the same
    /// order: the module's version and hash, then its acceptance, then the
    /// call's bounds.
    pub fn execute(
        &self,
        module: &ContractModule,
        call: WasmCall<'_>,
    ) -> Result<WasmOutput, RuntimeError> {
        let (runtime, artifact) = self.resolve(module)?;
        runtime.execute_artifact(&artifact, call)
    }

    /// Returns the live generation's engine and an artifact for `module`.
    ///
    /// The engine handle is returned alongside the artifact so the caller can
    /// execute outside the lock against the engine the artifact belongs to,
    /// even if the generation is retired in the meantime.
    fn resolve(
        &self,
        module: &ContractModule,
    ) -> Result<(Arc<WasmRuntime>, CompiledArtifact), RuntimeError> {
        if module.version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if module.code_hash != wasm_code_hash(&module.code) {
            return Err(RuntimeError::InvalidModule);
        }
        let mut state = self.state();
        let key = state.runtime.artifact_key(module);
        if let Some(artifact) = state.artifacts.get(&key) {
            let found = artifact.clone();
            state.stats.hits += 1;
            return Ok((Arc::clone(&state.runtime), found));
        }
        state.stats.misses += 1;

        // A module larger than the whole byte bound is never retained, so
        // retiring for it would retire on every call without ever caching it.
        let retainable = module.code.len() <= self.code_bytes;
        if retainable
            && (state.artifacts.len() >= self.artifacts
                || module.code.len() > self.code_bytes - state.code_bytes)
        {
            state.retire(self.profile);
        }
        let runtime = Arc::clone(&state.runtime);
        let artifact = runtime.compile_artifact(module)?;
        state.stats.compilations += 1;
        if retainable {
            state.code_bytes += artifact.code_len;
            state.artifacts.insert(key, artifact.clone());
        }
        Ok((runtime, artifact))
    }

    /// Locks the live generation, recovering a poisoned lock.
    ///
    /// An artifact is inserted only after it has been produced and the byte
    /// total is updated in the same statement, so a panic inside translation
    /// cannot leave the generation inconsistent. Recovering is therefore
    /// preferable to failing a call that has nothing wrong with it.
    fn state(&self) -> MutexGuard<'_, Generation> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ModuleValidator for ArtifactCache {
    /// Validates canonical bytes and retains the translated artifact.
    ///
    /// The acceptance decision is exactly [`WasmRuntime`]'s. Retaining the
    /// artifact is a side effect, so a deployment that is later rejected for an
    /// unrelated reason can leave an artifact for code that never reached
    /// state; it is keyed by that code's hash, bounded with every other
    /// artifact, and cannot be reached by any other module.
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError> {
        if version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        let module = ContractModule {
            code_hash: wasm_code_hash(bytes),
            version,
            code: bytes.to_vec(),
        };
        self.resolve(&module)?;
        Ok(module)
    }
}

/// Executes ahead-of-time compiled ABI-v2 WebAssembly behind the legacy
/// [`RuntimeBackend`] seam, reporting [`BackendKind::Aot`].
///
/// This is the only backend in the workspace that may report that class, and it
/// reports it for one reason: translation is complete before a call's fuel
/// budget exists, and a call performs none. It still emits no native machine
/// code, so it is not a just-in-time or SIMD backend, and `kind` says nothing
/// about throughput.
///
/// Like [`crate::WasmBackend`], the seam carries no caller, no finalized
/// height, no contract-local state and no access declaration, so every call
/// runs against [`Address::ZERO`], height zero, empty state and an empty access
/// set under the fixed grant supplied at construction. State helpers therefore
/// trap exactly as they do for an undeclared key, and the seam is usable for
/// equivalence qualification rather than for production execution, which goes
/// through [`ArtifactCache::execute`] with a real finalized context.
pub struct AotBackend {
    /// Bounded cache of modules compiled ahead of any call.
    cache: ArtifactCache,
    /// Fixed deterministic grant applied to every seam call.
    limits: Resources,
}

impl AotBackend {
    /// Creates a backend on [`EngineProfile::Reference`] with default bounds.
    #[must_use]
    pub fn new(limits: Resources) -> Self {
        Self {
            cache: ArtifactCache::new(),
            limits,
        }
    }

    /// Creates a backend on one profile with the default cache bounds.
    ///
    /// Returns [`None`] for exactly the profiles [`ArtifactCache::with_profile`]
    /// refuses.
    #[must_use]
    pub fn with_profile(profile: EngineProfile, limits: Resources) -> Option<Self> {
        ArtifactCache::with_profile(profile).map(|cache| Self { cache, limits })
    }

    /// Creates a backend on one profile with explicit cache bounds.
    ///
    /// Returns [`None`] for exactly the inputs [`ArtifactCache::with_bounds`]
    /// refuses.
    #[must_use]
    pub fn with_bounds(
        profile: EngineProfile,
        limits: Resources,
        artifacts: usize,
        code_bytes: usize,
    ) -> Option<Self> {
        ArtifactCache::with_bounds(profile, artifacts, code_bytes)
            .map(|cache| Self { cache, limits })
    }

    /// Borrows the cache, so complete ABI-v2 outputs can be compared.
    #[must_use]
    pub fn cache(&self) -> &ArtifactCache {
        &self.cache
    }

    /// Returns the engine tuning profile this backend was built with.
    #[must_use]
    pub fn profile(&self) -> EngineProfile {
        self.cache.profile()
    }

    /// Returns the finalized call context the seam executes, for the input.
    ///
    /// Exposed so a caller can run the same context through
    /// [`ArtifactCache::execute`] and check that the seam result is the
    /// [`project_wasm_output`] projection of the complete output.
    #[must_use]
    pub fn seam_call<'a>(
        &self,
        input: &'a [u8],
        state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
        access: &'a BTreeSet<Vec<u8>>,
    ) -> WasmCall<'a> {
        WasmCall {
            input,
            caller: Address::ZERO,
            height: 0,
            state,
            access,
            limits: self.limits,
        }
    }
}

impl RuntimeBackend for AotBackend {
    fn kind(&self) -> BackendKind {
        // Translation completes before any call budget exists and a call
        // performs none, which is what this class asserts. No native machine
        // code is emitted, which is why Jit stays unclaimed.
        BackendKind::Aot
    }

    fn execute(
        &self,
        module: &ContractModule,
        input: &[u8],
    ) -> Result<RuntimeOutput, RuntimeError> {
        let state = BTreeMap::new();
        let access = BTreeSet::new();
        self.cache
            .execute(module, self.seam_call(input, &state, &access))
            .map(|output| project_wasm_output(&output))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AotBackend, ArtifactCache, ArtifactCacheStats, BackendKind, EngineProfile, Resources,
        RuntimeBackend,
    };
    use crate::wasm::{WASM_ENGINE_FEATURES, WASM_ENGINE_VERSION};

    /// The manifest of the crate under test, read at compile time.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Grant used by the seam tests; far below the call bounds.
    const LIMITS: Resources = Resources {
        compute: 1_000_000,
        memory: 1_048_576,
        io: 65_536,
        bandwidth: 65_536,
    };

    #[test]
    fn the_declared_engine_pin_matches_the_manifest() {
        let features = WASM_ENGINE_FEATURES
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let expected = format!(
            "wasmi = {{ version = \"={WASM_ENGINE_VERSION}\", \
             default-features = false, features = [{features}] }}"
        );
        assert!(
            MANIFEST.lines().any(|line| line == expected),
            "the compiler identity declares `{expected}`, which is not a line of \
             crates/runtime/Cargo.toml; the engine pin and the declared identity \
             must be changed together"
        );
    }

    #[test]
    fn only_profiles_that_translate_ahead_of_the_call_may_back_a_cache() {
        for profile in EngineProfile::QUALIFIED {
            assert!(
                ArtifactCache::with_profile(profile).is_some(),
                "{profile:?} translates eagerly and must be accepted"
            );
            assert!(
                AotBackend::with_profile(profile, LIMITS).is_some(),
                "{profile:?} must also back an AOT backend"
            );
        }
        for profile in EngineProfile::DISQUALIFIED {
            assert!(
                ArtifactCache::with_profile(profile).is_none(),
                "{profile:?} defers translation into the call and must be refused"
            );
            assert!(
                AotBackend::with_profile(profile, LIMITS).is_none(),
                "{profile:?} must not back an AOT backend either"
            );
        }
    }

    #[test]
    fn zero_bounds_are_refused_so_a_generation_cannot_retire_on_every_call() {
        assert!(ArtifactCache::with_bounds(EngineProfile::Reference, 0, 1).is_none());
        assert!(ArtifactCache::with_bounds(EngineProfile::Reference, 1, 0).is_none());
        assert!(ArtifactCache::with_bounds(EngineProfile::Reference, 1, 1).is_some());
        assert!(AotBackend::with_bounds(EngineProfile::Reference, LIMITS, 0, 1).is_none());
        assert!(AotBackend::with_bounds(EngineProfile::Reference, LIMITS, 1, 1).is_some());
    }

    #[test]
    fn a_fresh_cache_reports_its_profile_bounds_and_empty_counters() {
        let cache = ArtifactCache::new();
        assert_eq!(cache.profile(), EngineProfile::Reference);
        assert_eq!(
            cache.bounds(),
            (
                super::DEFAULT_CACHE_ARTIFACTS,
                super::DEFAULT_CACHE_CODE_BYTES
            )
        );
        assert_eq!(cache.stats(), ArtifactCacheStats::default());

        let backend = AotBackend::new(LIMITS);
        assert_eq!(backend.profile(), EngineProfile::Reference);
        assert_eq!(backend.cache().stats(), ArtifactCacheStats::default());
        assert_eq!(backend.kind(), BackendKind::Aot);
    }

    #[test]
    fn retirement_counts_a_generation_and_empties_the_live_one() {
        let cache = ArtifactCache::new();
        cache.retire();
        assert_eq!(
            cache.stats(),
            ArtifactCacheStats {
                retirements: 1,
                ..ArtifactCacheStats::default()
            }
        );
    }

    #[test]
    fn the_aot_backend_is_send_and_sync_behind_the_seam() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ArtifactCache>();
        assert_send_sync::<AotBackend>();
        assert_send_sync::<super::CompiledArtifact>();
        let backend: Box<dyn RuntimeBackend> = Box::new(AotBackend::new(LIMITS));
        assert_eq!(backend.kind(), BackendKind::Aot);
    }
}
