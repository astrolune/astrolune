// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Integer-only WebAssembly contracts with a bounded, deterministic host ABI.

use std::collections::{BTreeMap, BTreeSet};

use types::{Address, Hash256, Resources};
use wasmi::{
    Caller, CompilationMode, Config, Engine, ExternType, Linker, Memory, Module, Store,
    StoreLimits, StoreLimitsBuilder, ValType,
};

use crate::{
    ArtifactKey, ContractModule, MAX_INPUT_SIZE, MAX_MODULE_SIZE, MAX_OUTPUT_SIZE, ModuleValidator,
    RuntimeError, RuntimeVersion,
};

/// WebAssembly host ABI v2 and pinned Wasmi 2.0.0 metering schedule v1.
pub const WASM_VERSION: RuntimeVersion = RuntimeVersion {
    abi: 2,
    metering: 1,
};
/// Maximum linear memory in bytes (256 WebAssembly pages).
pub const MAX_WASM_MEMORY: usize = 16 * 1024 * 1024;
/// Maximum state value or event body in bytes.
pub const MAX_HOST_VALUE: usize = 64 * 1024;
/// Maximum combined state I/O per call, in bytes.
pub const MAX_HOST_IO: u64 = 1024 * 1024;
/// Maximum call frames. Part of the runtime identity: the frame at which a
/// `StackOverflow` trap is raised is consensus-visible.
const MAX_RECURSION_DEPTH: usize = 128;
/// Maximum value stack height in bytes. Part of the runtime identity for the
/// same reason as [`MAX_RECURSION_DEPTH`].
const MAX_STACK_HEIGHT: usize = 16_384;
/// Cached engine stacks kept for reuse by the reference profile.
const REFERENCE_CACHED_STACKS: usize = 2;

/// Pinned Wasmi release the compiler identity commits to.
///
/// `crates/runtime/Cargo.toml` pins `wasmi = "=2.0.0"`, and the
/// `the_declared_engine_pin_matches_the_manifest` test asserts that this
/// constant, [`WASM_ENGINE_FEATURES`] and that manifest line agree. The engine
/// therefore cannot be bumped without moving every compiler identity, which is
/// what stops an artifact compiled by one release from being reused by another.
pub const WASM_ENGINE_VERSION: &str = "2.0.0";

/// Pinned Wasmi cargo features, in manifest order.
///
/// Wasmi derives its default proposal set from its cargo features, so `simd`,
/// `relaxed-simd` and `memory64` are rejected because those features are off
/// rather than because a `Config` call disables them. An enabled cargo feature
/// would change the accepted instruction set without changing any engine
/// setting this runtime applies, so the feature list is part of the compiler
/// identity.
pub const WASM_ENGINE_FEATURES: [&str; 5] = [
    "stable",
    "std",
    "validate",
    "portable-dispatch",
    "prefer-btree-collections",
];

/// Engine tuning axes an alternate backend may vary.
///
/// Every profile pins one runtime identity: the same rejected WebAssembly
/// proposals, the same fuel schedule, the same 128-frame recursion cap and the
/// same 16,384-byte value stack cap. [`Self::QUALIFIED`] lists the profiles
/// that are measurably indistinguishable from [`Self::Reference`];
/// [`Self::DISQUALIFIED`] lists configurations that are retained only so the
/// qualification campaign can keep asserting that they do differ.
///
/// Two axes are consensus-neutral and are varied: the initial value-stack
/// height and the number of engine stacks kept for reuse. Both are allocation
/// strategies that a contract cannot observe.
///
/// Four axis classes are excluded. The recursion cap and the maximum value
/// stack height decide where a `StackOverflow` trap occurs, which is directly
/// observable in a call's result. The fuel and operator cost schedules define
/// charged compute. The enforced parsing limits and custom-section handling
/// decide which modules validate. The WebAssembly proposal toggles define the
/// accepted instruction set. Varying any of them would be a runtime-version
/// change rather than a backend choice.
///
/// Compilation strategy was expected to be neutral and measurably is not; see
/// [`Self::LazyTranslation`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineProfile {
    /// Reference configuration built by [`WasmRuntime::new`]: eager
    /// compilation, a value stack that grows from the Wasmi default initial
    /// height, and two cached engine stacks.
    Reference,
    /// Eager compilation with the value stack preallocated to its 16,384-byte
    /// maximum instead of growing from the Wasmi default initial height.
    PreallocatedStack,
    /// Eager compilation with engine stack pooling disabled.
    UnpooledStack,
    /// Both neutral axes moved at once: a preallocated value stack and no
    /// engine stack pooling.
    Alternate,
    /// Eager validation with per-function translation deferred to first call.
    ///
    /// Not consensus-neutral. Wasmi 2.0.0 charges the deferred translation to
    /// the executing call's fuel, so `Resources::compute` grows with the size
    /// of the translated body. Selecting this profile for execution would fork
    /// the chain. It is public only so the campaign can pin the measurement.
    LazyTranslation,
    /// Validation and translation both deferred to first call.
    ///
    /// Not consensus-neutral, for the same reason as [`Self::LazyTranslation`]
    /// and by a larger margin, because the deferred validation is charged too.
    Lazy,
}

impl EngineProfile {
    /// Profiles measurably indistinguishable from [`Self::Reference`], which is
    /// listed first.
    pub const QUALIFIED: [Self; 4] = [
        Self::Reference,
        Self::PreallocatedStack,
        Self::UnpooledStack,
        Self::Alternate,
    ];
    /// The qualified profiles other than [`Self::Reference`].
    pub const ALTERNATES: [Self; 3] = [
        Self::PreallocatedStack,
        Self::UnpooledStack,
        Self::Alternate,
    ];
    /// Configurations measured to change consensus-visible charged compute.
    pub const DISQUALIFIED: [Self; 2] = [Self::LazyTranslation, Self::Lazy];

    /// Returns whether this profile may be selected for live execution.
    #[must_use]
    pub fn is_consensus_neutral(self) -> bool {
        match self {
            Self::Reference | Self::PreallocatedStack | Self::UnpooledStack | Self::Alternate => {
                true
            }
            Self::LazyTranslation | Self::Lazy => false,
        }
    }

    /// Returns the Wasmi compilation strategy this profile selects.
    #[must_use]
    pub fn compilation_mode(self) -> CompilationMode {
        match self {
            Self::Reference | Self::PreallocatedStack | Self::UnpooledStack | Self::Alternate => {
                CompilationMode::Eager
            }
            Self::LazyTranslation => CompilationMode::LazyTranslation,
            Self::Lazy => CompilationMode::Lazy,
        }
    }

    /// Returns whether the value stack starts at its 16,384-byte maximum
    /// instead of growing from the Wasmi default initial height.
    #[must_use]
    pub fn preallocates_stack(self) -> bool {
        matches!(self, Self::PreallocatedStack | Self::Alternate)
    }

    /// Returns whether this profile completes translation before a call starts.
    ///
    /// Eager compilation translates every function body while the module is
    /// compiled, which is strictly before any call's fuel budget exists. The
    /// deferred strategies translate inside the call and are charged for it, so
    /// an artifact reused across calls would be charged more on its first use
    /// than on its later ones and a charge would depend on cache state. Only a
    /// profile that answers `true` may back a [`crate::ArtifactCache`].
    #[must_use]
    pub fn translates_ahead_of_the_call(self) -> bool {
        matches!(self.compilation_mode(), CompilationMode::Eager)
    }

    /// Returns how many engine stacks this profile keeps for reuse.
    #[must_use]
    pub fn cached_stacks(self) -> usize {
        match self {
            Self::Reference | Self::PreallocatedStack | Self::LazyTranslation | Self::Lazy => {
                REFERENCE_CACHED_STACKS
            }
            Self::UnpooledStack | Self::Alternate => 0,
        }
    }
}

/// One engine toggle this runtime pins for every profile.
///
/// The toggles are enumerated rather than stored as fields so that one table
/// drives both the `Config` the engine is built from and the compiler identity
/// an artifact is keyed by. Adding a toggle to [`PINNED_TOGGLES`] therefore
/// moves every identity, and no toggle can be applied without being committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineToggle {
    ConsumeFuel,
    Floats,
    AllowStartFn,
    MultiMemory,
    ReferenceTypes,
    TailCall,
    ExtendedConst,
    SaturatingFloatToInt,
    MultiValue,
}

/// Every engine toggle and the value this runtime pins it to.
const PINNED_TOGGLES: [(EngineToggle, bool); 9] = [
    (EngineToggle::ConsumeFuel, true),
    (EngineToggle::Floats, false),
    (EngineToggle::AllowStartFn, false),
    (EngineToggle::MultiMemory, false),
    (EngineToggle::ReferenceTypes, false),
    (EngineToggle::TailCall, false),
    (EngineToggle::ExtendedConst, false),
    (EngineToggle::SaturatingFloatToInt, false),
    (EngineToggle::MultiValue, false),
];

impl EngineToggle {
    /// Applies this toggle to a configuration under construction.
    fn apply(self, config: &mut Config, enabled: bool) {
        match self {
            Self::ConsumeFuel => {
                config.consume_fuel(enabled);
            }
            Self::Floats => {
                config.floats(enabled);
            }
            Self::AllowStartFn => {
                config.allow_start_fn(enabled);
            }
            Self::MultiMemory => {
                config.wasm_multi_memory(enabled);
            }
            Self::ReferenceTypes => {
                config.wasm_reference_types(enabled);
            }
            Self::TailCall => {
                config.wasm_tail_call(enabled);
            }
            Self::ExtendedConst => {
                config.wasm_extended_const(enabled);
            }
            Self::SaturatingFloatToInt => {
                config.wasm_saturating_float_to_int(enabled);
            }
            Self::MultiValue => {
                config.wasm_multi_value(enabled);
            }
        }
    }

    /// Returns the stable byte the compiler identity commits this toggle by.
    ///
    /// The code is explicit so reordering [`PINNED_TOGGLES`] cannot change an
    /// identity, and so a removed toggle's code cannot be reused by accident.
    fn code(self) -> u8 {
        match self {
            Self::ConsumeFuel => 1,
            Self::Floats => 2,
            Self::AllowStartFn => 3,
            Self::MultiMemory => 4,
            Self::ReferenceTypes => 5,
            Self::TailCall => 6,
            Self::ExtendedConst => 7,
            Self::SaturatingFloatToInt => 8,
            Self::MultiValue => 9,
        }
    }
}

/// The two tuning axes and the stack bounds, resolved for one profile.
///
/// One value produces both the [`Config`] the engine is built from and the
/// compiler identity an artifact is keyed by, so a setting that moves the
/// engine also moves the identity, and an artifact compiled before the change
/// can never be reused after it.
#[derive(Clone, Copy, Debug)]
struct EnginePolicy {
    max_recursion_depth: usize,
    max_stack_height: usize,
    /// `None` leaves the pinned release's own default initial height in place,
    /// which is why the identity encodes the absence rather than a sentinel.
    min_stack_height: Option<usize>,
    max_cached_stacks: usize,
    compilation_mode: CompilationMode,
}

impl EnginePolicy {
    /// Resolves the stack bounds and the two tuning axes for one profile.
    fn for_profile(profile: EngineProfile) -> Self {
        Self {
            max_recursion_depth: MAX_RECURSION_DEPTH,
            max_stack_height: MAX_STACK_HEIGHT,
            min_stack_height: profile.preallocates_stack().then_some(MAX_STACK_HEIGHT),
            max_cached_stacks: profile.cached_stacks(),
            compilation_mode: profile.compilation_mode(),
        }
    }

    /// Builds the engine configuration this policy describes.
    fn config(&self) -> Config {
        let mut config = Config::default();
        for (toggle, enabled) in PINNED_TOGGLES {
            toggle.apply(&mut config, enabled);
        }
        config
            .set_max_recursion_depth(self.max_recursion_depth)
            .set_max_stack_height(self.max_stack_height)
            .set_max_cached_stacks(self.max_cached_stacks)
            .compilation_mode(self.compilation_mode);
        if let Some(height) = self.min_stack_height {
            // The maximum is already set above, so the minimum cannot exceed it.
            config.set_min_stack_height(height);
        }
        config
    }

    /// Commits the pinned engine release, its pinned cargo features, every
    /// pinned toggle and every field above, in declaration order.
    fn identity(&self) -> Hash256 {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, WASM_ENGINE_VERSION.as_bytes());
        push_count(&mut bytes, WASM_ENGINE_FEATURES.len());
        for feature in WASM_ENGINE_FEATURES {
            push_bytes(&mut bytes, feature.as_bytes());
        }
        push_count(&mut bytes, PINNED_TOGGLES.len());
        for (toggle, enabled) in PINNED_TOGGLES {
            bytes.push(toggle.code());
            bytes.push(u8::from(enabled));
        }
        push_count(&mut bytes, self.max_recursion_depth);
        push_count(&mut bytes, self.max_stack_height);
        match self.min_stack_height {
            None => bytes.push(0),
            Some(height) => {
                bytes.push(1);
                push_count(&mut bytes, height);
            }
        }
        push_count(&mut bytes, self.max_cached_stacks);
        bytes.push(match self.compilation_mode {
            CompilationMode::Eager => 1,
            CompilationMode::LazyTranslation => 2,
            CompilationMode::Lazy => 3,
        });
        types::hash::domain_hash(b"astrolune.contract.wasm.compiler.v1", &bytes)
    }
}

/// Appends a length-framed byte string, so no two encodings can run together.
fn push_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    push_count(buffer, bytes.len());
    buffer.extend_from_slice(bytes);
}

/// Appends a count as eight little-endian bytes.
fn push_count(buffer: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).expect("engine counts fit in 64 bits");
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// Commits the execution target this interpreter was compiled for.
///
/// The interpreter emits no native machine code and the `simd` cargo feature is
/// off, so no CPU feature detection participates in execution and none is
/// encoded here. What is encoded is the compile-time target: architecture,
/// operating system, target family, pointer width and endianness. A toolchain
/// change that leaves all five equal is not distinguished; see
/// `docs/58-ahead-of-time-contract-backend.md` for that limit.
#[must_use]
pub fn target_identity() -> Hash256 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, std::env::consts::ARCH.as_bytes());
    push_bytes(&mut bytes, std::env::consts::OS.as_bytes());
    push_bytes(&mut bytes, std::env::consts::FAMILY.as_bytes());
    bytes.extend_from_slice(&usize::BITS.to_le_bytes());
    bytes.push(u8::from(cfg!(target_endian = "little")));
    types::hash::domain_hash(b"astrolune.contract.wasm.target.v1", &bytes)
}

/// Finalized call context and explicit contract-local access authorization.
#[derive(Clone, Copy)]
pub struct WasmCall<'a> {
    /// Canonical call input bytes.
    pub input: &'a [u8],
    /// Caller authenticated by the enclosing transaction.
    pub caller: Address,
    /// Finalized block height; no wall clock is exposed.
    pub height: u64,
    /// Immutable contract-local state; keys are scoped by the outer executor.
    pub state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    /// Authorized keys for reads and writes. Missing declarations trap.
    pub access: &'a BTreeSet<Vec<u8>>,
    /// Deterministic call budget in compute, memory bytes, I/O bytes, output bytes.
    pub limits: Resources,
}

/// Successful staged output. Traps return no writes or events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmOutput {
    /// Contract return bytes.
    pub return_data: Vec<u8>,
    /// Ordered events, with 32-byte topics.
    pub events: Vec<([u8; 32], Vec<u8>)>,
    /// Canonically ordered writes; `None` deletes a key.
    pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Actual read/write keys, independent of declared supersets.
    pub accessed: BTreeSet<Vec<u8>>,
    /// Charged resources. Compute includes Wasmi fuel and host work.
    pub resources: Resources,
}

/// Portable interpreter and validator for the versioned contract profile.
pub struct WasmRuntime {
    engine: Engine,
    profile: EngineProfile,
    compiler: Hash256,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    /// Creates the fixed, integer-only engine with eager validation and fuel.
    #[must_use]
    pub fn new() -> Self {
        Self::with_profile(EngineProfile::Reference)
    }

    /// Creates the same integer-only engine under an alternate tuning profile.
    ///
    /// For every profile in [`EngineProfile::QUALIFIED`] the returned runtime
    /// accepts and rejects the same modules as [`WasmRuntime::new`] and charges
    /// the same resources; `crates/runtime/tests/backends.rs` and the workspace
    /// backend qualification campaign check that on the shared corpus and its
    /// mutations. The profiles in [`EngineProfile::DISQUALIFIED`] are measured
    /// to charge more compute and must never execute live calls.
    #[must_use]
    pub fn with_profile(profile: EngineProfile) -> Self {
        let policy = EnginePolicy::for_profile(profile);
        Self {
            engine: Engine::new(&policy.config()),
            profile,
            compiler: policy.identity(),
        }
    }

    /// Returns the engine tuning profile this runtime was built with.
    #[must_use]
    pub fn profile(&self) -> EngineProfile {
        self.profile
    }

    /// Returns the deterministic compiler identity of this runtime's engine.
    ///
    /// The digest commits to the pinned Wasmi release, its pinned cargo
    /// features and every engine setting this runtime applies, including the
    /// two tuning axes [`EngineProfile`] moves. It is derived from those
    /// settings and not from the profile's name, so two profiles that resolved
    /// to the same settings would correctly share an identity and renaming a
    /// profile cannot change one.
    ///
    /// It identifies a configuration and not an `Engine` instance. Two
    /// runtimes built from the same profile report the same identity while
    /// holding engines that cannot share translated code, which is why
    /// [`WasmRuntime::execute_artifact`] additionally refuses an artifact
    /// produced by a different engine.
    #[must_use]
    pub fn compiler_identity(&self) -> Hash256 {
        self.compiler
    }

    /// Returns the artifact cache identity of `module` under this runtime.
    ///
    /// This is a pure projection of the module's own identity onto this engine
    /// and target. It validates nothing; a key for a module this runtime would
    /// reject is still well defined.
    #[must_use]
    pub fn artifact_key(&self, module: &ContractModule) -> ArtifactKey {
        ArtifactKey {
            code_hash: module.code_hash,
            version: module.version,
            compiler: self.compiler,
            target: target_identity(),
        }
    }

    /// Borrows the engine, so a sibling module can compare artifact ownership.
    pub(crate) fn engine(&self) -> &Engine {
        &self.engine
    }

    pub(crate) fn compile(&self, bytes: &[u8]) -> Result<Module, RuntimeError> {
        if bytes.len() > MAX_MODULE_SIZE {
            return Err(RuntimeError::LimitExceeded);
        }
        // The wire profile accepts binary modules only, never WAT or native code.
        if !bytes.starts_with(b"\0asm\x01\0\0\0") {
            return Err(RuntimeError::InvalidModule);
        }
        // Validate complete bodies before Wasmi's combined validation/translation.
        // In 2.0.0 an instruction after a function's end can reach the translator
        // with an empty control stack before its validator rejects the operator.
        // Keep the same engine feature policy and never pass malformed code to it.
        Module::validate(&self.engine, bytes).map_err(|_| RuntimeError::InvalidModule)?;
        let module = Module::new(&self.engine, bytes).map_err(|_| RuntimeError::InvalidModule)?;
        let Some(ExternType::Memory(memory)) = module.get_export("memory") else {
            return Err(RuntimeError::InvalidModule);
        };
        if memory.minimum() > 256 || memory.maximum().is_none_or(|max| max > 256) {
            return Err(RuntimeError::LimitExceeded);
        }
        let Some(ExternType::Func(call)) = module.get_export("call") else {
            return Err(RuntimeError::InvalidModule);
        };
        if !call.params().is_empty() || call.results() != [ValType::I32] {
            return Err(RuntimeError::InvalidModule);
        }
        for import in module.imports() {
            let ExternType::Func(function) = import.ty() else {
                return Err(RuntimeError::Unsupported);
            };
            let (parameters, result) = match import.name() {
                "input_len" => (0, ValType::I32),
                "input_copy" | "emit" => (3, ValType::I32),
                "output" | "state_delete" => (2, ValType::I32),
                "state_get" | "state_put" => (4, ValType::I32),
                "caller" => (1, ValType::I32),
                "block_height" => (0, ValType::I64),
                _ => return Err(RuntimeError::Unsupported),
            };
            if import.module() != "astrolune_v2"
                || function.params().len() != parameters
                || function.params().iter().any(|ty| *ty != ValType::I32)
                || function.results() != [result]
            {
                return Err(RuntimeError::Unsupported);
            }
        }
        Ok(module)
    }

    /// Executes a validated module in a fresh instance with private writes.
    ///
    /// Every call translates `module` again, so a contract transaction pays the
    /// translation cost once per call. [`WasmRuntime::compile_artifact`] hoists
    /// that translation out of the metered call and
    /// [`WasmRuntime::execute_artifact`] then executes without translating.
    /// Both paths charge identically, which `crates/runtime/tests/aot.rs` pins.
    ///
    /// # Errors
    /// Rejects forged module hashes/versions, forbidden imports/features, exhausted
    /// resources, invalid pointers, undeclared accesses, nonzero returns, and traps.
    pub fn execute_call(
        &self,
        module: &ContractModule,
        call: WasmCall<'_>,
    ) -> Result<WasmOutput, RuntimeError> {
        if module.version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if module.code_hash != wasm_code_hash(&module.code) {
            return Err(RuntimeError::InvalidModule);
        }
        validate_call(&call)?;
        let compiled = self.compile(&module.code)?;
        self.run(&compiled, call)
    }

    /// Instantiates already translated bytecode and runs one metered call.
    ///
    /// Everything this does happens after the fuel budget is installed, so it
    /// is the part of a call that `Resources::compute` accounts for. No
    /// translation occurs here under an eager profile.
    pub(crate) fn run(
        &self,
        compiled: &Module,
        call: WasmCall<'_>,
    ) -> Result<WasmOutput, RuntimeError> {
        let fuel = call.limits.compute;
        let host = Host {
            call,
            output: Vec::new(),
            writes: BTreeMap::new(),
            accessed: BTreeSet::new(),
            events: Vec::new(),
            io: 0,
            bandwidth: 0,
            limiter: StoreLimitsBuilder::new()
                .memory_size(
                    usize::try_from(call.limits.memory).map_err(|_| RuntimeError::LimitExceeded)?,
                )
                .table_elements(4096)
                .instances(1)
                .memories(1)
                .tables(1)
                .trap_on_grow_failure(true)
                .build(),
            failure: None,
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|host| &mut host.limiter);
        store
            .set_fuel(fuel)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let linker = host_linker(&self.engine).map_err(|_| RuntimeError::InvalidModule)?;
        let instance = linker
            .instantiate_and_start(&mut store, compiled)
            .map_err(|error| runtime_error(&error))?;
        let function = instance
            .get_typed_func::<(), i32>(&store, "call")
            .map_err(|_| RuntimeError::InvalidModule)?;
        let status = function.call(&mut store, ()).map_err(|error| {
            store
                .data()
                .failure
                .unwrap_or_else(|| runtime_error(&error))
        })?;
        if status != 0 {
            return Err(RuntimeError::Trap);
        }
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(RuntimeError::InvalidModule)?;
        let resources = Resources {
            compute: fuel - store.get_fuel().map_err(|_| RuntimeError::Trap)?,
            memory: memory.data_size(&store) as u64,
            io: store.data().io,
            bandwidth: store.data().bandwidth,
        };
        let host = store.into_data();
        Ok(WasmOutput {
            return_data: host.output,
            events: host.events,
            writes: host.writes,
            accessed: host.accessed,
            resources,
        })
    }
}

impl ModuleValidator for WasmRuntime {
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError> {
        if version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        self.compile(bytes)?;
        Ok(ContractModule {
            code_hash: wasm_code_hash(bytes),
            version,
            code: bytes.to_vec(),
        })
    }
}

/// Commits the fixed WebAssembly ABI/metering identity and exact binary bytes.
#[must_use]
pub fn wasm_code_hash(bytes: &[u8]) -> Hash256 {
    types::hash::domain_hash(b"astrolune.contract.wasm.abi2.meter1", bytes)
}

pub(crate) fn validate_call(call: &WasmCall<'_>) -> Result<(), RuntimeError> {
    if call.input.len() > MAX_INPUT_SIZE
        || call.limits.compute == 0
        || call.limits.compute > 10_000_000
        || call.limits.memory > MAX_WASM_MEMORY as u64
        || call.limits.io > MAX_HOST_IO
        || call.limits.bandwidth > MAX_OUTPUT_SIZE as u64
        || call.state.len() > 1024
        || call.access.len() > 1024
    {
        return Err(RuntimeError::LimitExceeded);
    }
    let mut bytes = 0usize;
    for (key, value) in call.state {
        if key.is_empty() || key.len() > 256 || value.len() > MAX_HOST_VALUE {
            return Err(RuntimeError::LimitExceeded);
        }
        bytes = bytes
            .checked_add(key.len() + value.len())
            .ok_or(RuntimeError::LimitExceeded)?;
        if bytes as u64 > MAX_HOST_IO {
            return Err(RuntimeError::LimitExceeded);
        }
    }
    if call
        .access
        .iter()
        .any(|key| key.is_empty() || key.len() > 256)
    {
        return Err(RuntimeError::LimitExceeded);
    }
    Ok(())
}

struct Host<'a> {
    call: WasmCall<'a>,
    output: Vec<u8>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accessed: BTreeSet<Vec<u8>>,
    events: Vec<([u8; 32], Vec<u8>)>,
    io: u64,
    bandwidth: u64,
    limiter: StoreLimits,
    failure: Option<RuntimeError>,
}

fn runtime_error(error: &wasmi::Error) -> RuntimeError {
    match error.as_trap_code() {
        Some(wasmi::TrapCode::OutOfFuel | wasmi::TrapCode::StackOverflow) => {
            RuntimeError::LimitExceeded
        }
        _ => RuntimeError::Trap,
    }
}

fn fail(caller: &mut Caller<'_, Host<'_>>, error: RuntimeError) -> wasmi::Error {
    caller.data_mut().failure = Some(error);
    wasmi::Error::new("contract host rejected operation")
}

fn memory(caller: &Caller<'_, Host<'_>>) -> Result<Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
        .ok_or_else(|| wasmi::Error::new("missing contract memory"))
}

fn charge(
    caller: &mut Caller<'_, Host<'_>>,
    bytes: usize,
    io: bool,
    bandwidth: bool,
) -> Result<(), wasmi::Error> {
    let cost = 20 + bytes as u64;
    let remaining = caller.get_fuel()?;
    if remaining < cost {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    caller.set_fuel(remaining - cost)?;
    let host = caller.data_mut();
    if io {
        host.io = host
            .io
            .checked_add(bytes as u64)
            .ok_or_else(|| wasmi::Error::new("I/O overflow"))?;
    }
    if bandwidth {
        host.bandwidth = host
            .bandwidth
            .checked_add(bytes as u64)
            .ok_or_else(|| wasmi::Error::new("output overflow"))?;
    }
    if host.io > host.call.limits.io || host.bandwidth > host.call.limits.bandwidth {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    Ok(())
}

fn read_memory(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    length: i32,
    maximum: usize,
) -> Result<Vec<u8>, wasmi::Error> {
    let pointer = usize::try_from(pointer).map_err(|_| fail(caller, RuntimeError::Trap))?;
    let length = usize::try_from(length).map_err(|_| fail(caller, RuntimeError::Trap))?;
    if length > maximum {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    charge(caller, length, false, false)?;
    let mut bytes = vec![0; length];
    memory(caller)?
        .read(&*caller, pointer, &mut bytes)
        .map_err(|_| fail(caller, RuntimeError::Trap))?;
    Ok(bytes)
}

fn write_memory(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    bytes: &[u8],
) -> Result<(), wasmi::Error> {
    let pointer = usize::try_from(pointer).map_err(|_| fail(caller, RuntimeError::Trap))?;
    charge(caller, bytes.len(), false, false)?;
    memory(caller)?
        .write(&mut *caller, pointer, bytes)
        .map_err(|_| fail(caller, RuntimeError::Trap))
}

fn read_key(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    length: i32,
) -> Result<Vec<u8>, wasmi::Error> {
    let key = read_memory(caller, pointer, length, 256)?;
    if key.is_empty() || !caller.data().call.access.contains(&key) {
        return Err(fail(caller, RuntimeError::Trap));
    }
    caller.data_mut().accessed.insert(key.clone());
    Ok(key)
}

fn host_linker(engine: &Engine) -> Result<Linker<Host<'_>>, wasmi::Error> {
    let mut linker = Linker::new(engine);
    link_io(&mut linker)?;
    link_state(&mut linker)?;
    link_context(&mut linker)?;
    Ok(linker)
}

fn link_io(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "input_len",
        |mut caller: Caller<'_, Host<'_>>| -> Result<i32, wasmi::Error> {
            charge(&mut caller, 0, false, false)?;
            Ok(i32::try_from(caller.data().call.input.len()).expect("bounded input"))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "input_copy",
        |mut caller: Caller<'_, Host<'_>>,
         offset: i32,
         pointer: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            let offset =
                usize::try_from(offset).map_err(|_| fail(&mut caller, RuntimeError::Trap))?;
            let length =
                usize::try_from(length).map_err(|_| fail(&mut caller, RuntimeError::Trap))?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| fail(&mut caller, RuntimeError::Trap))?;
            let bytes = caller
                .data()
                .call
                .input
                .get(offset..end)
                .ok_or_else(|| wasmi::Error::new("input bounds"))?
                .to_vec();
            write_memory(&mut caller, pointer, &bytes)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "output",
        |mut caller: Caller<'_, Host<'_>>,
         pointer: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            let bytes = read_memory(&mut caller, pointer, length, MAX_OUTPUT_SIZE)?;
            charge(&mut caller, bytes.len(), false, true)?;
            caller.data_mut().output = bytes;
            Ok(0)
        },
    )?;
    Ok(())
}

fn link_state(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "state_get",
        |mut caller: Caller<'_, Host<'_>>,
         key: i32,
         key_len: i32,
         output: i32,
         capacity: i32|
         -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            let value = caller
                .data()
                .writes
                .get(&key)
                .cloned()
                .unwrap_or_else(|| caller.data().call.state.get(&key).cloned());
            charge(
                &mut caller,
                key.len() + value.as_ref().map_or(0, Vec::len),
                true,
                false,
            )?;
            let Some(value) = value else {
                return Ok(-1);
            };
            if !usize::try_from(capacity).is_ok_and(|capacity| capacity >= value.len()) {
                return Err(fail(&mut caller, RuntimeError::LimitExceeded));
            }
            write_memory(&mut caller, output, &value)?;
            Ok(i32::try_from(value.len()).expect("bounded value"))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "state_put",
        |mut caller: Caller<'_, Host<'_>>,
         key: i32,
         key_len: i32,
         value: i32,
         value_len: i32|
         -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            let value = read_memory(&mut caller, value, value_len, MAX_HOST_VALUE)?;
            charge(&mut caller, key.len() + value.len(), true, false)?;
            caller.data_mut().writes.insert(key, Some(value));
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "state_delete",
        |mut caller: Caller<'_, Host<'_>>, key: i32, key_len: i32| -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            charge(&mut caller, key.len(), true, false)?;
            caller.data_mut().writes.insert(key, None);
            Ok(0)
        },
    )?;
    Ok(())
}

fn link_context(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "caller",
        |mut caller: Caller<'_, Host<'_>>, output: i32| -> Result<i32, wasmi::Error> {
            let address = caller.data().call.caller.0;
            write_memory(&mut caller, output, &address)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "block_height",
        |mut caller: Caller<'_, Host<'_>>| -> Result<i64, wasmi::Error> {
            charge(&mut caller, 0, false, false)?;
            Ok(i64::from_le_bytes(caller.data().call.height.to_le_bytes()))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "emit",
        |mut caller: Caller<'_, Host<'_>>,
         topic: i32,
         value: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            if caller.data().events.len() >= 256 {
                return Err(fail(&mut caller, RuntimeError::LimitExceeded));
            }
            let topic = read_memory(&mut caller, topic, 32, 32)?;
            let value = read_memory(&mut caller, value, length, MAX_HOST_VALUE)?;
            charge(&mut caller, 32 + value.len(), false, true)?;
            caller
                .data_mut()
                .events
                .push((topic.try_into().expect("32-byte topic"), value));
            Ok(0)
        },
    )?;
    Ok(())
}
