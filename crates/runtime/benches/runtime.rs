// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures module validation, engine construction and metered ABI-v2 calls.
//!
//! These figures describe one machine and one toolchain. They are not a
//! correctness gate. Which modules validate, which traps occur, and how much
//! compute a call is charged are fixed by the pinned runtime version and are
//! established by the tests in `crates/runtime`, not here. A faster engine
//! profile is not a more correct one: `EngineProfile::QUALIFIED` is qualified by
//! field-by-field output comparison, and `EngineProfile::DISQUALIFIED` stays
//! disqualified however it measures.
//!
//! Every benchmarked operation is repeatable without a reset. Validation and
//! `WasmRuntime::execute_call` take an immutable module and return a fresh
//! result, so the second call does the same work as the first; staged writes
//! stay inside the returned output and are never published. The fuel-exhaustion
//! and trap benchmarks measure a failing call, which is the point of measuring
//! them, and their figures include the error path.
//!
//! What this does NOT establish: block or contract throughput for any
//! deployment, charged compute (which is a consensus quantity measured in fuel,
//! not nanoseconds), the cost of a module produced by a real compiler rather
//! than by the generators below, a figure comparable to another machine, or any
//! bound under contention from other processes. No figure here licenses a
//! change to the runtime version, the fuel schedule or the selected engine
//! profile.

use std::collections::{BTreeMap, BTreeSet};

use runtime::{
    ContractModule, DEMO_VERSION, DemoModuleValidator, EngineProfile, InterpreterBackend,
    MAX_INPUT_SIZE, MAX_MODULE_SIZE, MAX_OUTPUT_SIZE, ModuleValidator, RuntimeBackend,
    WASM_VERSION, WasmCall, WasmRuntime, wasm_code_hash,
};
use testkit::bench::Suite;
use types::{Address, Resources};

/// Body sizes for the module-size sweep, in repeated integer operations.
///
/// Each step emits one `local.get`/`i32.const`/`i32.add`/`local.set` group, so
/// the encoded module grows by a few bytes per step and the executed call grows
/// by a fixed number of interpreted instructions per step.
const BODY_STEPS: [usize; 4] = [1, 16, 256, 4_096];

/// Fuel budgets for the exhaustion sweep.
///
/// A non-terminating loop consumes the whole budget before the engine retires
/// it, so the measured time is dominated by interpreting that many fuel units.
const FUEL_BUDGETS: [u64; 3] = [10_000, 100_000, 1_000_000];

/// Call budget used by every benchmark that is not measuring exhaustion.
///
/// `compute` is the largest budget a call may request, so no benchmarked module
/// is retired for want of fuel. The other classes are per-call host limits and
/// are set below the runtime maxima, which no fixture approaches.
const BUDGET: Resources = Resources {
    compute: 10_000_000,
    memory: 1 << 17,
    io: 1 << 16,
    bandwidth: 1 << 16,
};

/// Builds a module from WebAssembly text.
fn module(text: &str) -> Vec<u8> {
    wat::parse_str(text).expect("benchmark module text is well formed")
}

/// Builds a module whose exported `call` runs `steps` integer additions.
///
/// The accumulator is masked to zero at the end so the function returns success
/// for any step count, and it is read on every step so the body cannot be
/// reduced to a constant.
fn adder(steps: usize) -> Vec<u8> {
    let mut text = String::from(
        r#"(module (memory (export "memory") 1 1)
        (func (export "call") (result i32) (local $acc i32)"#,
    );
    for _ in 0..steps {
        text.push_str("(local.set $acc (i32.add (local.get $acc) (i32.const 1)))");
    }
    text.push_str("(i32.and (local.get $acc) (i32.const 0))))");
    module(&text)
}

/// Builds a module whose exported `call` never returns.
///
/// The call is retired when its fuel budget is exhausted, which is the bounded
/// failure path the engine is configured to guarantee.
fn endless_loop() -> Vec<u8> {
    module(
        r#"(module (memory (export "memory") 1 1)
        (func (export "call") (result i32) (loop $forever br $forever) (i32.const 0)))"#,
    )
}

/// Builds a module whose exported `call` copies its input to its return data.
fn input_copier() -> Vec<u8> {
    module(
        r#"(module
        (import "astrolune_v2" "input_len" (func $len (result i32)))
        (import "astrolune_v2" "input_copy" (func $copy (param i32 i32 i32) (result i32)))
        (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
        (memory (export "memory") 1 1)
        (func (export "call") (result i32)
            (drop (call $copy (i32.const 0) (i32.const 256) (call $len)))
            (drop (call $out (i32.const 256) (call $len))) (i32.const 0)))"#,
    )
}

/// Builds a module whose exported `call` writes one state key and reads it back.
///
/// The read observes the staged write, so the supplied state view changes only
/// the pre-call validation of that view, not the value the contract sees.
fn state_writer() -> Vec<u8> {
    module(
        r#"(module
        (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
        (import "astrolune_v2" "state_get" (func $get (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1 1) (data (i32.const 0) "keyvalue")
        (func (export "call") (result i32)
            (drop (call $put (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 5)))
            (drop (call $get (i32.const 0) (i32.const 3) (i32.const 256) (i32.const 5)))
            (i32.const 0)))"#,
    )
}

/// Builds a module whose exported `call` emits one 32-byte-topic event.
fn event_emitter() -> Vec<u8> {
    module(
        r#"(module
        (import "astrolune_v2" "emit" (func $emit (param i32 i32 i32) (result i32)))
        (memory (export "memory") 1 1)
        (func (export "call") (result i32)
            (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 32))) (i32.const 0)))"#,
    )
}

/// Builds a module whose exported `call` traps immediately.
fn trapping() -> Vec<u8> {
    module(
        r#"(module (memory (export "memory") 1 1)
        (func (export "call") (result i32) unreachable))"#,
    )
}

/// Returns every enumerated engine profile, the qualified ones first.
fn all_profiles() -> Vec<EngineProfile> {
    EngineProfile::QUALIFIED
        .into_iter()
        .chain(EngineProfile::DISQUALIFIED)
        .collect()
}

/// Validates `code` under `runtime`, or panics.
///
/// Fixtures are validated once outside the measured closure so a benchmark that
/// measures execution does not also measure a rejection.
fn accepted(runtime: &WasmRuntime, code: &[u8]) -> ContractModule {
    runtime
        .validate(code, WASM_VERSION)
        .expect("benchmark fixture module is accepted")
}

/// Returns the finalized call context shared by the execution benchmarks.
fn call<'a>(
    input: &'a [u8],
    state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    access: &'a BTreeSet<Vec<u8>>,
    limits: Resources,
) -> WasmCall<'a> {
    WasmCall {
        input,
        caller: Address([7; 32]),
        height: 9,
        state,
        access,
        limits,
    }
}

/// Measures engine construction for every enumerated profile.
///
/// `execution::execute_contract` builds one runtime per contract transaction,
/// so whatever this costs is paid per transaction and not once per node.
fn bench_engine(suite: &mut Suite) {
    suite.bench("engine/new", WasmRuntime::new);
    for profile in all_profiles() {
        suite.bench(format!("engine/with_profile/{profile:?}"), || {
            WasmRuntime::with_profile(profile)
        });
    }
}

/// Measures validation over a module-size sweep and over rejected inputs.
fn bench_validation(suite: &mut Suite, runtime: &WasmRuntime) {
    for steps in BODY_STEPS {
        let code = adder(steps);
        let bytes = code.len();
        suite.bench(format!("validate/body_steps/{steps}/{bytes}B"), || {
            runtime.validate(&code, WASM_VERSION)
        });
        suite.bench(format!("wasm_code_hash/{bytes}B"), || wasm_code_hash(&code));
    }

    // Rejection paths, to record what a validator spends on a bad candidate.
    // The truncated input keeps a valid eight-byte preamble, so it reaches the
    // parser instead of being refused on its magic bytes.
    let truncated = adder(16)[..8].to_vec();
    suite.bench("validate/rejected/truncated", || {
        runtime.validate(&truncated, WASM_VERSION)
    });
    let not_wasm = vec![0u8; 1_024];
    suite.bench("validate/rejected/wrong_magic", || {
        runtime.validate(&not_wasm, WASM_VERSION)
    });
    let no_memory = module(r#"(module (func (export "call") (result i32) i32.const 0))"#);
    suite.bench("validate/rejected/missing_memory", || {
        runtime.validate(&no_memory, WASM_VERSION)
    });
}

/// Measures complete calls: compile, instantiate, interpret and charge.
///
/// `WasmRuntime::execute_call` compiles the module again on every call, so the
/// one-step figure is the floor a contract transaction pays before running any
/// instruction of its own. The crate exposes no instantiate-only entry point,
/// so instantiation cannot be isolated here; the difference between
/// `execute_call/body_steps/1` and `validate/body_steps/1` is indicative of it
/// and nothing stronger.
fn bench_execution(suite: &mut Suite, runtime: &WasmRuntime) {
    let empty_state = BTreeMap::new();
    let no_access = BTreeSet::new();
    for steps in BODY_STEPS {
        let contract = accepted(runtime, &adder(steps));
        suite.bench(format!("execute_call/body_steps/{steps}"), || {
            runtime.execute_call(&contract, call(&[], &empty_state, &no_access, BUDGET))
        });
    }

    let copier = accepted(runtime, &input_copier());
    for size in [0_usize, 256, 4_096] {
        let input = vec![0xa5; size];
        suite.bench(format!("execute_call/input_output/{size}B"), || {
            runtime.execute_call(&copier, call(&input, &empty_state, &no_access, BUDGET))
        });
    }

    let events = accepted(runtime, &event_emitter());
    suite.bench("execute_call/emit_one_event", || {
        runtime.execute_call(&events, call(&[], &empty_state, &no_access, BUDGET))
    });

    let keyed = accepted(runtime, &state_writer());
    let declared = BTreeSet::from([b"key".to_vec()]);
    let one_entry = BTreeMap::from([(b"key".to_vec(), b"older".to_vec())]);
    suite.bench("execute_call/state_round_trip/empty_view", || {
        runtime.execute_call(&keyed, call(&[], &empty_state, &declared, BUDGET))
    });
    suite.bench("execute_call/state_round_trip/one_entry_view", || {
        runtime.execute_call(&keyed, call(&[], &one_entry, &declared, BUDGET))
    });

    let trap = accepted(runtime, &trapping());
    suite.bench("execute_call/trap/unreachable", || {
        runtime.execute_call(&trap, call(&[], &empty_state, &no_access, BUDGET))
    });

    let endless = accepted(runtime, &endless_loop());
    for compute in FUEL_BUDGETS {
        let limits = Resources { compute, ..BUDGET };
        suite.bench(format!("execute_call/fuel_exhausted/{compute}"), || {
            runtime.execute_call(&endless, call(&[], &empty_state, &no_access, limits))
        });
    }
}

/// Measures every engine profile against the reference on one mid-size module.
///
/// The two qualified allocation axes are expected to be invisible to a
/// contract; whether they are invisible in wall clock is what this records. The
/// disqualified profiles defer translation, which moves work out of validation
/// and into the call, and they are included only to measure that movement. They
/// stay forbidden for live execution whatever the figures say.
fn bench_profiles(suite: &mut Suite) {
    let code = adder(256);
    let empty_state = BTreeMap::new();
    let no_access = BTreeSet::new();
    for profile in all_profiles() {
        let runtime = WasmRuntime::with_profile(profile);
        suite.bench(format!("profile/{profile:?}/validate/256"), || {
            runtime.validate(&code, WASM_VERSION)
        });
        let contract = accepted(&runtime, &code);
        suite.bench(format!("profile/{profile:?}/execute_call/256"), || {
            runtime.execute_call(&contract, call(&[], &empty_state, &no_access, BUDGET))
        });
    }
}

/// Measures the retained ABI-v1 demonstration path.
///
/// `DemoModuleValidator` performs size and version checks with a non-standard
/// hash, and `InterpreterBackend` transforms bytes. Neither interprets
/// WebAssembly. They are measured because they are public, not because they are
/// a contract execution path.
fn bench_demonstration(suite: &mut Suite) {
    let validator = DemoModuleValidator::new(MAX_MODULE_SIZE);
    let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
    for size in [32_usize, 4_096] {
        let code = vec![0x5a; size];
        suite.bench(format!("demo/validate/{size}B"), || {
            validator.validate(&code, DEMO_VERSION)
        });
        let contract = validator
            .validate(&code, DEMO_VERSION)
            .expect("demonstration fixture is accepted");
        let input = vec![0xa5; size];
        suite.bench(format!("demo/execute/{size}B"), || {
            backend.execute(&contract, &input)
        });
    }
}

fn main() {
    let mut suite = Suite::new("runtime");
    let runtime = WasmRuntime::new();
    bench_engine(&mut suite);
    bench_validation(&mut suite, &runtime);
    bench_execution(&mut suite, &runtime);
    bench_profiles(&mut suite);
    bench_demonstration(&mut suite);
    suite.report();
}
