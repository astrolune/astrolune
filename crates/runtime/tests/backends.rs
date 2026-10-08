// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Qualification of the alternate engine profiles behind the `RuntimeBackend`
//! seam: configuration independence for the neutral axes, the seam projection,
//! the measured non-neutrality of lazy compilation, and the engine bounds that
//! are consensus-visible and therefore not backend axes.
//!
//! Every profile is the same Wasmi interpreter under a different value-stack
//! allocation strategy. Nothing here is an ahead-of-time, just-in-time or SIMD
//! backend, and no such backend exists.

use runtime::{
    BackendKind, ContractModule, EngineProfile, ModuleValidator, OutputDifference, RuntimeBackend,
    RuntimeError, WASM_VERSION, WasmBackend, WasmCall, WasmRuntime, project_wasm_output,
    runtime_difference, wasm_code_hash, wasm_difference,
};
use std::collections::{BTreeMap, BTreeSet};
use types::{Address, Resources};

/// Deterministic grant shared by every comparison; far below the call bounds.
const LIMITS: Resources = Resources {
    compute: 1_000_000,
    memory: 1_048_576,
    io: 65_536,
    bandwidth: 65_536,
};

fn module(body: &str) -> Vec<u8> {
    wat::parse_str(body).unwrap()
}

/// Modules exercising the returning, looping, input/output, state, delete,
/// event, context, nonzero-status, memory-growth and trapping paths.
fn modules() -> Vec<Vec<u8>> {
    [
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) (loop br 0) i32.const 0))"#,
        r#"(module
            (import "astrolune_v2" "input_len" (func $len (result i32)))
            (import "astrolune_v2" "input_copy" (func $copy (param i32 i32 i32) (result i32)))
            (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
            (memory (export "memory") 1 2)
            (func (export "call") (result i32)
                (drop (call $copy (i32.const 0) (i32.const 128) (call $len)))
                (drop (call $out (i32.const 128) (call $len)))
                (i32.const 0)))"#,
        r#"(module
            (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
            (import "astrolune_v2" "state_get" (func $get (param i32 i32 i32 i32) (result i32)))
            (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "keynew")
            (func (export "call") (result i32)
                (drop (call $put (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 3)))
                (drop (call $out (i32.const 128)
                    (call $get (i32.const 0) (i32.const 3) (i32.const 128) (i32.const 3))))
                (i32.const 0)))"#,
        r#"(module
            (import "astrolune_v2" "state_delete" (func $delete (param i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "key")
            (func (export "call") (result i32)
                (drop (call $delete (i32.const 0) (i32.const 3)))
                (i32.const 0)))"#,
        r#"(module
            (import "astrolune_v2" "emit" (func $emit (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "topic")
            (func (export "call") (result i32)
                (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 8)))
                (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 8)))
                (i32.const 0)))"#,
        r#"(module
            (import "astrolune_v2" "caller" (func $caller (param i32) (result i32)))
            (import "astrolune_v2" "block_height" (func $height (result i64)))
            (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
            (memory (export "memory") 1 2)
            (func (export "call") (result i32)
                (drop (call $caller (i32.const 0)))
                (i64.store (i32.const 32) (call $height))
                (drop (call $out (i32.const 0) (i32.const 40)))
                (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 1))"#,
        r#"(module (memory (export "memory") 1 256)
            (func (export "call") (result i32)
                (drop (memory.grow (i32.const 3))) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) unreachable))"#,
    ]
    .into_iter()
    .map(module)
    .collect()
}

/// Candidates the reference validator must reject.
fn rejected() -> Vec<Vec<u8>> {
    let valid = module(
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 0))"#,
    );
    // Code section: one body containing zero locals, i32.const 0 and end.
    let tail = [10, 6, 1, 4, 0, 65, 0, 11];
    assert!(valid.ends_with(&tail));

    let mut candidates = vec![
        Vec::new(),
        b"\0asm\x01\0\0\0".to_vec(),
        module(
            r#"(module (memory (export "memory") 1 1)
                (func (export "call") (result i32) i32.const 0)
                (func $float (result f32) f32.const 1))"#,
        ),
        module(
            r#"(module (import "astrolune_v2" "unknown" (func))
                (memory (export "memory") 1 1)
                (func (export "call") (result i32) i32.const 0))"#,
        ),
        module(r#"(module (memory (export "memory") 1 1))"#),
        module(
            r#"(module (memory (export "memory") 1 1)
                (func (export "call") (result i32) i32.const 0)
                (func $s) (start $s))"#,
        ),
        module(
            r#"(module (memory (export "memory") 1)
                (func (export "call") (result i32) i32.const 0))"#,
        ),
    ];
    for opcode in [0x01, 0x0b, 0x0f] {
        let mut invalid = valid.clone();
        let start = invalid.len() - tail.len();
        invalid[start + 1] += 1;
        invalid[start + 3] += 1;
        invalid.push(opcode);
        candidates.push(invalid);
    }
    candidates
}

/// Contract-local state and the access declaration authorizing it.
type Context = (BTreeMap<Vec<u8>, Vec<u8>>, BTreeSet<Vec<u8>>);

/// A finalized context in which the state, event and context paths succeed.
fn context() -> Context {
    (
        BTreeMap::from([(b"key".to_vec(), vec![3; 3])]),
        BTreeSet::from([b"key".to_vec()]),
    )
}

fn call<'a>(state: &'a BTreeMap<Vec<u8>, Vec<u8>>, access: &'a BTreeSet<Vec<u8>>) -> WasmCall<'a> {
    WasmCall {
        input: b"differential",
        caller: Address([5; 32]),
        height: 77,
        state,
        access,
        limits: LIMITS,
    }
}

fn forge(code: Vec<u8>) -> ContractModule {
    ContractModule {
        code_hash: wasm_code_hash(&code),
        version: WASM_VERSION,
        code,
    }
}

/// Builds a self-recursive module whose frames hold only the i32 parameter.
fn narrow_frames(depth: u32) -> Vec<u8> {
    module(&format!(
        r#"(module (memory (export "memory") 1 1)
            (func $down (param i32) (result i32)
                (if (result i32) (local.get 0)
                    (then (call $down (i32.sub (local.get 0) (i32.const 1))))
                    (else (i32.const 0))))
            (func (export "call") (result i32) (call $down (i32.const {depth}))))"#
    ))
}

/// Builds the same recursion with thirty-two additional i64 locals per frame.
fn wide_frames(depth: u32) -> Vec<u8> {
    let locals = (0..32)
        .map(|index| format!("(local $l{index} i64)"))
        .collect::<Vec<_>>()
        .join(" ");
    module(&format!(
        r#"(module (memory (export "memory") 1 1)
            (func $down (param i32) (result i32) {locals}
                (if (result i32) (local.get 0)
                    (then (call $down (i32.sub (local.get 0) (i32.const 1))))
                    (else (i32.const 0))))
            (func (export "call") (result i32) (call $down (i32.const {depth}))))"#
    ))
}

#[test]
fn qualified_profiles_agree_with_the_reference_interpreter_on_accepted_modules() {
    let reference = WasmRuntime::new();
    let (state, access) = context();
    let mut compared = 0;

    for (index, bytes) in modules().into_iter().enumerate() {
        let contract = reference.validate(&bytes, WASM_VERSION).unwrap();
        let expected = reference.execute_call(&contract, call(&state, &access));

        for profile in EngineProfile::ALTERNATES {
            let alternate = WasmRuntime::with_profile(profile);
            assert_eq!(alternate.profile(), profile);
            assert_eq!(
                alternate.validate(&bytes, WASM_VERSION),
                Ok(contract.clone()),
                "module {index} must validate identically under {profile:?}"
            );
            assert_eq!(
                wasm_difference(
                    &expected,
                    &alternate.execute_call(&contract, call(&state, &access))
                ),
                None,
                "module {index} must execute identically under {profile:?}"
            );
            compared += 1;
        }
    }

    assert_eq!(compared, 30, "ten modules across three alternate profiles");
}

#[test]
fn qualified_profiles_agree_on_rejected_modules_and_error_variants() {
    let reference = WasmRuntime::new();
    let (state, access) = context();
    let mut compared = 0;

    for (index, bytes) in rejected().into_iter().enumerate() {
        let expected = reference.validate(&bytes, WASM_VERSION);
        assert!(
            expected.is_err(),
            "candidate {index} must be rejected by the reference validator"
        );
        let contract = forge(bytes.clone());
        let executed = reference.execute_call(&contract, call(&state, &access));

        for profile in EngineProfile::ALTERNATES {
            let alternate = WasmRuntime::with_profile(profile);
            assert_eq!(
                alternate.validate(&bytes, WASM_VERSION),
                expected,
                "candidate {index} must be rejected identically under {profile:?}"
            );
            assert_eq!(
                wasm_difference(
                    &executed,
                    &alternate.execute_call(&contract, call(&state, &access))
                ),
                None,
                "candidate {index} must fail with the same error under {profile:?}"
            );
            compared += 1;
        }
    }

    assert_eq!(
        compared, 30,
        "ten rejected candidates across three profiles"
    );
}

#[test]
fn lazy_compilation_charges_its_own_work_to_the_call_and_stays_disqualified() {
    let reference = WasmRuntime::new();
    let (state, access) = context();
    // Measured on 2026-10-08 with Rust 1.99.0 and pinned Wasmi 2.0.0: charged
    // compute for the minimal returning module, by compilation strategy.
    let expected = [
        (EngineProfile::Reference, 2),
        (EngineProfile::PreallocatedStack, 2),
        (EngineProfile::UnpooledStack, 2),
        (EngineProfile::Alternate, 2),
        (EngineProfile::LazyTranslation, 30),
        (EngineProfile::Lazy, 38),
    ];

    for (profile, compute) in expected {
        let runtime = WasmRuntime::with_profile(profile);
        let contract = runtime.validate(&modules()[0], WASM_VERSION).unwrap();
        let output = runtime
            .execute_call(&contract, call(&state, &access))
            .unwrap();
        assert_eq!(
            output.resources.compute, compute,
            "{profile:?} must charge exactly {compute} compute for the minimal module"
        );
        assert_eq!(
            profile.is_consensus_neutral(),
            compute == 2,
            "{profile:?} neutrality must follow its charged compute"
        );
    }

    // The disagreement is a charged-compute disagreement, not a wrong result.
    for profile in EngineProfile::DISQUALIFIED {
        let runtime = WasmRuntime::with_profile(profile);
        for (index, bytes) in modules().into_iter().enumerate() {
            let contract = reference.validate(&bytes, WASM_VERSION).unwrap();
            assert_eq!(
                runtime.validate(&bytes, WASM_VERSION),
                Ok(contract.clone()),
                "module {index} must still validate identically under {profile:?}"
            );
            let expected = reference.execute_call(&contract, call(&state, &access));
            let observed = runtime.execute_call(&contract, call(&state, &access));
            assert!(
                matches!(
                    wasm_difference(&expected, &observed),
                    None | Some(OutputDifference::Compute)
                ),
                "module {index} under {profile:?} may differ only in charged compute"
            );
            if let (Ok(expected), Ok(observed)) = (&expected, &observed) {
                assert!(
                    observed.resources.compute > expected.resources.compute,
                    "module {index} under {profile:?} must charge more, not less"
                );
                assert_eq!(expected.return_data, observed.return_data);
                assert_eq!(expected.events, observed.events);
                assert_eq!(expected.writes, observed.writes);
                assert_eq!(expected.accessed, observed.accessed);
            }
        }
    }
}

#[test]
fn the_runtime_backend_seam_returns_exactly_the_projection_of_the_interpreter_output() {
    let reference = WasmBackend::new(EngineProfile::Reference, LIMITS);
    let (state, access) = (BTreeMap::new(), BTreeSet::new());

    for (index, bytes) in modules().into_iter().enumerate() {
        let contract = reference.runtime().validate(&bytes, WASM_VERSION).unwrap();
        let expected = reference
            .runtime()
            .execute_call(&contract, reference.seam_call(b"seam", &state, &access));
        let seam = reference.execute(&contract, b"seam");

        assert_eq!(
            seam,
            match &expected {
                Ok(output) => Ok(project_wasm_output(output)),
                Err(error) => Err(*error),
            },
            "module {index} seam output must be the projected interpreter output"
        );

        for profile in EngineProfile::ALTERNATES {
            let alternate = WasmBackend::new(profile, LIMITS);
            assert_eq!(alternate.kind(), reference.kind());
            assert_eq!(alternate.profile(), profile);
            assert_eq!(
                runtime_difference(&seam, &alternate.execute(&contract, b"seam")),
                None,
                "module {index} must agree across the seam under {profile:?}"
            );
        }
    }
}

#[test]
fn the_seam_cannot_express_events_writes_or_accessed_keys() {
    let backend = WasmBackend::new(EngineProfile::Alternate, LIMITS);
    let (state, access) = context();
    let bytes = module(
        r#"(module
            (import "astrolune_v2" "emit" (func $emit (param i32 i32 i32) (result i32)))
            (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "key")
            (func (export "call") (result i32)
                (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 8)))
                (drop (call $put (i32.const 0) (i32.const 3) (i32.const 64) (i32.const 4)))
                (i32.const 0)))"#,
    );
    let contract = backend.runtime().validate(&bytes, WASM_VERSION).unwrap();
    let full = backend
        .runtime()
        .execute_call(&contract, call(&state, &access))
        .unwrap();

    assert_eq!(full.events.len(), 1);
    assert_eq!(full.writes.len(), 1);
    assert_eq!(full.accessed.len(), 1);

    let projected = project_wasm_output(&full);
    assert_eq!(projected.return_data, full.return_data);
    assert_eq!(projected.resources, full.resources);

    let mut without_effects = full.clone();
    without_effects.events.clear();
    without_effects.writes.clear();
    without_effects.accessed.clear();
    assert_eq!(
        wasm_difference(&Ok(full), &Ok(without_effects.clone())),
        Some(OutputDifference::Events),
        "the complete comparison must observe discarded staged effects"
    );
    assert_eq!(
        runtime_difference(&Ok(projected), &Ok(project_wasm_output(&without_effects))),
        None,
        "the narrow seam provably cannot observe them"
    );
}

#[test]
fn the_recursion_and_stack_caps_are_consensus_visible_and_not_backend_axes() {
    let (state, access) = context();
    // Measured on 2026-10-08 with Rust 1.99.0 and pinned Wasmi 2.0.0. The
    // 128-frame cap retires narrow frames at depth 127; the 16,384-byte value
    // stack cap retires thirty-two-i64 frames much earlier, at depth 61. Both
    // bounds are therefore directly observable in a call's result and cannot be
    // varied by a backend.
    for profile in EngineProfile::QUALIFIED {
        let runtime = WasmRuntime::with_profile(profile);

        for (build, last, first_failing) in [
            (narrow_frames as fn(u32) -> Vec<u8>, 126, 127),
            (wide_frames as fn(u32) -> Vec<u8>, 60, 61),
        ] {
            let accepted = runtime.validate(&build(last), WASM_VERSION).unwrap();
            assert!(
                runtime
                    .execute_call(&accepted, call(&state, &access))
                    .is_ok(),
                "depth {last} must stay inside the fixed caps under {profile:?}"
            );

            let exhausted = runtime
                .validate(&build(first_failing), WASM_VERSION)
                .unwrap();
            assert_eq!(
                runtime.execute_call(&exhausted, call(&state, &access)),
                Err(RuntimeError::LimitExceeded),
                "depth {first_failing} must exceed the fixed caps under {profile:?}"
            );
        }
    }
}

#[test]
fn every_profile_builds_a_send_and_sync_interpreter_backend() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WasmRuntime>();
    assert_send_sync::<WasmBackend>();

    for profile in EngineProfile::QUALIFIED {
        let backend: Box<dyn RuntimeBackend> = Box::new(WasmBackend::new(profile, LIMITS));
        assert_eq!(
            backend.kind(),
            BackendKind::Interpreter,
            "{profile:?} interprets Wasmi bytecode and must not claim Aot or Jit"
        );
    }
}
