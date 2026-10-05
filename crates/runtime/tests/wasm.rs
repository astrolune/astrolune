// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Host isolation, validation, deterministic execution, and resource exhaustion.

use runtime::{ModuleValidator, RuntimeError, WASM_VERSION, WasmCall, WasmRuntime};
use std::collections::{BTreeMap, BTreeSet};
use types::{Address, Resources};

fn call<'a>(state: &'a BTreeMap<Vec<u8>, Vec<u8>>, access: &'a BTreeSet<Vec<u8>>) -> WasmCall<'a> {
    WasmCall {
        input: b"hello",
        caller: Address([7; 32]),
        height: 9,
        state,
        access,
        limits: Resources {
            compute: 100_000,
            memory: 131_072,
            io: 100_000,
            bandwidth: 100_000,
        },
    }
}
fn module(body: &str) -> Vec<u8> {
    wat::parse_str(body).unwrap()
}

#[test]
fn instructions_after_function_end_are_rejected_before_translation() {
    let runtime = WasmRuntime::new();
    let valid = module(
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 0))"#,
    );
    // Code section: one body containing zero locals, i32.const 0 and end.
    let suffix = [10, 6, 1, 4, 0, 65, 0, 11];
    assert!(valid.ends_with(&suffix));
    for opcode in [0x01, 0x0b, 0x0f] {
        let mut invalid = valid.clone();
        let start = invalid.len() - suffix.len();
        invalid[start + 1] += 1;
        invalid[start + 3] += 1;
        invalid.push(opcode);
        assert_eq!(
            runtime.validate(&invalid, WASM_VERSION),
            Err(RuntimeError::InvalidModule)
        );
        let forged = runtime::ContractModule {
            code_hash: runtime::wasm_code_hash(&invalid),
            code: invalid,
            version: WASM_VERSION,
        };
        assert_eq!(
            runtime.execute_call(&forged, call(&BTreeMap::new(), &BTreeSet::new())),
            Err(RuntimeError::InvalidModule)
        );
    }
}

#[test]
fn input_output_is_repeatable_and_resources_are_deterministic() {
    let runtime = WasmRuntime::new();
    let wasm = module(
        r#"(module
        (import "astrolune_v2" "input_len" (func $len (result i32)))
        (import "astrolune_v2" "input_copy" (func $copy (param i32 i32 i32) (result i32)))
        (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
        (memory (export "memory") 1 2)
        (func (export "call") (result i32)
            (drop (call $copy (i32.const 0) (i32.const 128) (call $len)))
            (drop (call $out (i32.const 128) (call $len))) (i32.const 0)))"#,
    );
    let contract = runtime.validate(&wasm, WASM_VERSION).unwrap();
    let (state, access) = (BTreeMap::new(), BTreeSet::new());
    let first = runtime
        .execute_call(&contract, call(&state, &access))
        .unwrap();
    assert_eq!(first.return_data, b"hello");
    assert!(first.resources.compute > 0);
    assert_eq!(first.resources.memory, 65536);
    assert_eq!(first.resources.bandwidth, 5);
    assert!(first.writes.is_empty());
    for _ in 0..3 {
        assert_eq!(
            runtime
                .execute_call(&contract, call(&state, &access))
                .unwrap(),
            first
        );
        assert_eq!(
            WasmRuntime::new()
                .execute_call(&contract, call(&state, &access))
                .unwrap(),
            first
        );
    }
    let mut forged = contract;
    forged.code_hash.0[0] ^= 1;
    assert_eq!(
        runtime.execute_call(&forged, call(&state, &access)),
        Err(RuntimeError::InvalidModule)
    );
}

#[test]
fn state_is_private_lease_checked_and_visible_within_call() {
    let runtime = WasmRuntime::new();
    let wasm = module(
        r#"(module
        (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
        (import "astrolune_v2" "state_get" (func $get (param i32 i32 i32 i32) (result i32)))
        (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
        (memory (export "memory") 1 2) (data (i32.const 0) "keynew")
        (func (export "call") (result i32)
            (drop (call $put (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 3)))
            (drop (call $out (i32.const 128) (call $get (i32.const 0) (i32.const 3) (i32.const 128) (i32.const 3))))
            (i32.const 0)))"#,
    );
    let contract = runtime.validate(&wasm, WASM_VERSION).unwrap();
    let state = BTreeMap::from([(b"key".to_vec(), b"old".to_vec())]);
    let access = BTreeSet::from([b"key".to_vec()]);
    let output = runtime
        .execute_call(&contract, call(&state, &access))
        .unwrap();
    assert_eq!(output.return_data, b"new");
    assert_eq!(output.writes[&b"key"[..]], Some(b"new".to_vec()));
    assert_eq!(output.accessed, access);
    assert_eq!(state[&b"key"[..]], b"old");
    assert!(
        runtime
            .execute_call(&contract, call(&state, &BTreeSet::new()))
            .is_err()
    );
    let mut low_io = call(&state, &access);
    low_io.limits.io = 1;
    assert_eq!(
        runtime.execute_call(&contract, low_io),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(state[&b"key"[..]], b"old");
}

#[test]
fn rejects_forbidden_features_imports_start_memory_and_signatures() {
    let runtime = WasmRuntime::new();
    for invalid in [
        r#"(module (memory (export "memory") 1) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (memory (export "memory") 1 257) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (memory (export "memory") 1 2) (func (export "call") (result i32) f32.const 1 drop i32.const 0))"#,
        r#"(module (memory (export "memory") 1 2) (func (export "call")))"#,
        r#"(module (memory (export "memory") 1 2) (func $start) (start $start) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (import "wasi_snapshot_preview1" "random_get" (func)) (memory (export "memory") 1 2) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (import "astrolune_v2" "input_len" (func (param i32))) (memory (export "memory") 1 2) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (import "astrolune_v2" "memory" (memory 1 2)) (export "memory" (memory 0)) (func (export "call") (result i32) i32.const 0))"#,
        r#"(module (memory (export "memory") 1 2 shared) (func (export "call") (result i32) i32.const 0))"#,
    ] {
        assert!(
            runtime.validate(&module(invalid), WASM_VERSION).is_err(),
            "accepted {invalid}"
        );
    }
    assert!(runtime.validate(b"(module)", WASM_VERSION).is_err());
}

#[test]
fn infinite_loops_recursion_growth_and_bad_pointers_are_bounded() {
    let runtime = WasmRuntime::new();
    let (state, access) = (BTreeMap::new(), BTreeSet::new());
    for body in [
        "(loop $forever br $forever) i32.const 0",
        "call 0",
        "i32.const 3 memory.grow",
        "i32.const -1 i32.load drop i32.const 0",
        "unreachable",
        "i32.const 1",
    ] {
        let wasm = module(&format!(
            r#"(module (memory (export "memory") 1 2) (func (export "call") (result i32) {body}))"#
        ));
        let contract = runtime.validate(&wasm, WASM_VERSION).unwrap();
        assert!(
            runtime
                .execute_call(&contract, call(&state, &access))
                .is_err(),
            "accepted {body}"
        );
    }
    let wasm = module(
        r#"(module (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
        (memory (export "memory") 1 2) (func (export "call") (result i32) i32.const -1 i32.const 5 call $out))"#,
    );
    let contract = runtime.validate(&wasm, WASM_VERSION).unwrap();
    assert_eq!(
        runtime.execute_call(&contract, call(&state, &access)),
        Err(RuntimeError::Trap)
    );
}
