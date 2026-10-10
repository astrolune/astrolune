// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Shared ABI-v2 contract fixtures for the `runtime` qualification suites.
//!
//! Included by `crates/runtime/tests/backends.rs` and
//! `crates/runtime/tests/aot.rs` through `#[path]` source inclusion, so the
//! engine-configuration campaign and the ahead-of-time campaign compare the
//! same ten accepted modules, the same ten rejected candidates and the same
//! recursion fixtures against the same reference interpreter.
//!
//! These are hand-written fixtures covering the host ABI's paths. They are not
//! a generated corpus, not a contract produced by a real compiler and not a
//! statement about which modules a deployment will see; the mutation campaign
//! in `tests/integration/tests/backends.rs` supplies the derived inputs.

use runtime::{ContractModule, WASM_VERSION, WasmCall, wasm_code_hash};
use std::collections::{BTreeMap, BTreeSet};
use types::{Address, Resources};

/// Deterministic grant shared by every comparison; far below the call bounds.
pub const LIMITS: Resources = Resources {
    compute: 1_000_000,
    memory: 1_048_576,
    io: 65_536,
    bandwidth: 65_536,
};

/// Assembles one module from WebAssembly text.
pub fn module(body: &str) -> Vec<u8> {
    wat::parse_str(body).unwrap()
}

/// Modules exercising the returning, looping, input/output, state, delete,
/// event, context, nonzero-status, memory-growth and trapping paths.
pub fn modules() -> Vec<Vec<u8>> {
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
pub fn rejected() -> Vec<Vec<u8>> {
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
pub type Context = (BTreeMap<Vec<u8>, Vec<u8>>, BTreeSet<Vec<u8>>);

/// A finalized context in which the state, event and context paths succeed.
pub fn context() -> Context {
    (
        BTreeMap::from([(b"key".to_vec(), vec![3; 3])]),
        BTreeSet::from([b"key".to_vec()]),
    )
}

/// Borrows one finalized call over the shared context and grant.
pub fn call<'a>(
    state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    access: &'a BTreeSet<Vec<u8>>,
) -> WasmCall<'a> {
    WasmCall {
        input: b"differential",
        caller: Address([5; 32]),
        height: 77,
        state,
        access,
        limits: LIMITS,
    }
}

/// Wraps bytes as a module whose declared hash and version are consistent.
pub fn forge(code: Vec<u8>) -> ContractModule {
    ContractModule {
        code_hash: wasm_code_hash(&code),
        version: WASM_VERSION,
        code,
    }
}

/// Builds a self-recursive module whose frames hold only the i32 parameter.
pub fn narrow_frames(depth: u32) -> Vec<u8> {
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
pub fn wide_frames(depth: u32) -> Vec<u8> {
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
