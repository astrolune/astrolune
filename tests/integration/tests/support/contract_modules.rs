// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Structured WebAssembly contract corpus for the contract fuzz surface.
//!
//! Shared by the stable-toolchain contract mutation campaign and by the seed
//! exporter that feeds the `execute_contract` libFuzzer target. The modules
//! cover the returning, fuel-exhausting, input/output, state read-write, state
//! delete, event, context, nonzero-status and memory-growth paths of the host
//! ABI. `wat` is only reachable from the `integration` package, so this file is
//! deliberately separate from the oracle the fuzz target compiles.

/// Exact code-section tail of the first module: one body, zero locals,
/// `i32.const 0`, `end`. The malformed regressions are derived from it.
pub const MINIMAL_TAIL: [u8; 8] = [10, 6, 1, 4, 0, 65, 0, 11];

/// Builds the structured, individually accepted contract modules.
pub fn modules() -> Vec<Vec<u8>> {
    [
        // Minimal returning module; the regression source.
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 0))"#,
        // Unbounded loop, retired by the fuel grant alone.
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) (loop br 0) i32.const 0))"#,
        // Input length, input copy and output, bounded by the bandwidth grant.
        r#"(module
            (import "astrolune_v2" "input_len" (func $len (result i32)))
            (import "astrolune_v2" "input_copy" (func $copy (param i32 i32 i32) (result i32)))
            (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
            (memory (export "memory") 1 2)
            (func (export "call") (result i32)
                (drop (call $copy (i32.const 0) (i32.const 128) (call $len)))
                (drop (call $out (i32.const 128) (call $len)))
                (i32.const 0)))"#,
        // Declared state write then read-back, bounded by the I/O grant.
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
        // Declared state deletion, which traps when the key is undeclared.
        r#"(module
            (import "astrolune_v2" "state_delete" (func $delete (param i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "key")
            (func (export "call") (result i32)
                (drop (call $delete (i32.const 0) (i32.const 3)))
                (i32.const 0)))"#,
        // Two 32-byte-topic events, bounded by the bandwidth grant.
        r#"(module
            (import "astrolune_v2" "emit" (func $emit (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1 2) (data (i32.const 0) "topic")
            (func (export "call") (result i32)
                (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 8)))
                (drop (call $emit (i32.const 0) (i32.const 64) (i32.const 8)))
                (i32.const 0)))"#,
        // Authenticated caller and finalized height, returned as output.
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
        // Nonzero status, which stages no writes or events.
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32) i32.const 1))"#,
        // Memory growth, retired by the memory grant through the store limiter.
        r#"(module (memory (export "memory") 1 256)
            (func (export "call") (result i32)
                (drop (memory.grow (i32.const 3))) (i32.const 0)))"#,
    ]
    .into_iter()
    .map(|body| wat::parse_str(body).unwrap())
    .collect()
}

/// Derives the malformed regressions that place an instruction after a
/// function's `end`, the case Wasmi 2.0.0 could reach with an empty control
/// stack. The exact tail of `valid` is asserted so the derivation cannot
/// silently stop producing those modules.
pub fn regressions(valid: &[u8]) -> Vec<Vec<u8>> {
    assert!(
        valid.ends_with(&MINIMAL_TAIL),
        "the minimal module's code-section tail changed; update MINIMAL_TAIL"
    );

    [0x01, 0x0b, 0x0f]
        .into_iter()
        .map(|opcode| {
            let mut invalid = valid.to_vec();
            let start = invalid.len() - MINIMAL_TAIL.len();

            invalid[start + 1] += 1;
            invalid[start + 3] += 1;
            invalid.push(opcode);

            invalid
        })
        .collect()
}

/// Builds the exported contract corpus: accepted modules then regressions.
pub fn corpus() -> Vec<Vec<u8>> {
    let mut corpus = modules();
    let valid = corpus[0].clone();

    corpus.extend(regressions(&valid));
    corpus
}
