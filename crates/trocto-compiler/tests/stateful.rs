// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed control flow, capability ordering, effects, and native ABI invariants.

use trocto_compiler::{
    ContractContext, ExecutionError, MAX_EVENTS, MAX_NESTING, MAX_STATE_KEY_BYTES, MAX_STATE_KEYS,
    STATEFUL_LANGUAGE_VERSION, STATEFUL_METERING_VERSION, compile,
};

fn source(body: &str) -> String {
    format!("fn call(input: u64) -> u64 {{ {body} }}")
}

fn context(keys: Vec<Vec<u8>>) -> ContractContext {
    ContractContext {
        state: vec![None; keys.len()],
        access: vec![true; keys.len()],
        keys,
        ..ContractContext::default()
    }
}

#[test]
fn mutation_loop_lexical_shadowing_and_early_returns() {
    let program = compile(&source(
        "let mut total: u64 = 0; let mut n = 0;
         while n < input { total = total + n; n = n + 1; }
         if input == 0 { return 9; } else { let total: bool = true;
         if !total { return 8; } }
         return total;",
    ))
    .unwrap();
    assert_eq!(program.language_version(), STATEFUL_LANGUAGE_VERSION);
    assert_eq!(program.metering_version(), STATEFUL_METERING_VERSION);
    assert_eq!(program.evaluate(0, 1000).unwrap().value, 9);
    for input in 1..20 {
        assert_eq!(
            program.evaluate(input, 1000).unwrap().value,
            input * (input - 1) / 2
        );
    }
    let branches = compile(&source("if input > 0 { return 1; } else { return 2; }")).unwrap();
    assert_eq!(branches.evaluate(0, 10).unwrap().value, 2);
    assert_eq!(branches.evaluate(1, 10).unwrap().value, 1);
}

#[test]
fn type_scope_initialization_and_control_errors_are_rejected() {
    for body in [
        "let mut x = 1; let x = 2; return x;",
        "let mut x = 1; if true { let x = 2; x = 3; } return x;",
        "if true { let x = 1; } return x;",
        "let mut x: u64; return x;",
        "let mut x = x; return x;",
        "let mut x = 1; x = false; return x;",
        "let x = false; return x;",
        "if 1 { return 1; } else { return 0; }",
        "if true { return 1; }",
        "if true { return 1; } else { return 0; } return 2;",
        "while false { return 1; }",
        "let mut x = 1; let key_count = 1; return x;",
        "return state_get_at(false);",
        "state_set_at(0, false); return 0;",
        "return key_word(0, input);",
        "return key_word(0, 4);",
        "return caller(4);",
        "if true == 1 { return 1; } else { return 2; }",
    ] {
        assert!(compile(&source(body)).is_err(), "accepted {body}");
    }
}

#[test]
fn short_circuit_skips_arithmetic_access_and_dynamic_bounds() {
    for condition in [
        "false && 1 / 0 == 0",
        "true || 18446744073709551615 + 1 == 0",
        "false && state_get(\"secret\") == 0",
        "true || state_get_at(18446744073709551615) == 0",
    ] {
        let program = compile(&source(&format!(
            "if {condition} {{ return 1; }} else {{ return 2; }}"
        )))
        .unwrap();
        let mut ctx = context(program.state_keys().to_vec());
        ctx.access.fill(false);
        let result = program.evaluate_contract(0, &ctx, 4).unwrap();
        assert_eq!(result.fuel_used, 4);
    }
    let program = compile(&source(
        "if true && 1 / 0 == 0 { return 1; } else { return 2; }",
    ))
    .unwrap();
    assert_eq!(program.evaluate(0, 4), Err(ExecutionError::FuelExhausted));
    assert_eq!(program.evaluate(0, 5), Err(ExecutionError::DivisionByZero));
}

#[test]
fn empty_loops_always_consume_fuel_and_allow_local_interruption() {
    let program = compile(&source("while true { } return 0;")).unwrap();
    for fuel in [0, 1, 2, 3, 1000] {
        assert_eq!(
            program.evaluate(0, fuel),
            Err(ExecutionError::FuelExhausted)
        );
    }
    let mut polls = 0;
    let result = program
        .evaluate_contract_with_interrupt(0, &ContractContext::default(), u64::MAX, || {
            polls += 1;
            polls == 3
        })
        .unwrap();
    assert_eq!(result, None);
    assert_eq!(polls, 3);
}

#[test]
fn state_metadata_effects_and_atomic_failure() {
    let program = compile(&source(
        "let mut n: u64 = 0; let mut total: u64 = state_get(\"balance\");
         while n < input { total = total + 1; n = n + 1; }
         if total >= 10 && caller(0) != 0 {
         state_set(\"balance\", total); emit(height(), total);
         } else { state_delete(\"balance\"); } return total;",
    ))
    .unwrap();
    assert!(program.requires_context());
    assert_eq!(
        program.evaluate(3, 1000),
        Err(ExecutionError::InvalidContext)
    );
    let mut ctx = context(program.state_keys().to_vec());
    ctx.height = 42;
    ctx.caller[0] = 1;
    ctx.state[0] = Some(8);
    let output = program.evaluate_contract(3, &ctx, 1000).unwrap();
    assert_eq!(output.value, 11);
    assert_eq!(output.state, vec![Some(11)]);
    assert_eq!(output.writes, vec![true]);
    assert_eq!(output.events, vec![(42, 11)]);
    assert_eq!(
        program.evaluate_contract(0, &ctx, 1000).unwrap().state,
        vec![None]
    );
    ctx.access[0] = false;
    assert_eq!(
        program.evaluate_contract(3, &ctx, 1000),
        Err(ExecutionError::AccessDenied)
    );
    ctx.access[0] = true;
    let rollback = compile(&source(
        "state_set(\"balance\", 99); emit(1, 2); return 1 / 0;",
    ))
    .unwrap();
    let original = ctx.clone();
    assert_eq!(
        rollback.evaluate_contract(0, &ctx, 1000),
        Err(ExecutionError::DivisionByZero)
    );
    assert_eq!(ctx, original);
}

#[test]
fn dynamic_address_keys_read_write_delete_and_error_order() {
    let mut ctx = context(vec![vec![1; 32], vec![2; 32]]);
    ctx.state = vec![Some(7), None];
    ctx.caller = [u64::from_le_bytes([1; 8]); 4];
    let program = compile(&source(
        "if key_word(input, 0) == caller(0) && key_word(input, 3) == caller(3) {
         state_set_at(input, state_get_at(input) + key_count()); emit(input, key_count());
         } else { state_delete_at(input); } return state_get_at(input);",
    ))
    .unwrap();
    let output = program.evaluate_contract(0, &ctx, 1000).unwrap();
    assert_eq!(output.value, 9);
    assert_eq!(output.state, vec![Some(9), None]);
    assert_eq!(output.writes, vec![true, false]);
    assert_eq!(output.events, vec![(0, 2)]);
    assert_eq!(
        program.evaluate_contract(1, &ctx, 1000).unwrap().state,
        vec![Some(7), None]
    );
    let get = compile(&source("return state_get_at(input);")).unwrap();
    assert_eq!(
        get.evaluate_contract(u64::MAX, &ctx, 1),
        Err(ExecutionError::FuelExhausted)
    );
    assert_eq!(
        get.evaluate_contract(u64::MAX, &ctx, 2),
        Err(ExecutionError::Bounds)
    );
    ctx.access[0] = false;
    assert_eq!(
        get.evaluate_contract(0, &ctx, 1),
        Err(ExecutionError::FuelExhausted)
    );
    assert_eq!(
        get.evaluate_contract(0, &ctx, 2),
        Err(ExecutionError::AccessDenied)
    );
    let word = compile(&source("return key_word(input, 0);")).unwrap();
    let short = context(vec![vec![1; 31]]);
    assert_eq!(
        word.evaluate_contract(0, &short, 2),
        Err(ExecutionError::Bounds)
    );
}

#[test]
fn contexts_require_prefix_unique_sorted_extras_and_bounded_shapes() {
    let program = compile(&source("state_set(\"z\", state_get(\"a\")); return 0;")).unwrap();
    assert_eq!(program.state_keys(), &[b"a".to_vec(), b"z".to_vec()]);
    let ctx = context(vec![
        b"a".to_vec(),
        b"z".to_vec(),
        b"b".to_vec(),
        b"c".to_vec(),
    ]);
    assert!(program.evaluate_contract(0, &ctx, 10).is_ok());
    for keys in [
        vec![b"z".to_vec(), b"a".to_vec()],
        vec![b"a".to_vec()],
        vec![b"a".to_vec(), b"z".to_vec(), b"c".to_vec(), b"b".to_vec()],
        vec![b"a".to_vec(), b"z".to_vec(), b"a".to_vec()],
        vec![b"a".to_vec(), b"z".to_vec(), Vec::new()],
        vec![
            b"a".to_vec(),
            b"z".to_vec(),
            vec![0; MAX_STATE_KEY_BYTES + 1],
        ],
    ] {
        assert_eq!(
            program.evaluate_contract(0, &context(keys), 0),
            Err(ExecutionError::InvalidContext)
        );
    }
    let scalar = compile(&source("return input;")).unwrap();
    assert_eq!(scalar.language_version(), 1);
    let ctx = context(vec![vec![0; 32], vec![1; 32]]);
    let output = scalar.evaluate_contract(7, &ctx, 1).unwrap();
    assert_eq!(output.state, ctx.state);
    assert_eq!(output.writes, vec![false, false]);
    let mut bad = ctx.clone();
    bad.state.pop();
    assert_eq!(
        scalar.evaluate_contract(0, &bad, 0),
        Err(ExecutionError::InvalidContext)
    );
    let keys = (0..=MAX_STATE_KEYS)
        .map(|i| u64::try_from(i).unwrap().to_be_bytes().to_vec())
        .collect();
    assert_eq!(
        scalar.evaluate_contract(0, &context(keys), 0),
        Err(ExecutionError::InvalidContext)
    );
}

#[test]
fn events_are_bounded_and_failure_publishes_no_effects() {
    let program = compile(&source(
        "let mut n = 0; while n < input { emit(1, n); n = n + 1; } return n;",
    ))
    .unwrap();
    let ctx = ContractContext::default();
    let output = program
        .evaluate_contract(u64::try_from(MAX_EVENTS).unwrap(), &ctx, 10000)
        .unwrap();
    assert_eq!(output.events.len(), MAX_EVENTS);
    assert_eq!(
        program.evaluate_contract(u64::try_from(MAX_EVENTS + 1).unwrap(), &ctx, 10000),
        Err(ExecutionError::EventLimit)
    );
    assert_eq!(ctx.state, Vec::<Option<u64>>::new());
}

#[test]
fn v2_llvm_contains_bounded_slots_and_final_native_abi() {
    let program = compile(&source(
        "state_set_at(input, key_word(input, 2)); return state_get_at(input);",
    ))
    .unwrap();
    let ir = program.llvm_ir();
    assert!(
        ir.contains("i64 %height, i64 %state_count, ptr %key_words, ptr %key_lengths, ptr %caller")
    );
    assert!(ir.contains("label %bounds_error"));
    assert!(ir.contains("bounds_error:\n  ret i32 7"));
    assert!(ir.contains("%count_maximum = icmp ule i64 %state_count, 1024"));
    assert_eq!(
        ir,
        compile(&source(
            "state_set_at(input, key_word(input, 2)); return state_get_at(input);"
        ))
        .unwrap()
        .llvm_ir()
    );
}

#[test]
fn new_recursive_syntax_and_literal_keys_obey_compiler_limits() {
    let blocks = format!(
        "{}return 0;{}return 1;",
        "if true {".repeat(MAX_NESTING + 1),
        "}".repeat(MAX_NESTING + 1)
    );
    assert!(
        compile(&source(&blocks))
            .unwrap_err()
            .message
            .contains("nesting limit")
    );
    let calls = format!(
        "return {}0{};",
        "state_get_at(".repeat(MAX_NESTING + 1),
        ")".repeat(MAX_NESTING + 1)
    );
    assert!(
        compile(&source(&calls))
            .unwrap_err()
            .message
            .contains("nesting limit")
    );
    let valid = "x".repeat(MAX_STATE_KEY_BYTES);
    assert!(compile(&source(&format!("return state_get(\"{valid}\");"))).is_ok());
    for key in [
        String::new(),
        "x".repeat(MAX_STATE_KEY_BYTES + 1),
        "a\\b".to_owned(),
        "ключ".to_owned(),
    ] {
        assert!(compile(&source(&format!("return state_get(\"{key}\");"))).is_err());
    }
    let mut keys = String::new();
    for index in 0..MAX_STATE_KEYS {
        use std::fmt::Write;
        write!(keys, "state_delete(\"k{index}\");").unwrap();
    }
    assert_eq!(
        compile(&source(&(keys.clone() + "return 0;")))
            .unwrap()
            .state_keys()
            .len(),
        MAX_STATE_KEYS
    );
    keys.push_str("state_delete(\"extra\"); return 0;");
    assert!(
        compile(&source(&keys))
            .unwrap_err()
            .message
            .contains("state key count limit")
    );
    let bounded = source(
        "let mut x = 0; while x < input { if x == 2 { return state_get_at(x); } x = x + 1; } return x;",
    );
    for index in 0..bounded.len() {
        for byte in [0, b'!', b'"', b'(', b')', b'{', b'}', b';', 127] {
            let mut bytes = bounded.as_bytes().to_vec();
            bytes[index] = byte;
            let _ = compile(&String::from_utf8(bytes).unwrap());
        }
    }
}

#[test]
fn llvm_definitions_are_unique_across_all_instruction_families() {
    let program = compile(&source(
        "let mut n = input; let flag = !(n == 0); let mut count = 0;
         while flag && count < 1 {
         n = n + 3 - 1; n = n * 2 / 2 % 9;
         state_set(\"a\", n); state_delete(\"b\");
         state_set_at(0, state_get_at(0)); state_delete_at(1);
         emit(height(), caller(0)); count = count + 1; }
         if n != state_get(\"a\") || n <= key_count() {
         return key_word(0, 3); } else { return n; }",
    ))
    .unwrap();
    let mut definitions = std::collections::BTreeSet::new();
    for line in program.llvm_ir().lines() {
        if line.starts_with("define ") {
            definitions.clear();
        }
        let line = line.trim();
        if line.starts_with('%')
            && let Some((name, _)) = line.split_once(" = ")
        {
            assert!(
                definitions.insert(name.to_owned()),
                "duplicate LLVM definition {name}"
            );
        }
    }
}
