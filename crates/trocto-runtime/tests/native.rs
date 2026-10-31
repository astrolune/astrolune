// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real native LLVM compilation, persistent IPC and reference equivalence.

use std::{path::PathBuf, time::Duration};

use trocto_compiler::{ContractContext, ExecutionError, compile};
use trocto_runtime::{
    LLVM_VERSION, MAX_NATIVE_FUEL, NativeArtifactCache, NativeError, NativeProgram,
};

fn clang() -> PathBuf {
    std::env::var_os("ASTROLUNE_LLVM_CLANG").map_or_else(|| PathBuf::from("clang"), PathBuf::from)
}

#[test]
#[ignore = "requires pinned native clang 22.1.8; optional ASTROLUNE_LLVM_CLANG"]
fn native_arithmetic_and_fuel_match_reference_across_reused_workers() {
    for expression in [
        "input + 7",
        "input - 7",
        "input * 7",
        "input / 7",
        "input % 7",
        "input / (input % 7)",
    ] {
        let source =
            format!("fn call(input: u64) -> u64 {{ let x: u64 = {expression}; return x + 1; }}");
        let program = compile(&source).unwrap();
        let mut native =
            NativeProgram::compile(program.clone(), &clang(), Duration::from_secs(30)).unwrap();
        assert!(native.compiler_identity().contains(LLVM_VERSION));
        let mut state = 42_u64;
        let inputs = [0, 1, 6, 7, 8, u64::MAX / 7, u64::MAX - 7, u64::MAX];
        for input in inputs.into_iter().chain((0..64).map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            state
        })) {
            for fuel in [0, 1, 2, 3, 4, 5, 6, 7, 8, MAX_NATIVE_FUEL] {
                let expected = program.evaluate(input, fuel);
                let actual = native.execute(input, fuel, Duration::from_secs(5));
                match (expected, actual) {
                    (Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
                    (Err(expected), Err(NativeError::Contract(actual))) => {
                        assert_eq!(actual, expected);
                    }
                    (expected, actual) => panic!(
                        "native/reference mismatch: {expression}, input={input}, fuel={fuel}, expected={expected:?}, actual={actual:?}"
                    ),
                }
            }
        }
    }
}

fn contract(body: &str) -> String {
    format!("fn call(input: u64) -> u64 {{ {body} }}")
}

fn check(
    native: &mut NativeProgram,
    program: &trocto_compiler::Program,
    input: u64,
    context: &ContractContext,
    fuel: u64,
) {
    let expected = program.evaluate_contract(input, context, fuel);
    match (
        expected,
        native.execute_contract(input, context, fuel, Duration::from_secs(5)),
    ) {
        (Ok(expected), Ok(actual)) => assert_eq!(expected, actual),
        (Err(expected), Err(NativeError::Contract(actual))) => assert_eq!(expected, actual),
        (expected, actual) => panic!(
            "contract mismatch: input={input} fuel={fuel} expected={expected:?} actual={actual:?}"
        ),
    }
}

#[test]
#[ignore = "requires pinned native clang 22.1.8"]
fn native_control_flow_short_circuit_shadowing_and_early_return() {
    for body in [
        "let mut n = 0; let mut total = 0; while n < input { let total: bool = true; if !total { return 999; } n = n + 1; } if n == 0 { return 7; } else { total = n; } return total;",
        "if false && 1 / 0 == 0 { return 3; } else { if true || state_get_at(18446744073709551615) == 0 { return input; } else { return 5; } }",
        "if input > 0 { return 1; } else { return 2; }",
        "if true && 1 / 0 == 0 { return 1; } else { return 2; }",
    ] {
        let program = compile(&contract(body)).unwrap();
        let mut native =
            NativeProgram::compile(program.clone(), &clang(), Duration::from_secs(30)).unwrap();
        for input in [0, 1, 10] {
            for fuel in [0, 1, 2, 3, 4, 5, 10, 100, 1000] {
                check(
                    &mut native,
                    &program,
                    input,
                    &ContractContext::default(),
                    fuel,
                );
            }
        }
    }
}

#[test]
#[ignore = "requires pinned native clang 22.1.8"]
fn native_state_address_keys_metadata_events_and_failure_rollback() {
    let program=compile(&contract("if key_word(input, 0) == caller(0) && key_word(input, 3) == caller(3) { state_set_at(input, state_get_at(input) + key_count()); emit(height(), key_count()); } else { state_delete_at(input); } return state_get_at(input);")).unwrap();
    let context = ContractContext {
        height: 42,
        caller: [u64::from_le_bytes([1; 8]); 4],
        keys: vec![vec![1; 32], vec![2; 32]],
        state: vec![Some(7), None],
        access: vec![true, true],
    };
    let mut native =
        NativeProgram::compile(program.clone(), &clang(), Duration::from_secs(30)).unwrap();
    for input in [0, 1, 2, u64::MAX] {
        for fuel in [0, 1, 2, 3, 4, 5, 10, 100] {
            check(&mut native, &program, input, &context, fuel);
        }
    }
    for body in [
        "state_set(\"balance\", 99); emit(height(), caller(0)); return 1 / input;",
        "return state_get_at(input);",
        "return key_word(input, 0);",
        "return input + 1;",
    ] {
        let program = compile(&contract(body)).unwrap();
        let mut context = context.clone();
        let mut keys = program.state_keys().to_vec();
        keys.extend(context.keys.clone());
        context.keys = keys;
        context.state = vec![Some(7); context.keys.len()];
        context.access = vec![true; context.keys.len()];
        let mut native =
            NativeProgram::compile(program.clone(), &clang(), Duration::from_secs(30)).unwrap();
        for input in [0, 1, 2, u64::MAX] {
            for fuel in [0, 1, 2, 3, 4, 100] {
                check(&mut native, &program, input, &context, fuel);
            }
        }
        context.access.fill(false);
        check(&mut native, &program, 0, &context, 100);
        if program.state_keys().is_empty() {
            context.keys = vec![vec![1; 31]];
            context.state = vec![None];
            context.access = vec![true];
            check(&mut native, &program, 0, &context, 100);
        }
    }
}

#[test]
#[ignore = "requires pinned native clang 22.1.8"]
fn native_event_limit_and_protocol_fuel_limit() {
    let program = compile(&contract(
        "let mut n = 0; while n < input { emit(1, n); n = n + 1; } return n;",
    ))
    .unwrap();
    let mut native =
        NativeProgram::compile(program.clone(), &clang(), Duration::from_secs(30)).unwrap();
    for input in [0, 1, 256, 257] {
        check(
            &mut native,
            &program,
            input,
            &ContractContext::default(),
            10000,
        );
    }
    assert!(matches!(
        native.execute_contract(
            0,
            &ContractContext::default(),
            MAX_NATIVE_FUEL + 1,
            Duration::from_secs(1)
        ),
        Err(NativeError::FuelLimit)
    ));
    check(&mut native, &program, 1, &ContractContext::default(), 10000);
}

#[test]
#[ignore = "requires pinned native clang 22.1.8"]
fn native_shared_artifact_uses_independent_bounded_workers() {
    let cache = NativeArtifactCache::with_compiler(clang());
    let source = contract("let mut n = 0; while n < input { n = n + 1; } return n;");
    cache.prepare(&source).unwrap();
    let gate = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        let mut callers = Vec::new();
        for _ in 0..8 {
            let cache = &cache;
            let source = &source;
            let gate = &gate;
            callers.push(scope.spawn(move || {
                gate.wait();
                cache
                    .execute_contract(source, 100_000, &ContractContext::default(), 2_000_000)
                    .unwrap()
            }));
        }
        for caller in callers {
            assert_eq!(caller.join().unwrap().value, 100_000);
        }
    });
    let stats = cache.stats();
    assert_eq!(stats.compilations, 1);
    assert_eq!(stats.executions, 8);
    assert!((2..=4).contains(&stats.workers_started));
}

#[test]
#[ignore = "requires pinned native clang 22.1.8"]
fn native_timeout_retires_worker_and_bounds_reference_verification() {
    let program = compile(&contract(
        "let mut n = 0; while n < input { n = n + 1; } return n;",
    ))
    .unwrap();
    let mut native = NativeProgram::compile(program, &clang(), Duration::from_secs(30)).unwrap();
    let start = std::time::Instant::now();
    assert!(matches!(
        native.execute(1_000_000, MAX_NATIVE_FUEL, Duration::from_millis(1)),
        Err(NativeError::ExecutionTimeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        native.execute(1, 100, Duration::from_secs(1)),
        Err(NativeError::WorkerUnavailable)
    ));
}

#[test]
#[ignore = "requires pinned native clang 22.1.8; optional ASTROLUNE_LLVM_CLANG"]
fn deterministic_traps_leave_the_native_worker_reusable() {
    let source = "fn call(input: u64) -> u64 { let unused: u64 = input + 1; return 100 / input; }";
    let mut native =
        NativeProgram::compile(compile(source).unwrap(), &clang(), Duration::from_secs(30))
            .unwrap();
    for (input, fuel, error) in [
        (10, 0, ExecutionError::FuelExhausted),
        (u64::MAX, 100, ExecutionError::Overflow),
        (0, 100, ExecutionError::DivisionByZero),
    ] {
        assert!(
            matches!(native.execute(input, fuel, Duration::from_secs(5)), Err(NativeError::Contract(actual)) if actual == error)
        );
        assert_eq!(
            native
                .execute(10, 100, Duration::from_secs(5))
                .unwrap()
                .value,
            10
        );
    }
    assert!(matches!(
        native.execute(10, 100, Duration::ZERO),
        Err(NativeError::InvalidDeadline)
    ));
    assert_eq!(
        native
            .execute(10, 100, Duration::from_secs(5))
            .unwrap()
            .value,
        10
    );
}

#[test]
#[ignore = "requires pinned native clang 22.1.8; optional ASTROLUNE_LLVM_CLANG"]
fn fuel_and_unused_expression_errors_survive_llvm_optimization() {
    let mut native = NativeProgram::compile(
        compile("fn call(input: u64) -> u64 { let x: u64 = input + 1; return x * 2; }").unwrap(),
        &clang(),
        Duration::from_secs(30),
    )
    .unwrap();
    for (fuel, error) in [
        (2, ExecutionError::FuelExhausted),
        (3, ExecutionError::Overflow),
    ] {
        assert!(
            matches!(native.execute(u64::MAX, fuel, Duration::from_secs(5)), Err(NativeError::Contract(actual)) if actual == error)
        );
    }
    let mut native = NativeProgram::compile(
        compile("fn call(input: u64) -> u64 { let unused: u64 = 1 / 0; return 42; }").unwrap(),
        &clang(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(matches!(
        native.execute(0, 100, Duration::from_secs(5)),
        Err(NativeError::Contract(ExecutionError::DivisionByZero))
    ));
}
