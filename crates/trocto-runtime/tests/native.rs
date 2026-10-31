// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Real native LLVM compilation, persistent IPC and reference equivalence.

use std::{path::PathBuf, time::Duration};

use trocto_compiler::{ExecutionError, compile};
use trocto_runtime::{LLVM_VERSION, NativeError, NativeProgram};

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
            for fuel in [0, 1, 2, 3, 4, 5, 6, 7, 8, u64::MAX] {
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
