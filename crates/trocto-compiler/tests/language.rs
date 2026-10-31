// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Independent arithmetic, source safety, charging, and bounded-input checks.

use trocto_compiler::{
    Execution, ExecutionError, MAX_IDENTIFIER_BYTES, MAX_INSTRUCTIONS, MAX_LOCALS, MAX_NESTING,
    MAX_SOURCE_BYTES, MAX_TOKENS, compile,
};

fn expression(value: &str) -> String {
    format!("fn call(input: u64) -> u64 {{ return {value}; }}")
}

#[test]
fn precedence_left_associativity_and_immutable_bindings() {
    let program = compile(
        "// Integer arithmetic, with an immutable intermediate.\n\
         fn call(input: u64) -> u64 {\n\
         let scaled: u64 = input * 3;\n\
         let adjusted = scaled + 11 / 2;\n\
         return adjusted % 17 + 20 - 3 - 2;\n\
         }",
    )
    .unwrap();
    for input in 0..100 {
        let expected = (input * 3 + 11 / 2) % 17 + 20 - 3 - 2;
        assert_eq!(
            program.evaluate(input, u64::MAX),
            Ok(Execution {
                value: expected,
                fuel_used: u64::try_from(program.instruction_count()).unwrap(),
            })
        );
    }
    assert_eq!(
        compile(&expression("20 / 3 / 2"))
            .unwrap()
            .evaluate(0, 5)
            .unwrap()
            .value,
        3
    );
    assert_eq!(
        compile(&expression("20 - (3 - 2)"))
            .unwrap()
            .evaluate(0, 5)
            .unwrap()
            .value,
        19
    );
}

#[test]
fn literal_extremes_and_every_checked_operator() {
    let maximum = compile(&expression("18446744073709551615")).unwrap();
    assert_eq!(maximum.evaluate(0, 1).unwrap().value, u64::MAX);
    assert!(compile(&expression("18446744073709551616")).is_err());
    for (operation, left, right) in [("+", u64::MAX, 1), ("-", 0, 1), ("*", u64::MAX, 2)] {
        let program = compile(&expression(&format!("{left} {operation} {right}"))).unwrap();
        assert_eq!(program.evaluate(0, 3), Err(ExecutionError::Overflow));
    }
    for operation in ["/", "%"] {
        let program = compile(&expression(&format!("input {operation} 0"))).unwrap();
        assert_eq!(
            program.evaluate(u64::MAX, 3),
            Err(ExecutionError::DivisionByZero)
        );
        let program = compile(&expression(&format!("input {operation} 1"))).unwrap();
        let expected = if operation == "/" { u64::MAX } else { 0 };
        assert_eq!(program.evaluate(u64::MAX, 3).unwrap().value, expected);
    }
}

#[test]
fn fuel_and_arithmetic_errors_keep_source_order() {
    let program =
        compile("fn call(input: u64) -> u64 { let x = input + 1; return x * 2; }").unwrap();
    assert_eq!(program.instruction_count(), 6);
    for fuel in 0..6 {
        assert_eq!(
            program.evaluate(10, fuel),
            Err(ExecutionError::FuelExhausted)
        );
    }
    assert_eq!(
        program.evaluate(10, 6),
        Ok(Execution {
            value: 22,
            fuel_used: 6
        })
    );
    // Fuel is checked before the arithmetic of the same instruction.
    assert_eq!(
        program.evaluate(u64::MAX, 2),
        Err(ExecutionError::FuelExhausted)
    );
    assert_eq!(program.evaluate(u64::MAX, 3), Err(ExecutionError::Overflow));
    let left_first = compile(&expression("(18446744073709551615 + 1) / (1 - 1)")).unwrap();
    assert_eq!(left_first.evaluate(0, 100), Err(ExecutionError::Overflow));
    let unused = compile("fn call(input: u64) -> u64 { let unused = 1 / 0; return 42; }").unwrap();
    assert_eq!(unused.evaluate(0, 100), Err(ExecutionError::DivisionByZero));
}

#[test]
fn unsupported_authority_types_and_binding_errors_are_refused() {
    for source in [
        "",
        "fn call() -> u64 { return 0; }",
        "fn call(input: i64) -> u64 { return 0; }",
        "fn call(input: u64) -> f64 { return 0; }",
        "fn call(input: u64) -> u64 { return 1.0; }",
        "fn call(input: u64) -> u64 { return -1; }",
        "fn call(input: u64) -> u64 { return missing; }",
        "fn call(input: u64) -> u64 { let x = x; return x; }",
        "fn call(input: u64) -> u64 { let x = 1; let x = 2; return x; }",
        "fn call(input: u64) -> u64 { let input = 1; return input; }",
        "fn call(input: u64) -> u64 { let x: bool = 1; return x; }",
        "fn call(input: u64) -> u64 { let mut x: f64 = 1; return x; }",
        "fn call(input: u64) -> u64 { let x = 1; x = 2; return x; }",
        "fn call(input: u64) -> u64 { return unsafe { 1 }; }",
        "fn call(input: u64) -> u64 { return input(); }",
        "fn call(input: u64) -> u64 { return *input; }",
        "fn call(input: u64) -> u64 { return &input; }",
        "fn call(input: u64) -> u64 { while input { } return 0; }",
        "fn call(input: u64) -> u64 { return 0; return 1; }",
        "fn call(input: u64) -> u64 { return 0; } fn other() {}",
        "extern fn call(input: u64) -> u64 { return input; }",
        "import filesystem; fn call(input: u64) -> u64 { return input; }",
        "fn call(input: u64) -> u64 { return input }",
    ] {
        assert!(compile(source).is_err(), "accepted {source}");
    }
}

#[test]
fn all_explicit_input_limits_are_enforced() {
    let source = " ".repeat(MAX_SOURCE_BYTES + 1);
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("source byte limit")
    );
    let source = expression(&format!(
        "{}0{}",
        "(".repeat(MAX_NESTING + 1),
        ")".repeat(MAX_NESTING + 1)
    ));
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("nesting limit")
    );
    let source = expression(&"+ ".repeat(MAX_TOKENS + 1));
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("token limit")
    );
    let source = expression(&"x".repeat(MAX_IDENTIFIER_BYTES + 1));
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("identifier byte limit")
    );
    let mut source = String::from("fn call(input: u64) -> u64 {");
    for index in 0..=MAX_LOCALS {
        use std::fmt::Write;
        write!(source, "let x{index} = 0;").unwrap();
    }
    source.push_str("return 0; }");
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("local binding limit")
    );
    // This left-associative chain exercises the instruction cap without a deep AST.
    let source = expression(
        &std::iter::repeat_n("1", MAX_INSTRUCTIONS / 2 + 1)
            .collect::<Vec<_>>()
            .join("+"),
    );
    assert!(
        compile(&source)
            .unwrap_err()
            .message
            .contains("instruction limit")
    );
}

#[test]
fn identities_and_ir_are_deterministic_and_malformed_bytes_do_not_panic() {
    let source = expression("input + 7");
    let first = compile(&source).unwrap();
    let second = compile(&source).unwrap();
    assert_eq!(first.source_hash(), second.source_hash());
    assert_eq!(first.llvm_ir(), second.llvm_ir());
    assert_ne!(
        first.source_hash(),
        compile(&(source.clone() + "\n")).unwrap().source_hash()
    );
    assert_eq!(first.clone().evaluate(5, 3), first.evaluate(5, 3));
    for index in 0..source.len() {
        for byte in 0..=127 {
            let mut changed = source.as_bytes().to_vec();
            changed[index] = byte;
            let changed = String::from_utf8(changed).unwrap();
            let _ = compile(&changed);
        }
    }
    assert!(compile(&expression("á")).is_err());
    assert!(compile(&(source + " // comments may contain Unicode: ✓")).is_ok());
}
