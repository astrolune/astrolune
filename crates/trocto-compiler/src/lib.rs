// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded Trocto source checking, reference semantics, and native LLVM IR.
//!
//! Version one accepts a single `fn call(input: u64) -> u64`, immutable local
//! bindings, decimal integers, and checked integer arithmetic. It has no pointers,
//! heap, imports, calls, loops, or floating point. The compiler generates LLVM IR
//! directly; it does not invoke a native compiler or execute producer-supplied IR.

#![forbid(unsafe_code)]

mod frontend;
mod llvm;

use std::fmt;
use types::Hash256;

/// The accepted source-language version.
pub const LANGUAGE_VERSION: u32 = 1;
/// The instruction charging and native-call ABI version.
pub const METERING_VERSION: u32 = 1;
/// Maximum source length, in UTF-8 bytes.
pub const MAX_SOURCE_BYTES: usize = 65_536;
/// Maximum lexical tokens, excluding the end marker.
pub const MAX_TOKENS: usize = 16_384;
/// Maximum straight-line instructions in one program.
pub const MAX_INSTRUCTIONS: usize = 4096;
/// Maximum parser recursion depth, including nested parentheses.
pub const MAX_NESTING: usize = 64;
/// Maximum immutable local bindings.
pub const MAX_LOCALS: usize = 1024;
/// Maximum identifier length, in ASCII bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 64;

/// Source rejection with a zero-based UTF-8 byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileError {
    /// Byte position at which the source was refused.
    pub offset: usize,
    /// Human-readable diagnostic without source contents.
    pub message: String,
}

impl CompileError {
    pub(crate) fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Trocto byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for CompileError {}

/// Deterministic execution refusal, also returned by the native ABI as 1/2/3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// The next source instruction would exceed the supplied budget.
    FuelExhausted,
    /// Addition, subtraction, or multiplication exceeds the `u64` range.
    Overflow,
    /// The divisor of division or remainder is zero.
    DivisionByZero,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FuelExhausted => "Trocto fuel exhausted",
            Self::Overflow => "Trocto integer overflow",
            Self::DivisionByZero => "Trocto division by zero",
        })
    }
}

impl std::error::Error for ExecutionError {}

/// A successful call with deterministic source-instruction charging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Execution {
    /// The returned `u64`.
    pub value: u64,
    /// One unit for each constant, input/local load, and arithmetic operation.
    pub fuel_used: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Operator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
}

impl Operator {
    fn apply(self, left: u64, right: u64) -> Result<u64, ExecutionError> {
        match self {
            Self::Add => left.checked_add(right).ok_or(ExecutionError::Overflow),
            Self::Subtract => left.checked_sub(right).ok_or(ExecutionError::Overflow),
            Self::Multiply => left.checked_mul(right).ok_or(ExecutionError::Overflow),
            Self::Divide => left
                .checked_div(right)
                .ok_or(ExecutionError::DivisionByZero),
            Self::Remainder => left
                .checked_rem(right)
                .ok_or(ExecutionError::DivisionByZero),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Instruction {
    Constant(u64),
    Input,
    Copy(usize),
    Binary {
        operator: Operator,
        left: usize,
        right: usize,
    },
}

/// An immutable, checked program. Arbitrary LLVM IR cannot construct this type.
#[derive(Clone, Debug)]
pub struct Program {
    instructions: Vec<Instruction>,
    result: usize,
    source_hash: Hash256,
    llvm: String,
}

impl Program {
    /// Content identity including language and metering version domains.
    #[must_use]
    pub const fn source_hash(&self) -> Hash256 {
        self.source_hash
    }

    /// Emits a checked native-call function for compilation by LLVM.
    ///
    /// ABI: `i32 trocto_call(i64 input, i64 fuel, ptr output, ptr used)`.
    /// It returns 0 on success, 1 on budget exhaustion, 2 on overflow, and 3
    /// on division by zero. The two aligned `u64` output pointers must be valid
    /// and non-aliasing; both are written only on success by the trusted harness.
    #[must_use]
    pub fn llvm_ir(&self) -> &str {
        &self.llvm
    }

    /// Number of source instructions charged by a successful call.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Executes independently of LLVM, preserving source error and fuel order.
    ///
    /// Every instruction, including unused local initializers, executes and costs
    /// one unit. The budget check precedes the instruction's arithmetic check.
    ///
    /// # Errors
    /// Returns a deterministic budget, arithmetic, or zero-divisor refusal.
    pub fn evaluate(&self, input: u64, fuel: u64) -> Result<Execution, ExecutionError> {
        let mut values = Vec::with_capacity(self.instructions.len());
        let mut fuel_used = 0u64;
        for instruction in &self.instructions {
            if fuel_used >= fuel {
                return Err(ExecutionError::FuelExhausted);
            }
            fuel_used += 1;
            let value = match *instruction {
                Instruction::Constant(value) => value,
                Instruction::Input => input,
                Instruction::Copy(index) => values[index],
                Instruction::Binary {
                    operator,
                    left,
                    right,
                } => operator.apply(values[left], values[right])?,
            };
            values.push(value);
        }
        Ok(Execution {
            value: values[self.result],
            fuel_used,
        })
    }
}

/// Parses and checks bounded Trocto source before generating any native IR.
///
/// # Errors
/// Rejects unsupported syntax, invalid bindings, out-of-range literals, and
/// sources exceeding any of the explicit compiler limits.
pub fn compile(source: &str) -> Result<Program, CompileError> {
    let (instructions, result) = frontend::parse(source)?;
    let llvm = llvm::generate(&instructions, result);
    Ok(Program {
        instructions,
        result,
        source_hash: types::hash::domain_hash(
            b"astrolune.trocto.source.v1.meter1",
            source.as_bytes(),
        ),
        llvm,
    })
}
