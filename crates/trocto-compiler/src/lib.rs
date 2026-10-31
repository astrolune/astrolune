// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded Trocto source checking, reference semantics, and native LLVM IR.
//!
//! Version one preserves immutable scalar arithmetic. Version two adds typed
//! `u64`/`bool` Copy scalars, mutable lexical locals, branches, bounded-fuel loops,
//! state capabilities and events. Both reject pointers, references, heap allocation,
//! imports, arbitrary calls, and floating point. The compiler generates LLVM IR
//! directly; it does not invoke a native compiler or execute producer-supplied IR.

#![forbid(unsafe_code)]

mod frontend;
mod llvm;
mod package;
mod stateful;
mod stateful_frontend;
mod stateful_llvm;

pub use package::{MAX_PACKAGE_BYTES, SourcePackage};
pub use stateful::{ContractContext, ContractExecution};

use std::fmt;
use types::Hash256;

/// The preserved scalar source-language version.
pub const LANGUAGE_VERSION: u32 = 1;
/// The instruction charging and native-call ABI version.
pub const METERING_VERSION: u32 = 1;
/// Stateful source language with typed control flow and dynamic state slots.
pub const STATEFUL_LANGUAGE_VERSION: u32 = 2;
/// Stateful dynamic charging and native contract-call ABI version.
pub const STATEFUL_METERING_VERSION: u32 = 2;
/// Maximum source length, in UTF-8 bytes.
pub const MAX_SOURCE_BYTES: usize = 65_536;
/// Maximum lexical tokens, excluding the end marker.
pub const MAX_TOKENS: usize = 16_384;
/// Maximum statically emitted instructions and value registers in one program.
pub const MAX_INSTRUCTIONS: usize = 4096;
/// Maximum parser recursion depth, including nested parentheses.
pub const MAX_NESTING: usize = 64;
/// Maximum lexical local bindings, including mutable version-two bindings.
pub const MAX_LOCALS: usize = 1024;
/// Maximum identifier length, in ASCII bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 64;
/// Maximum state slots, including static and transaction-declared keys.
pub const MAX_STATE_KEYS: usize = 1024;
/// Maximum length of one static ASCII or transaction-declared raw state key.
pub const MAX_STATE_KEY_BYTES: usize = 256;
/// Maximum events emitted by one successful call.
pub const MAX_EVENTS: usize = 256;

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

/// Deterministic execution refusal, returned by the native ABI as statuses 1..7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// The next source instruction would exceed the supplied budget.
    FuelExhausted,
    /// Addition, subtraction, or multiplication exceeds the `u64` range.
    Overflow,
    /// The divisor of division or remainder is zero.
    DivisionByZero,
    /// A host state operation used a key not authorized by this call.
    AccessDenied,
    /// The call attempted to emit more than the bounded event count.
    EventLimit,
    /// Host context shape or scalar/context requirements are invalid.
    InvalidContext,
    /// A dynamic slot is out of bounds or does not contain a 32-byte address.
    Bounds,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FuelExhausted => "Trocto fuel exhausted",
            Self::Overflow => "Trocto integer overflow",
            Self::DivisionByZero => "Trocto division by zero",
            Self::AccessDenied => "Trocto state access denied",
            Self::EventLimit => "Trocto event limit exceeded",
            Self::InvalidContext => "invalid Trocto contract context",
            Self::Bounds => "Trocto state slot bounds exceeded",
        })
    }
}

impl std::error::Error for ExecutionError {}

/// A successful call with deterministic source-instruction charging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Execution {
    /// The returned `u64`.
    pub value: u64,
    /// Dynamic constant, read, operation, assignment, and control-edge units.
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
    stateful: Option<stateful::CheckedProgram>,
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
    /// on division by zero. Contextful programs return 6 from this scalar ABI.
    /// The contract ABI additionally accepts bounded context arrays and returns
    /// 4 for denied state access, 5 for event limits, 6 for invalid context, and
    /// 7 for dynamic slot bounds. The two aligned `u64` output pointers must be valid
    /// and non-aliasing; both are written only on success by the trusted harness.
    #[must_use]
    pub fn llvm_ir(&self) -> &str {
        &self.llvm
    }

    /// Source language version actually selected by this checked program.
    #[must_use]
    pub const fn language_version(&self) -> u32 {
        if self.stateful.is_some() {
            STATEFUL_LANGUAGE_VERSION
        } else {
            LANGUAGE_VERSION
        }
    }

    /// Metering version actually selected by this checked program.
    #[must_use]
    pub const fn metering_version(&self) -> u32 {
        if self.stateful.is_some() {
            STATEFUL_METERING_VERSION
        } else {
            METERING_VERSION
        }
    }

    /// Unique statically declared state keys in canonical byte order.
    #[must_use]
    pub fn state_keys(&self) -> &[Vec<u8>] {
        self.stateful
            .as_ref()
            .map_or(&[], |program| program.keys.as_slice())
    }

    /// Whether this program requires explicit host context.
    #[must_use]
    pub fn requires_context(&self) -> bool {
        self.stateful
            .as_ref()
            .is_some_and(|program| program.context)
    }

    /// Executes with private state writes and events, returned only on success.
    ///
    /// # Errors
    /// Refuses invalid contexts, denied keys, event overflow, arithmetic failure,
    /// or exhausted dynamic instruction fuel.
    pub fn evaluate_contract(
        &self,
        input: u64,
        context: &ContractContext,
        fuel: u64,
    ) -> Result<ContractExecution, ExecutionError> {
        if let Some(program) = &self.stateful {
            return program.evaluate(input, context, fuel);
        }
        context.validate(&[])?;
        let output = self.evaluate(input, fuel)?;
        Ok(ContractExecution {
            value: output.value,
            fuel_used: output.fuel_used,
            state: context.state.clone(),
            writes: vec![false; context.keys.len()],
            events: Vec::new(),
        })
    }

    /// Evaluates privately, polling local cancellation every 1,024 dispatches.
    /// `Ok(None)` means local interruption and is not a consensus execution error.
    ///
    /// # Errors
    /// Returns the same deterministic refusals as `evaluate_contract`.
    pub fn evaluate_contract_with_interrupt(
        &self,
        input: u64,
        context: &ContractContext,
        fuel: u64,
        mut interrupt: impl FnMut() -> bool,
    ) -> Result<Option<ContractExecution>, ExecutionError> {
        if let Some(program) = &self.stateful {
            return program.evaluate_with_interrupt(input, context, fuel, interrupt);
        }
        context.validate(&[])?;
        if interrupt() {
            return Ok(None);
        }
        let result = self.evaluate_contract(input, context, fuel)?;
        if interrupt() {
            return Ok(None);
        }
        Ok(Some(result))
    }

    /// Number of statically emitted instructions.
    /// This equals successful fuel for version one; version two includes uncharged
    /// bookkeeping and may revisit instructions through dynamically charged loops.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.stateful
            .as_ref()
            .map_or(self.instructions.len(), |program| {
                program.instructions.len()
            })
    }

    /// Executes independently of LLVM, preserving source error and fuel order.
    ///
    /// Constants, reads, operations, assignments and control edges cost one unit;
    /// initializer stores, internal moves and returns are uncharged. Unused local
    /// initializers still execute. Fuel checks precede operation errors.
    ///
    /// # Errors
    /// Returns a deterministic budget, arithmetic, or zero-divisor refusal.
    pub fn evaluate(&self, input: u64, fuel: u64) -> Result<Execution, ExecutionError> {
        if let Some(program) = &self.stateful {
            if program.context {
                return Err(ExecutionError::InvalidContext);
            }
            let execution = program.evaluate(input, &ContractContext::default(), fuel)?;
            return Ok(Execution {
                value: execution.value,
                fuel_used: execution.fuel_used,
            });
        }
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
    if let Ok((instructions, result)) = frontend::parse(source) {
        let llvm = llvm::generate(&instructions, result);
        return Ok(Program {
            instructions,
            result,
            source_hash: types::hash::domain_hash(
                b"astrolune.trocto.source.v1.meter1",
                source.as_bytes(),
            ),
            llvm,
            stateful: None,
        });
    }
    let program = stateful_frontend::parse(source)?;
    let llvm = stateful_llvm::generate(&program);
    Ok(Program {
        instructions: Vec::new(),
        result: 0,
        source_hash: types::hash::domain_hash(
            b"astrolune.trocto.source.v2.meter2",
            source.as_bytes(),
        ),
        llvm,
        stateful: Some(program),
    })
}
