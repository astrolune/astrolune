// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Legacy ABI-v1 demonstration backend. Live contracts use `WasmRuntime`.

use crate::error::RuntimeError;
use crate::version::{ContractModule, RuntimeOutput};
use types::Resources;

/// Local execution backend class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    /// Portable reference semantics.
    Interpreter,
    /// Translation completed before any call budget exists, then reused.
    ///
    /// Reported by [`crate::AotBackend`] only, and asserted never to be
    /// reported by an interpreter profile. It states when translation happened
    /// and nothing about native code generation; no backend in this workspace
    /// emits native machine code.
    Aot,
    /// Reserved just-in-time class; no implementation is provided, and none is
    /// possible while `unsafe_code` is forbidden workspace-wide.
    Jit,
}

/// Legacy ABI-v1 demonstration interface, without stateful WASM host semantics.
/// Live ABI-v2 calls use [`crate::WasmRuntime::execute_call`].
pub trait RuntimeBackend: Send + Sync {
    /// Identifies the local backend class.
    fn kind(&self) -> BackendKind;

    /// Executes one call. Optimized backends must match the interpreter.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for deterministic traps and resource exhaustion.
    fn execute(&self, module: &ContractModule, input: &[u8])
    -> Result<RuntimeOutput, RuntimeError>;
}

/// Demonstration byte transformation; does not interpret WebAssembly.
pub struct DemoByteTransformBackend {
    /// Maximum allowed input size in bytes.
    max_input: usize,
    /// Maximum allowed output size in bytes.
    max_output: usize,
}

/// Compatibility name for the ABI-v1 demonstration byte transformation.
/// Use [`crate::WasmRuntime`] for the active contract profile.
pub type InterpreterBackend = DemoByteTransformBackend;

impl DemoByteTransformBackend {
    /// Creates a demonstration backend with the given size limits.
    #[must_use]
    pub fn new(max_input: usize, max_output: usize) -> Self {
        Self {
            max_input,
            max_output,
        }
    }
}

impl RuntimeBackend for DemoByteTransformBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Interpreter
    }

    fn execute(
        &self,
        module: &ContractModule,
        input: &[u8],
    ) -> Result<RuntimeOutput, RuntimeError> {
        if input.len() > self.max_input {
            return Err(RuntimeError::LimitExceeded);
        }

        let code_len = module.code.len();
        if code_len == 0 {
            return Err(RuntimeError::Trap);
        }

        let mut output = Vec::with_capacity(input.len());
        for (i, &byte) in input.iter().enumerate() {
            let key = module.code[i % code_len];
            output.push(byte ^ key);
        }

        if output.len() > self.max_output {
            return Err(RuntimeError::LimitExceeded);
        }

        let input_len = input.len() as u64;
        let resources = Resources {
            compute: input_len.saturating_mul(10),
            memory: input_len,
            io: input_len.saturating_mul(2),
            bandwidth: input_len,
        };

        Ok(RuntimeOutput {
            return_data: output,
            resources,
        })
    }
}
