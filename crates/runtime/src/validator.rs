// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Module validation: traits and concrete validators that enforce deployment
//! invariants before code enters the runtime.

use crate::error::RuntimeError;
use crate::version::{ContractModule, DEFAULT_VERSION, RuntimeVersion};
use types::Hash256;

/// Validates a canonical contract module before deployment.
pub trait ModuleValidator {
    /// Validates target features, imports, control flow, memory, and metering.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the module is malformed, unsupported, or
    /// exceeds configured limits.
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError>;
}

/// ABI-v1 demonstration size/version checks, without WebAssembly validation.
/// Live deployments must use [`crate::WasmRuntime`].
pub struct DemoModuleValidator {
    /// Maximum allowed module code size in bytes.
    max_size: usize,
}

/// Compatibility name for the ABI-v1 demonstration validator.
pub type BasicModuleValidator = DemoModuleValidator;

impl DemoModuleValidator {
    /// Creates a new validator with the given maximum module size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl ModuleValidator for DemoModuleValidator {
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError> {
        if version != DEFAULT_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidModule);
        }
        if bytes.len() > self.max_size {
            return Err(RuntimeError::LimitExceeded);
        }
        let code_hash = compute_hash(bytes);
        Ok(ContractModule {
            code_hash,
            version,
            code: bytes.to_vec(),
        })
    }
}

/// Computes a deterministic 32-byte hash from input bytes.
pub(crate) fn compute_hash(data: &[u8]) -> Hash256 {
    let mut state = [0x6a09_e667_u32; 8];
    for (i, &byte) in data.iter().enumerate() {
        let word_idx = i % 8;
        #[allow(clippy::cast_possible_truncation)] // index is bounded by data length
        let idx = i as u32;
        state[word_idx] = state[word_idx]
            .wrapping_mul(0x9e37_79b9)
            .wrapping_add(u32::from(byte))
            .wrapping_add(idx);
    }
    let mut result = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Hash256(result)
}
