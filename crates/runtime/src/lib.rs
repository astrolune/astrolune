// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic Rust smart-contract module and compiler boundaries.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod validator;
mod version;
mod wasm;

pub use backend::*;
pub use error::*;
pub use validator::*;
pub use version::*;
pub use wasm::*;

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Hash256, Resources};

    fn test_module() -> Vec<u8> {
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    }

    fn test_version() -> RuntimeVersion {
        DEFAULT_VERSION
    }

    #[test]
    fn runtime_error_display() {
        assert_eq!(RuntimeError::InvalidModule.to_string(), "invalid module");
        assert_eq!(
            RuntimeError::Unsupported.to_string(),
            "unsupported feature or version"
        );
        assert_eq!(RuntimeError::LimitExceeded.to_string(), "limit exceeded");
        assert_eq!(RuntimeError::Trap.to_string(), "deterministic trap");
    }

    #[test]
    fn runtime_error_is_std_error() {
        let err: &dyn std::error::Error = &RuntimeError::Trap;
        assert!(err.source().is_none());
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(MAX_MODULE_SIZE, 1024 * 1024);
        assert_eq!(MAX_INPUT_SIZE, 256 * 1024);
        assert_eq!(MAX_OUTPUT_SIZE, 256 * 1024);
        assert_eq!(DEFAULT_VERSION.abi, 1);
        assert_eq!(DEFAULT_VERSION.metering, 1);
    }

    #[test]
    fn valid_module_accepted() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let result = validator.validate(&code, test_version());
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.version, test_version());
        assert_eq!(module.code, code);
        assert_eq!(module.code_hash, compute_hash(&code));
    }

    #[test]
    fn empty_module_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let result = validator.validate(&[], test_version());
        assert_eq!(result.unwrap_err(), RuntimeError::InvalidModule);
    }

    #[test]
    fn oversized_module_rejected() {
        let validator = BasicModuleValidator::new(10);
        let code = vec![0xAA; 11];
        let result = validator.validate(&code, test_version());
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn wrong_version_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let version = RuntimeVersion {
            abi: 99,
            metering: 1,
        };
        let result = validator.validate(&code, version);
        assert_eq!(result.unwrap_err(), RuntimeError::Unsupported);
    }

    #[test]
    fn wrong_metering_version_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let version = RuntimeVersion {
            abi: 1,
            metering: 99,
        };
        let result = validator.validate(&code, version);
        assert_eq!(result.unwrap_err(), RuntimeError::Unsupported);
    }

    #[test]
    fn code_hash_is_deterministic() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let m1 = validator.validate(&code, test_version()).unwrap();
        let m2 = validator.validate(&code, test_version()).unwrap();
        assert_eq!(m1.code_hash, m2.code_hash);
    }

    #[test]
    fn different_code_different_hash() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let m1 = validator.validate(&[0xAA], test_version()).unwrap();
        let m2 = validator.validate(&[0xBB], test_version()).unwrap();
        assert_ne!(m1.code_hash, m2.code_hash);
    }

    #[test]
    fn size_limit_at_boundary() {
        let validator = BasicModuleValidator::new(4);
        assert!(validator.validate(&[0; 4], test_version()).is_ok());
        assert_eq!(
            validator.validate(&[0; 5], test_version()).unwrap_err(),
            RuntimeError::LimitExceeded
        );
    }

    #[test]
    fn interpreter_kind() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        assert_eq!(backend.kind(), BackendKind::Interpreter);
    }

    #[test]
    fn interpreter_execute_basic() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01, 0x02, 0x03], test_version())
            .unwrap();
        let input = [0x04, 0x05, 0x06];
        let output = backend.execute(&module, &input).unwrap();
        assert_eq!(
            output.return_data,
            vec![0x04 ^ 0x01, 0x05 ^ 0x02, 0x06 ^ 0x03]
        );
    }

    #[test]
    fn interpreter_xor_wraps_at_code_length() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0xFF], test_version())
            .unwrap();
        let input = [0x01, 0x02, 0x03];
        let output = backend.execute(&module, &input).unwrap();
        assert_eq!(
            output.return_data,
            vec![0x01 ^ 0xFF, 0x02 ^ 0xFF, 0x03 ^ 0xFF]
        );
    }

    #[test]
    fn interpreter_empty_input() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0xAA], test_version())
            .unwrap();
        let output = backend.execute(&module, &[]).unwrap();
        assert_eq!(output.return_data, Vec::<u8>::new());
    }

    #[test]
    fn interpreter_empty_module_trap() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = ContractModule {
            code_hash: Hash256::ZERO,
            version: test_version(),
            code: vec![],
        };
        let result = backend.execute(&module, &[0x01]);
        assert_eq!(result.unwrap_err(), RuntimeError::Trap);
    }

    #[test]
    fn interpreter_input_size_limit() {
        let backend = InterpreterBackend::new(3, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 4];
        let result = backend.execute(&module, &input);
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn interpreter_output_size_limit() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, 2);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 3];
        let result = backend.execute(&module, &input);
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn interpreter_resource_metering() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 10];
        let output = backend.execute(&module, &input).unwrap();
        assert_eq!(output.resources.compute, 100);
        assert_eq!(output.resources.memory, 10);
        assert_eq!(output.resources.io, 20);
        assert_eq!(output.resources.bandwidth, 10);
    }

    #[test]
    fn interpreter_resource_metering_empty() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let output = backend.execute(&module, &[]).unwrap();
        assert_eq!(output.resources, Resources::ZERO);
    }

    #[test]
    fn roundtrip_validate_and_execute() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);

        let code = vec![0x10, 0x20, 0x30];
        let module = validator.validate(&code, test_version()).unwrap();
        let input = vec![0x10, 0x20, 0x30];
        let output = backend.execute(&module, &input).unwrap();

        assert_eq!(output.return_data, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn interpreter_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InterpreterBackend>();
    }
}
