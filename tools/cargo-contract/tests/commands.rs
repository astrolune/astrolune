// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Actual CLI validation, execution, and commitment checking.

use std::{
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cargo-contract"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn validates_executes_and_rejects_wrong_commitment_or_unsupported_commands() {
    let path = std::env::temp_dir().join(format!("astrolune-contract-cli-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);

    let code = wat::parse_str(
        r#"(module
        (import "astrolune_v2" "output" (func $out (param i32 i32) (result i32)))
        (memory (export "memory") 1 2) (data (i32.const 0) "hi")
        (func (export "call") (result i32) i32.const 0 i32.const 2 call $out))"#,
    )
    .unwrap();
    std::fs::write(fixture.0.join("contract.wasm"), &code).unwrap();

    let result = fixture.run(&["contract", "validate", "contract.wasm"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let expected = runtime::wasm_code_hash(&code).to_string();
    assert!(String::from_utf8_lossy(&result.stdout).contains(&expected));

    let result = fixture.run(&["test", "contract.wasm"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("return_data: 6869"));

    assert!(
        fixture
            .run(&["verify", "contract.wasm", &expected])
            .status
            .success()
    );
    assert!(
        !fixture
            .run(&["verify", "contract.wasm", &"0".repeat(64)])
            .status
            .success()
    );
    assert!(!fixture.run(&["verify", "contract.wasm"]).status.success());
    assert!(!fixture.run(&["deploy"]).status.success());

    std::fs::write(fixture.0.join("contract.wasm"), b"bad module").unwrap();
    assert!(!fixture.run(&["validate", "contract.wasm"]).status.success());

    // The build command must not replace an existing artifact, even on failure.
    std::fs::write(fixture.0.join("source.rs"), b"invalid rust").unwrap();
    assert!(
        !fixture
            .run(&["build", "source.rs", "contract.wasm"])
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(fixture.0.join("contract.wasm")).unwrap(),
        b"bad module"
    );
}

#[test]
#[ignore = "requires Rust 1.99.0 wasm32-unknown-unknown libraries; optional ASTROLUNE_CONTRACT_SYSROOT"]
fn pinned_rust_build_is_repeatable_and_executable() {
    let path = std::env::temp_dir().join(format!(
        "astrolune-contract-build-test-{}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);

    std::fs::write(
        fixture.0.join("contract.rs"),
        r#"
        #![no_std]
        #[panic_handler]
        fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }
        #[unsafe(export_name = "call")]
        pub extern "C" fn contract_call() -> i32 { 0 }
    "#,
    )
    .unwrap();

    let result = fixture.run(&["build", "contract.rs", "one.wasm"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("repeated_build: identical"));

    // Neither a shadow compiler in PATH nor the source directory's toolchain
    // override may replace the compiler committed by the contract profile.
    std::fs::write(
        fixture.0.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"unavailable-contract-test\"\n",
    )
    .unwrap();

    let shadow = fixture.0.join("shadow-bin");
    std::fs::create_dir(&shadow).unwrap();
    let fake = shadow.join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
    std::fs::write(&fake, b"this is not a compiler").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut paths = vec![shadow];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));

    let second = Command::new(env!("CARGO_BIN_EXE_cargo-contract"))
        .current_dir(&fixture.0)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("RUSTUP_TOOLCHAIN", "unavailable-contract-test")
        .args(["build", "contract.rs", "two.wasm"])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert_eq!(
        std::fs::read(fixture.0.join("one.wasm")).unwrap(),
        std::fs::read(fixture.0.join("two.wasm")).unwrap()
    );
    assert!(fixture.run(&["test", "one.wasm"]).status.success());
}

#[test]
#[ignore = "requires Rust 1.99.0 wasm32 libraries; optional ASTROLUNE_CONTRACT_SYSROOT"]
fn sdk_bindings_execute_all_host_calls_in_the_reference_interpreter() {
    use runtime::{ModuleValidator, WASM_VERSION, WasmCall, WasmRuntime};
    use std::collections::{BTreeMap, BTreeSet};

    let path = std::env::temp_dir().join(format!("astrolune-sdk-test-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);

    std::fs::write(fixture.0.join("sdk.rs"), r#"
        #![no_std]
        use contract_sdk::{Guest, AbiError};
        #[panic_handler] fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }
        fn run() -> Result<(), AbiError> {
            if Guest::input_len()? != 2 { return Err(AbiError::Host); }
            let mut value = [0];
            if Guest::input_copy(usize::MAX, &mut value) != Err(AbiError::Length) { return Err(AbiError::Host); }
            Guest::input_copy(1, &mut value)?;
            Guest::state_put(b"k", &[])?;
            let mut read = [0];
            if Guest::state_get(b"k", &mut read)? != Some(0) { return Err(AbiError::Host); }
            Guest::state_delete(b"k")?;
            if Guest::state_get(b"k", &mut read)? != None { return Err(AbiError::Host); }
            Guest::state_put(b"k", &value)?;
            if Guest::state_get(b"k", &mut read)? != Some(1) || read != value { return Err(AbiError::Host); }
            let caller = Guest::caller()?;
            Guest::emit(&caller, &read)?;
            let mut output = [0; 10]; output[0] = value[0]; output[1] = caller[0];
            output[2..].copy_from_slice(&Guest::block_height().to_le_bytes());
            Guest::output(&output)
        }
        #[unsafe(export_name = "call")]
        pub extern "C" fn contract_call() -> i32 { match run() { Ok(()) => 0, Err(_) => 1 } }
    "#).unwrap();

    let result = fixture.run(&["build", "sdk.rs", "sdk.wasm"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let bytes = std::fs::read(fixture.0.join("sdk.wasm")).unwrap();
    let runtime = WasmRuntime::new();
    let module = runtime.validate(&bytes, WASM_VERSION).unwrap();

    let height = (1u64 << 63) + 7;
    let output = runtime
        .execute_call(
            &module,
            WasmCall {
                input: &[0, 42],
                caller: types::Address([7; 32]),
                height,
                state: &BTreeMap::new(),
                access: &BTreeSet::from([b"k".to_vec()]),
                limits: types::Resources {
                    compute: 1_000_000,
                    memory: 1_000_000,
                    io: 1_000_000,
                    bandwidth: 100_000,
                },
            },
        )
        .unwrap();

    let mut expected = vec![42, 7];
    expected.extend_from_slice(&height.to_le_bytes());
    assert_eq!(output.return_data, expected);
    assert_eq!(
        output.writes,
        BTreeMap::from([(b"k".to_vec(), Some(vec![42]))])
    );
    assert_eq!(output.events, vec![([7; 32], vec![42])]);
}

#[test]
#[ignore = "requires Rust 1.99.0 wasm32 libraries; optional ASTROLUNE_CONTRACT_SYSROOT"]
fn registry_wasm_enforces_ownership_expiry_and_matches_the_native_transition() {
    use contract_sdk::registry::{self, RegistryCall};
    use runtime::{ModuleValidator, WASM_VERSION, WasmCall, WasmRuntime};
    use std::collections::{BTreeMap, BTreeSet};

    let path = std::env::temp_dir().join(format!("astrolune-registry-wasm-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);

    std::fs::write(
        fixture.0.join("registry.rs"),
        include_str!("../../../examples/contracts/name_registry.rs"),
    )
    .unwrap();

    let built = fixture.run(&["build", "registry.rs", "registry.wasm"]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );

    let bytes = std::fs::read(fixture.0.join("registry.wasm")).unwrap();
    assert!(
        bytes.len() <= 60 * 1024,
        "fits the signed deployment network limit"
    );

    let runtime = WasmRuntime::new();
    let module = runtime.validate(&bytes, WASM_VERSION).unwrap();

    let key = b"dns/v1/alice".to_vec();
    let access = BTreeSet::from([key.clone()]);
    let mut state = BTreeMap::new();

    for (action, caller, height) in registry_actions() {
        let call = RegistryCall {
            name: b"alice",
            action,
        };

        let mut input = [0; registry::MAX_CALL];
        let size = call.encode(&mut input).unwrap();

        let mut expected = [0; registry::MAX_LEASE];
        let reference = registry::transition(
            call,
            state.get(&key).map(Vec::as_slice),
            [caller; 32],
            height,
            &mut expected,
        );

        let result = runtime.execute_call(
            &module,
            WasmCall {
                input: &input[..size],
                caller: types::Address([caller; 32]),
                height,
                state: &state,
                access: &access,
                limits: types::Resources {
                    compute: 1_000_000,
                    memory: 4_000_000,
                    io: 1_000_000,
                    bandwidth: 100_000,
                },
            },
        );

        match reference {
            Err(_) => assert!(result.is_err()),
            Ok(length) => {
                let result = result.unwrap();
                let value = length.map(|length| expected[..length].to_vec());
                assert_eq!(
                    result.writes,
                    BTreeMap::from([(key.clone(), value.clone())])
                );

                if let Some(value) = value {
                    state.insert(key.clone(), value);
                } else {
                    state.remove(&key);
                }
            }
        }
    }

    assert!(state.is_empty());
}

fn registry_actions() -> [(contract_sdk::registry::RegistryAction<'static>, u8, u64); 9] {
    use contract_sdk::registry::{RegistryAction, RegistryRecord};

    [
        (
            RegistryAction::Register(
                10,
                RegistryRecord {
                    kind: 0,
                    value: &[9; 32],
                },
            ),
            1,
            1,
        ),
        (
            RegistryAction::Update(RegistryRecord {
                kind: 1,
                value: b"service",
            }),
            2,
            2,
        ),
        (RegistryAction::Renew(10), 1, 2),
        (RegistryAction::Transfer([2; 32]), 1, 3),
        (RegistryAction::Release, 1, 4),
        (
            RegistryAction::Update(RegistryRecord {
                kind: 1,
                value: b"service",
            }),
            2,
            4,
        ),
        (RegistryAction::Release, 2, 21),
        (
            RegistryAction::Register(
                10,
                RegistryRecord {
                    kind: 0,
                    value: &[7; 32],
                },
            ),
            3,
            21,
        ),
        (RegistryAction::Release, 3, 22),
    ]
}

#[test]
#[ignore = "requires Rust 1.99.0 wasm32 libraries; optional ASTROLUNE_CONTRACT_SYSROOT"]
fn multi_file_source_package_rebuilds_independently_and_detects_wrong_artifacts() {
    let path =
        std::env::temp_dir().join(format!("astrolune-source-package-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);

    assert!(fixture.run(&["init", "source"]).status.success());
    assert!(!fixture.run(&["init", "source"]).status.success());

    std::fs::write(fixture.0.join("source/src/lib.rs"), r#"
        #![no_std]
        mod helper;
        #[panic_handler] fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }
        #[unsafe(export_name="call")]
        pub extern "C" fn call() -> i32 { contract_sdk::Guest::output(helper::value().as_bytes()).map_or(1, |()| 0) }
    "#).unwrap();

    std::fs::write(
        fixture.0.join("source/src/helper.rs"),
        "pub fn value() -> &'static str { file!() }",
    )
    .unwrap();

    for directory in ["build-a", "build-b"] {
        let result = fixture.run(&["build-package", "source", directory]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    assert_eq!(
        std::fs::read(fixture.0.join("build-a/contract.wasm")).unwrap(),
        std::fs::read(fixture.0.join("build-b/contract.wasm")).unwrap()
    );
    assert_eq!(
        std::fs::read(fixture.0.join("build-a/source.alpkg")).unwrap(),
        std::fs::read(fixture.0.join("build-b/source.alpkg")).unwrap()
    );

    let verified = fixture.run(&[
        "verify-source",
        "build-a/source.alpkg",
        "build-a/contract.wasm",
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    std::fs::write(fixture.0.join("wrong.wasm"), b"incorrect artifact").unwrap();
    assert!(
        !fixture
            .run(&["verify-source", "build-a/source.alpkg", "wrong.wasm"])
            .status
            .success()
    );
    assert!(
        !fixture
            .run(&["build-package", "source", "build-a"])
            .status
            .success()
    );

    std::fs::write(
        fixture.0.join("source/src/helper.rs"),
        "pub fn value() -> &'static str { include_str!(\"../../outside\") }",
    )
    .unwrap();
    assert!(
        !fixture
            .run(&["package", "source", "bad.alpkg"])
            .status
            .success()
    );
    assert!(!fixture.0.join("bad.alpkg").exists());
}