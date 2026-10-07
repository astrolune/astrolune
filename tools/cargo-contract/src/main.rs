// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Validates, builds, and runs bounded WebAssembly contract artifacts.

#![forbid(unsafe_code)]

mod package;
mod package_policy;
mod sdk;

use runtime::{ModuleValidator, WASM_VERSION, WasmCall, WasmRuntime};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use types::{Address, Resources};

const HELP: &str = "AstroLune contract tools\n\nUsage: cargo contract <command>\n\nCommands:\n  init <new-directory>  Create a restricted Cargo contract package\n  package <directory> <source.alpkg>  Bundle bounded source files and SDK identity\n  build-package <directory> <new-output-directory>  Build a package and save its sources and commitments\n  verify-source <source.alpkg> <module.wasm>  Rebuild published sources and compare exact artifact bytes\n  build <source.rs> <output.wasm>  Build a standalone no_std Rust contract twice and compare bytes\n  validate <module.wasm>  Check the integer-only ABI v2 and print its commitment\n  test <module.wasm> [input-file]  Execute with empty state and bounded resources\n  verify <module.wasm> <code-hash>  Validate and compare an expected code commitment\n\nBuild requires Rust 1.99.0 and its wasm32-unknown-unknown standard library.\nThe source must export memory and call() -> i32 using the astrolune_v2 ABI.\nUse cli sign-deploy/sign-call/submit on a genesis runtime_version 2 network.\n";

fn main() {
    if let Err(error) = run(std::env::args_os().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;

    if bytes.len() > maximum {
        return Err("input exceeds its byte limit".into());
    }

    Ok(bytes)
}

fn run(mut args: Vec<OsString>) -> Result<(), String> {
    if args.first().is_some_and(|value| value == "contract") {
        args.remove(0);
    }

    let command = args
        .first()
        .and_then(|value| value.to_str())
        .unwrap_or("--help");
    let runtime = WasmRuntime::new();

    match (command, &args[args.len().min(1)..]) {
        ("--help" | "-h", []) => {
            print!("{HELP}");
            Ok(())
        }
        ("--version" | "-V", []) => {
            println!("cargo-contract {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        (command @ ("init" | "package" | "build-package" | "verify-source"), args) => {
            package::run(command, args)
        }
        ("build", [source, output]) => build(Path::new(source), Path::new(output), &runtime),
        ("validate" | "test" | "verify", [path, rest @ ..]) => {
            if (command == "verify" && rest.len() != 1)
                || (command == "validate" && !rest.is_empty())
                || rest.len() > 1
            {
                return Err("invalid command arguments; use --help".into());
            }

            let bytes = read(Path::new(path), runtime::MAX_MODULE_SIZE)?;
            let module = runtime
                .validate(&bytes, WASM_VERSION)
                .map_err(|e| e.to_string())?;

            if command == "verify"
                && rest[0].to_str() != Some(module.code_hash.to_string().as_str())
            {
                return Err("contract code commitment mismatch".into());
            }

            println!("code_hash: {}", module.code_hash);
            println!("runtime: wasm-abi2-meter1");

            if command == "test" {
                let input = rest
                    .first()
                    .map(|path| read(Path::new(path), runtime::MAX_INPUT_SIZE))
                    .transpose()?
                    .unwrap_or_default();
                let output = runtime
                    .execute_call(
                        &module,
                        WasmCall {
                            input: &input,
                            caller: Address::ZERO,
                            height: 1,
                            state: &BTreeMap::new(),
                            access: &BTreeSet::new(),
                            limits: Resources {
                                compute: 1_000_000,
                                memory: runtime::MAX_WASM_MEMORY as u64,
                                io: runtime::MAX_HOST_IO,
                                bandwidth: runtime::MAX_OUTPUT_SIZE as u64,
                            },
                        },
                    )
                    .map_err(|e| e.to_string())?;

                let mut hex = String::new();
                for byte in output.return_data {
                    use std::fmt::Write;
                    let _ = write!(hex, "{byte:02x}");
                }

                println!("return_data: {hex}");
                println!("resources: {:?}", output.resources);
            }

            Ok(())
        }
        _ => Err("unsupported command or invalid arguments; use --help".into()),
    }
}

struct BuildDirectory(PathBuf);

impl Drop for BuildDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn build(source: &Path, output: &Path, runtime: &WasmRuntime) -> Result<(), String> {
    if output.exists() {
        return Err("output already exists".into());
    }

    read(source, runtime::MAX_MODULE_SIZE)?;

    let rustc = sdk::resolve_compiler()?;
    let directory = build_directory()?;
    let sdk_library = sdk::compile(&directory.0, &rustc)?;
    let source = source.canonicalize().map_err(|e| e.to_string())?;

    let mut builds = Vec::new();

    for index in 0..2 {
        let artifact = directory.0.join(format!("build-{index}.wasm"));
        let mut compiler = sdk::compiler(&rustc);
        compiler.arg(sdk::remap(source.parent().ok_or("source parent missing")?));

        let status = compiler
            .arg(&source)
            .arg("--extern")
            .arg(sdk::external("contract_sdk", &sdk_library))
            .arg("-L")
            .arg(sdk::dependency(&directory.0))
            .args([
                "--crate-type=cdylib",
                "--crate-name=astrolune_contract",
                "-Cmetadata=astrolune-abi2-meter1",
                "-Clink-arg=--export-memory",
                "-Clink-arg=--compress-relocations",
                "-Clink-arg=--max-memory=16777216",
                "-Clink-arg=-zstack-size=65536",
                "-o",
            ])
            .arg(&artifact)
            .status()
            .map_err(|e| e.to_string())?;

        if !status.success() {
            return Err("Rust contract compilation failed; check compiler target installation and source ABI".into());
        }

        builds.push(read(&artifact, runtime::MAX_MODULE_SIZE)?);
    }

    if builds[0] != builds[1] {
        return Err("repeated builds produced different bytes".into());
    }

    let module = runtime
        .validate(&builds[0], WASM_VERSION)
        .map_err(|e| e.to_string())?;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    file.write_all(&module.code)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;

    println!("code_hash: {}", module.code_hash);
    println!("repeated_build: identical");

    Ok(())
}

fn build_directory() -> Result<BuildDirectory, String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("astrolune-contract-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path).map_err(|e| e.to_string())?;

    Ok(BuildDirectory(path))
}
