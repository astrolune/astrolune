// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Development commands for checked Trocto source and the native LLVM worker.

use std::{ffi::OsString, fs::OpenOptions, io::Write, path::Path, time::Duration};
use trocto_compiler::{ContractContext, Program, SourcePackage};
use trocto_runtime::NativeProgram;

const HELP: &str = "Trocto native LLVM contract tools\n\nUsage: cargo contract trocto <command>\n\n  init <new-directory>\n  check <source.tc|source.tcp>\n  package <source.tc> <new-source.tcp>\n  build <source.tc> <new-source.tcp>  Compile natively and save checked source\n  verify-source <source.tc> <source.tcp>\n  emit-llvm <source.tc|source.tcp> <new-output.ll>\n  run <source.tc|source.tcp> <input-u64> [fuel] [state-file]\n\nState files contain key=value lines (ASCII key, decimal u64).\nRun grants access to the source's declared keys and prints staged writes/events.\nSet ASTROLUNE_LLVM_CLANG to clang 22.1.8 if it is not in PATH.\nDeploy with cli sign-trocto-deploy on a genesis runtime_version 3 network.\n";

pub(super) fn run(args: &[OsString]) -> Result<(), String> {
    match args.split_first() {
        None => {
            print!("{HELP}");
            Ok(())
        }
        Some((command, [])) if command == "--help" || command == "-h" => {
            print!("{HELP}");
            Ok(())
        }
        Some((command, [directory])) if command == "init" => {
            let path = Path::new(directory);
            std::fs::create_dir(path).map_err(|error| error.to_string())?;
            write_new(&path.join("main.tc"), TEMPLATE.as_bytes())?;
            println!("source: {}", path.join("main.tc").display());
            Ok(())
        }
        Some((command, [source])) if command == "check" => {
            let program = source_program(Path::new(source))?;
            println!("language: trocto-{}", program.language_version());
            println!("metering: {}", program.metering_version());
            println!("source_hash: {}", program.source_hash());
            println!("llvm_ir_bytes: {}", program.llvm_ir().len());
            for key in program.state_keys() {
                println!("state_key: {}", String::from_utf8_lossy(key));
            }
            Ok(())
        }
        Some((command, [source, output])) if command == "package" || command == "build" => {
            let package = source_package(Path::new(source))?;
            if command == "build" {
                let native = NativeProgram::compile(
                    package.program().clone(),
                    &clang(),
                    Duration::from_secs(30),
                )
                .map_err(|error| error.to_string())?;
                println!("compiler: {}", native.compiler_identity());
            }
            write_new(Path::new(output), &package.to_bytes())?;
            println!("source_hash: {}", package.program().source_hash());
            println!("package: {}", Path::new(output).display());
            Ok(())
        }
        Some((command, [source, packaged])) if command == "verify-source" => {
            let source = source_package(Path::new(source))?;
            let bytes = super::read(Path::new(packaged), trocto_compiler::MAX_PACKAGE_BYTES)?;
            let package = SourcePackage::decode(&bytes).map_err(|error| error.to_string())?;
            if source.to_bytes() != package.to_bytes() {
                return Err("Trocto source package commitment mismatch".into());
            }
            println!("source_hash: {}", package.program().source_hash());
            println!("published_source: identical");
            Ok(())
        }
        Some((command, [source, output])) if command == "emit-llvm" => {
            let program = source_program(Path::new(source))?;
            write_new(Path::new(output), program.llvm_ir().as_bytes())?;
            println!("language: trocto-{}", program.language_version());
            println!("source_hash: {}", program.source_hash());
            println!("target: native-llvm");
            Ok(())
        }
        Some((command, [source, input, rest @ ..])) if command == "run" && rest.len() <= 2 => {
            let program = source_program(Path::new(source))?;
            let input = integer(input, "input")?;
            let fuel = rest
                .first()
                .map_or(Ok(1_000_000), |value| integer(value, "fuel"))?;
            let context = state_context(&program, rest.get(1).map(Path::new))?;
            let keys = context.keys.clone();
            let language = program.language_version();
            let metering = program.metering_version();
            let mut native = NativeProgram::compile(program, &clang(), Duration::from_secs(30))
                .map_err(|error| error.to_string())?;
            println!("compiler: {}", native.compiler_identity());
            let result = native
                .execute_contract(input, &context, fuel, Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            println!("runtime: trocto-native-{language}-meter{metering}");
            println!("return_value: {}", result.value);
            println!("fuel_used: {}", result.fuel_used);
            for (index, key) in keys.iter().enumerate() {
                if result.writes[index] {
                    match result.state[index] {
                        Some(value) => println!("write: {}={value}", key_label(key)),
                        None => println!("delete: {}", key_label(key)),
                    }
                }
            }
            for (topic, value) in result.events {
                println!("event: {topic}={value}");
            }
            Ok(())
        }
        _ => Err("invalid Trocto arguments; use cargo contract trocto --help".into()),
    }
}

fn source_program(path: &Path) -> Result<Program, String> {
    Ok(source_package(path)?.program().clone())
}

fn source_package(path: &Path) -> Result<SourcePackage, String> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("tc") => {
            let bytes = super::read(path, trocto_compiler::MAX_SOURCE_BYTES)?;
            let source = std::str::from_utf8(&bytes).map_err(|_| "Trocto source must be UTF-8")?;
            SourcePackage::new(source).map_err(|error| error.to_string())
        }
        Some("tcp") => {
            let bytes = super::read(path, trocto_compiler::MAX_PACKAGE_BYTES)?;
            SourcePackage::decode(&bytes).map_err(|error| error.to_string())
        }
        _ => Err("Trocto source must use the .tc or .tcp extension".into()),
    }
}

fn clang() -> std::path::PathBuf {
    std::env::var_os("ASTROLUNE_LLVM_CLANG").map_or_else(|| "clang".into(), Into::into)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

fn state_context(program: &Program, path: Option<&Path>) -> Result<ContractContext, String> {
    let mut initial = std::collections::BTreeMap::new();
    if let Some(path) = path {
        let bytes = super::read(path, trocto_compiler::MAX_SOURCE_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "state file must be UTF-8")?;
        for line in text.lines() {
            let (key, value) = line
                .rsplit_once('=')
                .ok_or("state line must be key=value")?;
            let key = if let Some(hex) = key.strip_prefix("hex:") {
                if hex.len() % 2 != 0 || hex.is_empty() || hex.len() > 512 || !hex.is_ascii() {
                    return Err("hex state key requires 1..256 encoded bytes".into());
                }
                hex.as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        let text =
                            std::str::from_utf8(pair).map_err(|_| "invalid hex state key")?;
                        u8::from_str_radix(text, 16).map_err(|_| "invalid hex state key")
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                if key.is_empty() || key.len() > 256 || !key.is_ascii() {
                    return Err("state key requires 1..256 ASCII bytes or hex encoding".into());
                }
                key.as_bytes().to_vec()
            };
            let value = integer(&OsString::from(value), "state value")?;
            if initial.insert(key, value).is_some() {
                return Err("duplicate key in state file".into());
            }
        }
    }
    let mut keys = program.state_keys().to_vec();
    for key in initial.keys() {
        if program.state_keys().binary_search(key).is_err() {
            keys.push(key.clone());
        }
    }
    if keys.len() > trocto_compiler::MAX_STATE_KEYS {
        return Err("state context exceeds 1024 keys".into());
    }
    Ok(ContractContext {
        height: 1,
        caller: [0; 4],
        state: keys.iter().map(|key| initial.get(key).copied()).collect(),
        access: vec![true; keys.len()],
        keys,
    })
}

fn key_label(key: &[u8]) -> String {
    if key.iter().all(|byte| (32..127).contains(byte)) {
        String::from_utf8_lossy(key).into_owned()
    } else {
        use std::fmt::Write;
        let mut output = String::from("hex:");
        for byte in key {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

const TEMPLATE: &str = "// Trocto stateful payment counter.\nfn call(input: u64) -> u64 {\n    let current: u64 = state_get(\"counter\");\n    let next: u64 = current + input;\n    state_set(\"counter\", next);\n    emit(1, next);\n    return next;\n}\n";

fn integer(value: &OsString, name: &str) -> Result<u64, String> {
    value
        .to_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("{name} must be an unsigned 64-bit decimal integer"))
}
