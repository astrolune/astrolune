// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Development commands for checked Trocto source and the native LLVM worker.

use std::{ffi::OsString, fs::OpenOptions, io::Write, path::Path, time::Duration};
use trocto_compiler::{Program, compile};
use trocto_runtime::NativeProgram;

const HELP: &str = "Trocto native LLVM development tools\n\nUsage: cargo contract trocto <command>\n\n  check <source.tc>\n  emit-llvm <source.tc> <new-output.ll>\n  run <source.tc> <input-u64> [fuel]\n\nSet ASTROLUNE_LLVM_CLANG to clang 22.1.8 if it is not in PATH.\nThe native worker is an experimental development runtime.\n";

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
        Some((command, [source])) if command == "check" => {
            let program = source_program(Path::new(source))?;
            println!("language: trocto-{}", trocto_compiler::LANGUAGE_VERSION);
            println!("source_hash: {}", program.source_hash());
            println!("llvm_ir_bytes: {}", program.llvm_ir().len());
            Ok(())
        }
        Some((command, [source, output])) if command == "emit-llvm" => {
            let program = source_program(Path::new(source))?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .map_err(|error| error.to_string())?;
            file.write_all(program.llvm_ir().as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| error.to_string())?;
            println!("language: trocto-{}", trocto_compiler::LANGUAGE_VERSION);
            println!("source_hash: {}", program.source_hash());
            println!("target: native-llvm");
            Ok(())
        }
        Some((command, [source, input, rest @ ..])) if command == "run" && rest.len() <= 1 => {
            let program = source_program(Path::new(source))?;
            let input = integer(input, "input")?;
            let fuel = rest
                .first()
                .map_or(Ok(1_000_000), |value| integer(value, "fuel"))?;
            let clang =
                std::env::var_os("ASTROLUNE_LLVM_CLANG").unwrap_or_else(|| OsString::from("clang"));
            let mut native =
                NativeProgram::compile(program, Path::new(&clang), Duration::from_secs(30))
                    .map_err(|error| error.to_string())?;
            println!("compiler: {}", native.compiler_identity());
            let result = native
                .execute(input, fuel, Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            println!(
                "runtime: trocto-native-{}-meter{}",
                trocto_compiler::LANGUAGE_VERSION,
                trocto_compiler::METERING_VERSION
            );
            println!("return_value: {}", result.value);
            println!("fuel_used: {}", result.fuel_used);
            Ok(())
        }
        _ => Err("invalid Trocto arguments; use cargo contract trocto --help".into()),
    }
}

fn source_program(path: &Path) -> Result<Program, String> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("tc") {
        return Err("Trocto source must use the .tc extension".into());
    }
    let bytes = super::read(path, trocto_compiler::MAX_SOURCE_BYTES)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| "Trocto source must be UTF-8")?;
    compile(source).map_err(|error| error.to_string())
}

fn integer(value: &OsString, name: &str) -> Result<u64, String> {
    value
        .to_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("{name} must be an unsigned 64-bit decimal integer"))
}
