// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bundles the exact SDK sources so installed tools need no checkout or network.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

const ABI_LIB: &str = include_str!("../../../crates/contract-abi/src/lib.rs");
const ABI_GUEST: &str = include_str!("../../../crates/contract-abi/src/guest.rs");
const SDK_FILES: &[(&str, &str)] = &[
    (
        "registry.rs",
        include_str!("../../../crates/contract-sdk/src/registry.rs"),
    ),
    (
        "lib.rs",
        include_str!("../../../crates/contract-sdk/src/lib.rs"),
    ),
    (
        "buffer.rs",
        include_str!("../../../crates/contract-sdk/src/buffer.rs"),
    ),
    (
        "error.rs",
        include_str!("../../../crates/contract-sdk/src/error.rs"),
    ),
    (
        "host.rs",
        include_str!("../../../crates/contract-sdk/src/host.rs"),
    ),
    (
        "metered.rs",
        include_str!("../../../crates/contract-sdk/src/metered.rs"),
    ),
];

pub(crate) const RUST_VERSION: &str = "1.99.0";

pub(crate) fn resolve_compiler() -> Result<PathBuf, String> {
    let output = Command::new("rustup")
        .args(["which", "--toolchain", RUST_VERSION, "rustc"])
        .output()
        .map_err(|error| format!("resolve pinned compiler through rustup: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "install Rust {RUST_VERSION} and its wasm32 target with rustup"
        ));
    }

    let path = PathBuf::from(
        String::from_utf8(output.stdout)
            .map_err(|error| error.to_string())?
            .trim(),
    );
    if !path.is_absolute() || !path.is_file() {
        return Err("rustup returned an invalid compiler path".into());
    }

    let version = Command::new(&path)
        .arg("--version")
        .env_remove("RUSTC_BOOTSTRAP")
        .output()
        .map_err(|error| error.to_string())?;
    if !version.status.success()
        || !version
            .stdout
            .starts_with(format!("rustc {RUST_VERSION} ").as_bytes())
    {
        return Err(format!("contract compiler must be rustc {RUST_VERSION}"));
    }

    Ok(path)
}

pub(crate) fn compiler(path: &Path) -> Command {
    let mut compiler = Command::new(path);
    if let Some(sysroot) = std::env::var_os("ASTROLUNE_CONTRACT_SYSROOT") {
        compiler.arg("--sysroot").arg(sysroot);
    }

    compiler.env_remove("RUSTC_BOOTSTRAP");
    compiler.args([
        "--edition=2024",
        "--target=wasm32-unknown-unknown",
        "-Copt-level=s",
        "-Ctarget-feature=-reference-types,-multivalue,-tail-call,-simd128,-relaxed-simd",
        "-Cpanic=abort",
        "-Ccodegen-units=1",
        "-Cdebuginfo=0",
        "-Cstrip=symbols",
    ]);

    compiler
}

pub(crate) fn compile(directory: &Path, rustc: &Path) -> Result<PathBuf, String> {
    let abi = directory.join("abi");
    let sdk = directory.join("sdk");
    std::fs::create_dir(&abi)
        .and_then(|()| std::fs::create_dir(&sdk))
        .map_err(|e| e.to_string())?;

    std::fs::write(abi.join("lib.rs"), ABI_LIB)
        .and_then(|()| std::fs::write(abi.join("guest.rs"), ABI_GUEST))
        .map_err(|e| e.to_string())?;
    for (name, source) in SDK_FILES {
        std::fs::write(sdk.join(name), source).map_err(|e| e.to_string())?;
    }

    let abi_library = directory.join("libcontract_abi.rlib");
    let sdk_library = directory.join("libcontract_sdk.rlib");

    let status = compiler(rustc)
        .arg(remap(directory))
        .arg(abi.join("lib.rs"))
        .args([
            "--crate-type=rlib",
            "--crate-name=contract_abi",
            "-Cmetadata=astrolune-abi2-meter1",
            "-o",
        ])
        .arg(&abi_library)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("ABI binding compilation failed".into());
    }

    let status = compiler(rustc)
        .arg(remap(directory))
        .arg(sdk.join("lib.rs"))
        .args([
            "--crate-type=rlib",
            "--crate-name=contract_sdk",
            "-Cmetadata=astrolune-sdk-v2",
            "--extern",
        ])
        .arg(external("contract_abi", &abi_library))
        .arg("-o")
        .arg(&sdk_library)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("SDK compilation failed".into());
    }

    Ok(sdk_library)
}

pub(crate) fn external(name: &str, path: &Path) -> std::ffi::OsString {
    let mut argument = std::ffi::OsString::from(format!("{name}="));
    argument.push(path);

    argument
}

pub(crate) fn dependency(path: &Path) -> std::ffi::OsString {
    let mut argument = std::ffi::OsString::from("dependency=");
    argument.push(path);

    argument
}

pub(crate) fn source_hash() -> types::Hash256 {
    let mut bytes = Vec::new();

    for (name, source) in [("abi/lib.rs", ABI_LIB), ("abi/guest.rs", ABI_GUEST)]
        .into_iter()
        .chain(SDK_FILES.iter().copied())
    {
        for field in [name, source] {
            bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
    }

    types::hash::domain_hash(b"astrolune.contract.sdk.source.v1", &bytes)
}

pub(crate) fn remap(directory: &Path) -> std::ffi::OsString {
    let mut argument = std::ffi::OsString::from("--remap-path-prefix=");
    argument.push(directory);
    argument.push("=/contract");

    argument
}
