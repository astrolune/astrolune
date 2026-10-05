// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Restricted Cargo package profile; no build scripts, environment or external inputs.

use proc_macro2::{TokenStream, TokenTree};
use std::str::FromStr;
use toml::{Table, Value};

pub(super) const MANIFEST: &str = "# Copyright (c) 2026 Astrolune contributors\n# SPDX-License-Identifier: MIT\n[package]\nname = \"astrolune-contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.99.0\"\n[lib]\ncrate-type = [\"cdylib\"]\n[dependencies.contract-sdk]\nversion = \"=0.1.0\"\ndefault-features = false\n[workspace]\n";

pub(super) fn manifest(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 16 * 1024 {
        return Err("Cargo.toml exceeds 16 KiB".into());
    }

    let text = std::str::from_utf8(bytes).map_err(|_| "manifest must be UTF-8")?;
    let table = Table::from_str(text).map_err(|error| format!("Cargo manifest: {error}"))?;
    only(&table, &["package", "lib", "dependencies", "workspace"])?;

    let package = child(&table, "package")?;
    only(
        package,
        &[
            "name",
            "version",
            "edition",
            "rust-version",
            "description",
            "license",
            "authors",
        ],
    )?;

    let name = package
        .get("name")
        .and_then(Value::as_str)
        .ok_or("package name missing")?;
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err("invalid package name".into());
    }

    let version = package
        .get("version")
        .and_then(Value::as_str)
        .ok_or("package version missing")?;
    if version.len() > 64
        || version.split('.').count() != 3
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("package version must be a numeric major.minor.patch".into());
    }

    if package.get("edition").and_then(Value::as_str) != Some("2024")
        || package.get("rust-version").and_then(Value::as_str) != Some("1.99.0")
    {
        return Err("package must pin edition 2024 and rust-version 1.99.0".into());
    }

    let library = child(&table, "lib")?;
    only(library, &["crate-type"])?;
    if library.get("crate-type") != Some(&Value::Array(vec![Value::String("cdylib".into())])) {
        return Err("package must define a cdylib at src/lib.rs".into());
    }

    let dependencies = child(&table, "dependencies")?;
    only(dependencies, &["contract-sdk"])?;

    let sdk = child(dependencies, "contract-sdk")?;
    only(sdk, &["version", "default-features"])?;
    if sdk.get("version").and_then(Value::as_str) != Some("=0.1.0")
        || sdk.get("default-features").and_then(Value::as_bool) != Some(false)
    {
        return Err(
            "the only dependency is bundled contract-sdk =0.1.0 without default features".into(),
        );
    }

    if table
        .get("workspace")
        .is_some_and(|workspace| workspace.as_table().is_none_or(|table| !table.is_empty()))
    {
        return Err("only an empty standalone workspace is supported".into());
    }

    Ok(())
}

fn only(table: &Table, allowed: &[&str]) -> Result<(), String> {
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unsupported Cargo manifest field: {key}"));
    }

    Ok(())
}

fn child<'a>(table: &'a Table, key: &str) -> Result<&'a Table, String> {
    table
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| format!("missing [{key}] table"))
}

pub(super) fn source(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Rust source must be UTF-8")?;
    let tokens = TokenStream::from_str(text).map_err(|error| format!("Rust tokens: {error}"))?;

    inspect(tokens, 0)
}

fn inspect(tokens: TokenStream, depth: usize) -> Result<(), String> {
    if depth > 128 {
        return Err("source nesting exceeds the package bound".into());
    }

    for token in tokens {
        match token {
            TokenTree::Group(group) => inspect(group.stream(), depth + 1)?,
            TokenTree::Ident(ident) => {
                let text = ident.to_string();
                let text = text.strip_prefix("r#").unwrap_or(&text);

                // These tokens are reserved even inside macro_rules definitions: a macro
                // must not hide file/environment/native-link inputs from the package.
                if [
                    "include",
                    "include_str",
                    "include_bytes",
                    "env",
                    "option_env",
                    "path",
                    "link",
                    "link_args",
                    "global_asm",
                    "asm",
                ]
                .contains(&text)
                {
                    return Err(format!(
                        "package source reserves token {text}; use ordinary src modules and literal data"
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_profile_rejects_ambient_inputs_scripts_and_unpinned_dependencies() {
        manifest(MANIFEST.as_bytes()).unwrap();

        for (old, new) in [
            ("[lib]", "[build-dependencies]\nsomething = \"1\"\n[lib]"),
            ("=0.1.0", "0.1"),
            ("2024", "2021"),
            ("[workspace]", "[workspace]\nmembers = [\"elsewhere\"]"),
            ("[lib]", "build = \"build.rs\"\n[lib]"),
        ] {
            assert!(manifest(MANIFEST.replace(old, new).as_bytes()).is_err());
        }

        for source_text in [
            "include!(\"secret\");",
            "const X: &str = env!(\"SECRET\");",
            "#[path=\"../outside\"] mod external;",
            "macro_rules! hidden { () => {r#include_bytes!(\"x\")} }",
            "#[link(name=\"native\")] extern \"C\" {}",
        ] {
            assert!(source(source_text.as_bytes()).is_err());
        }

        source(b"mod local; const VALUE: &str = file!();").unwrap();
        source(b"// env! in a comment is inert\nconst TEXT: &str = \"include_bytes\";").unwrap();
    }
}
