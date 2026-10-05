// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Canonical, bounded source bundles and offline artifact/source comparison.

use crate::{package_policy, sdk};
use codec::Decoder;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use types::{Hash256, hash::domain_hash};

const MAGIC: &[u8; 8] = b"ALPKG001";
const MAX_PACKAGE: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 128;
const PROFILE: &[u8] = b"rustc1.99.0/wasm32/abi2/meter1/package1/compress-relocations";

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), String> {
    match (command, args) {
        ("init", [directory]) => {
            let directory = Path::new(directory);
            fs::create_dir(directory).map_err(|e| e.to_string())?;
            fs::create_dir(directory.join("src")).map_err(|e| e.to_string())?;

            write_new(
                &directory.join("Cargo.toml"),
                package_policy::MANIFEST.as_bytes(),
            )?;
            write_new(
                &directory.join("src/lib.rs"),
                include_bytes!("../../../examples/contracts/counter.rs"),
            )
        }
        ("package", [directory, output]) => {
            let files = collect(Path::new(directory))?;
            let bytes = encode(&files)?;

            write_new(Path::new(output), &bytes)?;
            println!("source_hash: {}", source_hash(&bytes));

            Ok(())
        }
        ("build-package", [directory, output]) => {
            let bytes = encode(&collect(Path::new(directory))?)?;

            let temporary = crate::build_directory()?;
            let files = decode(&bytes)?;
            extract(&temporary.0, &files)?;

            let artifact = temporary.0.join("contract.wasm");
            crate::build(
                &temporary.0.join("src/lib.rs"),
                &artifact,
                &runtime::WasmRuntime::new(),
            )?;
            let code = crate::read(&artifact, runtime::MAX_MODULE_SIZE)?;

            let output = Path::new(output);
            fs::create_dir(output).map_err(|e| e.to_string())?;
            write_new(&output.join("contract.wasm"), &code)?;
            write_new(&output.join("source.alpkg"), &bytes)?;

            let manifest = format!(
                "profile: {}\nsource_hash: {}\ncode_hash: {}\nsdk_hash: {}\n",
                String::from_utf8_lossy(PROFILE),
                source_hash(&bytes),
                runtime::wasm_code_hash(&code),
                sdk::source_hash()
            );
            write_new(&output.join("artifact.txt"), manifest.as_bytes())?;

            println!("source_hash: {}", source_hash(&bytes));

            Ok(())
        }
        ("verify-source", [bundle, artifact]) => {
            let bytes = crate::read(Path::new(bundle), MAX_PACKAGE)?;
            let files = decode(&bytes)?;
            let expected = crate::read(Path::new(artifact), runtime::MAX_MODULE_SIZE)?;

            let directory = crate::build_directory()?;
            extract(&directory.0, &files)?;

            let output = directory.0.join("rebuilt.wasm");
            crate::build(
                &directory.0.join("src/lib.rs"),
                &output,
                &runtime::WasmRuntime::new(),
            )?;

            if crate::read(&output, runtime::MAX_MODULE_SIZE)? != expected {
                return Err("published source does not reproduce the supplied artifact".into());
            }

            println!("verified_source_hash: {}", source_hash(&bytes));

            Ok(())
        }
        _ => Err("invalid package command arguments; use --help".into()),
    }
}

fn source_hash(bytes: &[u8]) -> Hash256 {
    domain_hash(b"astrolune.contract.source.v1", bytes)
}

fn collect(directory: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    reject_link(directory)?;
    let root = directory.canonicalize().map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();

    for name in ["build.rs", ".cargo", "Cargo.lock"] {
        if root.join(name).exists() {
            return Err(format!("package profile forbids {name}"));
        }
    }

    let manifest = root.join("Cargo.toml");
    reject_link(&manifest)?;
    files.insert("Cargo.toml".into(), crate::read(&manifest, 16 * 1024)?);

    collect_source(&root, &root.join("src"), &mut files, 0, &mut 0)?;

    validate(&files)?;

    Ok(files)
}

fn collect_source(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    depth: usize,
    visited: &mut usize,
) -> Result<(), String> {
    reject_link(directory)?;
    if depth > 16 {
        return Err("source directory nesting exceeds 16".into());
    }

    let mut entries = fs::read_dir(directory)
        .map_err(|e| e.to_string())?
        .take(MAX_FILES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if entries.len() > MAX_FILES {
        return Err("too many source entries".into());
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        *visited += 1;
        if *visited > MAX_FILES {
            return Err("package directory entry limit exceeded".into());
        }

        let location = entry.path();
        reject_link(&location)?;

        let relative = location
            .strip_prefix(root)
            .map_err(|_| "source escaped package")?
            .to_str()
            .ok_or("non-UTF-8 source path")?
            .replace('\\', "/");
        safe_path(&relative)?;

        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            collect_source(root, &location, files, depth + 1, visited)?;
        } else {
            if !Path::new(&relative)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                || files.len() >= MAX_FILES
            {
                return Err("package accepts at most 128 Rust source files".into());
            }

            files.insert(relative, crate::read(&location, runtime::MAX_MODULE_SIZE)?);

            if files.values().map(Vec::len).sum::<usize>() > MAX_PACKAGE {
                return Err("source package exceeds 4 MiB".into());
            }
        }
    }

    Ok(())
}

fn reject_link(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        return Err("source links and special files are forbidden".into());
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("source reparse points are forbidden".into());
        }
    }

    Ok(())
}

fn safe_path(path: &str) -> Result<(), String> {
    if path == "Cargo.toml" {
        return Ok(());
    }

    if path.len() > 256 || !(path == "src" || path.starts_with("src/")) {
        return Err("invalid package path".into());
    }

    for part in path.split('/') {
        let stem = part.split('.').next().unwrap_or_default();
        if part.is_empty()
            || part.len() > 100
            || part.ends_with('.')
            || part.starts_with('.')
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            || ["con", "prn", "aux", "nul"].contains(&stem)
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err("package paths must use portable lowercase ASCII components".into());
        }
    }

    Ok(())
}

fn validate(files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    if files.len() > MAX_FILES || !files.contains_key("src/lib.rs") {
        return Err("bounded package requires src/lib.rs".into());
    }

    package_policy::manifest(files.get("Cargo.toml").ok_or("package manifest missing")?)?;

    for (name, bytes) in files {
        safe_path(name)?;

        if name == "Cargo.toml" {
            continue;
        }

        if !Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
            || bytes.len() > runtime::MAX_MODULE_SIZE
        {
            return Err("invalid Rust source file".into());
        }

        package_policy::source(bytes)?;
    }

    Ok(())
}

fn encode(files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    validate(files)?;

    let mut bytes = MAGIC.to_vec();
    bytes
        .extend_from_slice(domain_hash(b"astrolune.contract.build-profile.v1", PROFILE).as_bytes());
    bytes.extend_from_slice(sdk::source_hash().as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(files.len())
            .map_err(|_| "too many files")?
            .to_le_bytes(),
    );

    for (name, source) in files {
        for value in [name.as_bytes(), source.as_slice()] {
            bytes.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| "field too large")?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(value);
        }

        if bytes.len() > MAX_PACKAGE {
            return Err("source package exceeds 4 MiB".into());
        }
    }

    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut decoder = Decoder::new(bytes);
    let mut files = BTreeMap::new();

    let result = (|| -> Result<(), codec::DecodeError> {
        if bytes.len() > MAX_PACKAGE
            || decoder.read_exact(8)? != MAGIC
            || decoder.read_exact(32)?
                != domain_hash(b"astrolune.contract.build-profile.v1", PROFILE).as_bytes()
            || decoder.read_exact(32)? != sdk::source_hash().as_bytes()
        {
            return Err(codec::DecodeError::Unsupported);
        }

        let count = decoder.read_u32()? as usize;
        if count > MAX_FILES {
            return Err(codec::DecodeError::LimitExceeded);
        }

        let mut previous = String::new();

        for _ in 0..count {
            let name = std::str::from_utf8(field(&mut decoder, 256)?)
                .map_err(|_| codec::DecodeError::NonCanonical)?
                .to_owned();
            if name <= previous {
                return Err(codec::DecodeError::NonCanonical);
            }
            previous.clone_from(&name);

            files.insert(
                name,
                field(&mut decoder, runtime::MAX_MODULE_SIZE)?.to_vec(),
            );
        }

        decoder.finish()
    })();

    result.map_err(|_| "invalid, incompatible or noncanonical source bundle")?;
    validate(&files)?;

    Ok(files)
}

fn field<'a>(decoder: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], codec::DecodeError> {
    let size = decoder.read_u32()? as usize;
    if size > max {
        return Err(codec::DecodeError::LimitExceeded);
    }

    decoder.read_exact(size)
}

fn extract(directory: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for (name, bytes) in files {
        let path: PathBuf = directory.join(name);
        fs::create_dir_all(path.parent().ok_or("invalid source parent")?)
            .map_err(|e| e.to_string())?;
        write_new(&path, bytes)?;
    }

    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_decoder_rejects_truncation_traversal_and_incompatible_build_profiles() {
        let files = BTreeMap::from([
            (
                "Cargo.toml".into(),
                package_policy::MANIFEST.as_bytes().to_vec(),
            ),
            ("src/lib.rs".into(), b"#![no_std]".to_vec()),
        ]);
        let bytes = encode(&files).unwrap();
        assert_eq!(decode(&bytes).unwrap(), files);

        for length in 0..bytes.len() {
            assert!(decode(&bytes[..length]).is_err());
        }
        assert!(decode(&[bytes.as_slice(), &[0]].concat()).is_err());

        for offset in [0, 8, 40, 72] {
            let mut altered = bytes.clone();
            altered[offset] ^= 0xff;
            assert!(decode(&altered).is_err());
        }

        for name in [
            "/src/lib.rs",
            "src/../lib.rs",
            "src/cOn.rs",
            "src/con.rs",
            "src/nul",
            "src/a:",
            "src/a\\b.rs",
            "src/.hidden",
            "src/foo.",
        ] {
            assert!(safe_path(name).is_err(), "{name}");
        }
    }
}