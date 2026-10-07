<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# Reproducible contract source packages

```
cargo contract init my-contract
cargo contract package my-contract source.alpkg
cargo contract build-package my-contract release
cargo contract verify-source release/source.alpkg release/contract.wasm
```

`init` creates a standalone Cargo manifest and the SDK counter example.
`build-package` snapshots the source package, extracts that snapshot into a
private build directory, compiles it twice and requires identical validated
WASM bytes. The new output directory contains `contract.wasm`, `source.alpkg`
and `artifact.txt` with source, code and SDK commitments. Existing files and
directories are never overwritten. `verify-source` rebuilds the bundle with
the pinned tools and compares the entire artifact, not just a claimed hash.
It performs no network operation or publication.

The supported Cargo profile fixes Rust 1.99.0, edition 2024, `src/lib.rs`,
`cdylib`, and the bundled `contract-sdk =0.1.0` without default features.
Ordinary nested Rust modules are supported. The build driver uses the reviewed
manifest to select this fixed rustc profile; it does not run Cargo build scripts,
fetch dependencies or apply ambient Cargo configuration. Other dependencies,
features, workspace membership, target/profile overrides, `.cargo`, build
scripts and lockfiles are rejected. Package description, license and authors
may be included as metadata.

The Rust upgrade changes the source-package build-profile commitment. A bundle
created for the former Rust 1.93.1 or 1.98.1 profiles must be verified with their corresponding
toolchain or rebuilt/repackaged explicitly for 1.99.0. Previously deployed ABI-v2
WASM bytes keep their existing code hashes; dependency updates do not rewrite
deployed state or silently relabel old source bundles.

The versioned `ALPKG001` bundle commits to its build profile and the exact bundled
SDK/ABI source bytes. It contains sorted, unique, length-prefixed paths and file
contents. Limits are 4 MiB total, 128 files, 128 visited source directory entries,
16 directory levels, 1 MiB per Rust file, 16 KiB for `Cargo.toml` and 256 bytes per
path. Only portable lowercase ASCII source paths are accepted; traversal,
symlinks, Windows reparse points and device-name components are rejected.
Decoding validates the complete package before creating any files.

Rust source tokens that can introduce hidden input (`include`, `include_str`,
`include_bytes`, `env`, `option_env`, `path`, `link`, `link_args`, `global_asm`,
`asm`) are reserved in this profile, including inside macro definitions and as
raw identifiers. Use ordinary modules and literal data. Comments and string
contents are not treated as identifiers. The restriction is intentionally
conservative: a local variable named `path` must also be renamed. The compiler
is invoked without `RUSTC_BOOTSTRAP`. Build paths are remapped so `file!()` is
stable across extraction directories.

The compiler and its wasm32 standard library remain operator-provisioned trust
inputs; an arbitrary `ASTROLUNE_CONTRACT_SYSROOT` is not authenticated by the
package. Version pinning, source comparison and repeat builds are implemented;
cross-platform release qualification is tracked separately. The standalone
`build source.rs output.wasm` command remains available, but only package builds
apply the source-input restrictions and produce the canonical source bundle.

Tests cover exact bundle round trips, every truncation, incompatible SDK/profile
identities, hostile paths/manifests, macro-hidden external inputs, multi-file
compilation, path remapping, repeatability and wrong-artifact rejection.
