// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

fn main() {
    println!("cargo:rerun-if-changed=coverage_windows.c");
    if std::env::var_os("CARGO_FEATURE_WINDOWS_COVERAGE").is_some() {
        assert_eq!(std::env::var("TARGET").unwrap(), "x86_64-pc-windows-msvc");
        cc::Build::new()
            .file("coverage_windows.c")
            .compile("coverage_sections");
        println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
        println!("cargo:rustc-link-arg=/INCLUDE:main");
        println!("cargo:rustc-link-arg=/MERGE:.SCOV=.data");
        println!("cargo:rustc-link-arg=/MERGE:.SCOVP=.rdata");
        println!("cargo:rustc-link-arg=/OPT:NOICF");
    }
}
