// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Build the trusted Windows compiler supervisor independently of native LLVM.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    #[cfg(windows)]
    build_windows();
    #[cfg(not(windows))]
    panic!("Cross-host Windows compiler supervisor builds are unsupported");
}

#[cfg(windows)]
fn build_windows() {
    use std::{env, path::PathBuf};
    println!("cargo:rerun-if-changed=src/compiler-supervisor.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let compiler = cc::Build::new()
        .debug(false)
        .opt_level(2)
        .static_crt(true)
        .get_compiler();
    assert!(
        compiler.is_like_msvc(),
        "Windows native supervisor requires the MSVC build toolchain"
    );
    let mut command = compiler.to_command();
    command
        .args([
            "/nologo",
            "/O2",
            "/Brepro",
            "/W4",
            "/WX",
            "/D_WIN32_WINNT=0x0A00",
        ])
        .arg(format!(
            "/Fo{}",
            output.join("compiler-supervisor.obj").display()
        ))
        .arg(format!(
            "/Fe{}",
            output.join("compiler-supervisor.exe").display()
        ))
        .arg("src/compiler-supervisor.c")
        .args([
            "/link",
            "/Brepro",
            "/INCREMENTAL:NO",
            "/DEBUG:NONE",
            "kernel32.lib",
        ]);
    let result = command
        .output()
        .expect("MSVC compiler supervisor build must start");
    assert!(
        result.status.success(),
        "compiler supervisor build failed: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
