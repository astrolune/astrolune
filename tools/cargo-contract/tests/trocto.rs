// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Trocto CLI source validation and deterministic LLVM export.

use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "astrolune-trocto-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("main.tc"),
            "fn call(input: u64) -> u64 { return input + 7; }",
        )
        .unwrap();
        Self(root)
    }

    fn command(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_cargo-contract"))
            .current_dir(&self.0)
            .args(["trocto"])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn validates_source_exports_identical_llvm_and_refuses_overwrite() {
    let fixture = Fixture::new();
    let checked = fixture.command(&["check", "main.tc"]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("source_hash:"));
    for file in ["first.ll", "second.ll"] {
        let result = fixture.command(&["emit-llvm", "main.tc", file]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let original = std::fs::read(fixture.0.join("first.ll")).unwrap();
    assert_eq!(
        original,
        std::fs::read(fixture.0.join("second.ll")).unwrap()
    );
    assert!(String::from_utf8_lossy(&original).contains("@trocto_call"));
    assert!(
        !fixture
            .command(&["emit-llvm", "main.tc", "first.ll"])
            .status
            .success()
    );
    assert_eq!(original, std::fs::read(fixture.0.join("first.ll")).unwrap());
}

#[test]
fn rejects_malformed_source_extensions_and_native_call_arguments() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.0.join("main.rs"),
        "fn call(input: u64) -> u64 { return input; }",
    )
    .unwrap();
    std::fs::write(
        fixture.0.join("invalid.tc"),
        "fn call(input: u64) -> u64 { return missing; }",
    )
    .unwrap();
    std::fs::write(fixture.0.join("invalid-utf8.tc"), [0xff]).unwrap();
    for args in [
        vec!["check", "main.rs"],
        vec!["check", "invalid.tc"],
        vec!["check", "invalid-utf8.tc"],
        vec!["run", "main.tc", "-1"],
        vec!["run", "main.tc", "1", "-1"],
        vec!["run", "main.tc", "18446744073709551616"],
        vec!["check", "main.tc", "extra"],
    ] {
        assert!(!fixture.command(&args).status.success(), "{args:?}");
    }
}
