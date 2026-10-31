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

#[test]
fn source_packages_preserve_exact_source_and_reject_tampering() {
    let fixture = Fixture::new();
    let packaged = fixture.command(&["package", "main.tc", "main.tcp"]);
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    assert!(fixture.command(&["check", "main.tcp"]).status.success());
    assert!(
        fixture
            .command(&["verify-source", "main.tc", "main.tcp"])
            .status
            .success()
    );
    let original = std::fs::read(fixture.0.join("main.tcp")).unwrap();
    assert!(
        !fixture
            .command(&["package", "main.tc", "main.tcp"])
            .status
            .success()
    );
    assert_eq!(std::fs::read(fixture.0.join("main.tcp")).unwrap(), original);
    std::fs::write(
        fixture.0.join("changed.tc"),
        "fn call(input: u64) -> u64 { return input + 8; }",
    )
    .unwrap();
    assert!(
        !fixture
            .command(&["verify-source", "changed.tc", "main.tcp"])
            .status
            .success()
    );
    let mut altered = original;
    altered[12] ^= 1;
    std::fs::write(fixture.0.join("tampered.tcp"), altered).unwrap();
    assert!(!fixture.command(&["check", "tampered.tcp"]).status.success());
}

#[test]
fn initializes_stateful_source_and_exposes_declared_keys() {
    let fixture = Fixture::new();
    assert!(fixture.command(&["init", "counter"]).status.success());
    assert!(!fixture.command(&["init", "counter"]).status.success());
    let checked = fixture.command(&["check", "counter/main.tc"]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let output = String::from_utf8_lossy(&checked.stdout);
    assert!(output.contains("language: trocto-2"));
    assert!(output.contains("state_key: counter"));
}

#[test]
#[ignore = "requires pinned LLVM 22.1.8 and native OS isolation"]
fn native_stateful_cli_build_and_run() {
    let fixture = Fixture::new();
    assert!(fixture.command(&["init", "counter"]).status.success());
    let built = fixture.command(&["build", "counter/main.tc", "counter.tcp"]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    std::fs::write(fixture.0.join("state.txt"), "counter=10\n").unwrap();
    let output = fixture.command(&["run", "counter.tcp", "5", "1000", "state.txt"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("return_value: 15"));
    assert!(output.contains("write: counter=15"));
    assert!(output.contains("event: 1=15"));
}
