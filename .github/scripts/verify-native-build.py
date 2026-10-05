# Copyright (c) 2026 Astrolune contributors
# SPDX-License-Identifier: MIT

"""Build native executables in two fresh directories and compare their bytes."""

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import tomllib

BINARIES = ("cargo-contract", "cli", "daemon", "dns")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        choices=("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"),
    )
    parser.add_argument("--binaries-output", type=Path)
    options = parser.parse_args()
    root = Path.cwd().resolve()
    channel = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"][
        "channel"
    ]
    rustup = shutil.which("rustup")
    if rustup is None:
        raise SystemExit("rustup is required to resolve the pinned compiler")
    # Resolve absolute paths: a standalone Rust earlier in PATH must not compile
    # the binaries while a different rustup compiler supplies the reported version.
    cargo, rustc = (
        Path(
            subprocess.check_output(
                [rustup, "which", "--toolchain", channel, tool], text=True
            ).strip()
        ).resolve(strict=True)
        for tool in ("cargo", "rustc")
    )
    compiler_identity = subprocess.check_output(
        [str(rustc), "-Vv"], text=True
    ).strip()
    if not compiler_identity.startswith(f"rustc {channel} "):
        raise SystemExit("resolved compiler does not match rust-toolchain.toml")
    output = root / "target"
    output.mkdir(exist_ok=True)
    results = []
    verified_binaries = {}
    for _ in range(2):
        with tempfile.TemporaryDirectory(
            prefix="native-repro-", dir=output
        ) as directory:
            build = Path(directory)
            env = os.environ.copy()
            # The same normalized paths and linker policy apply to both builds.
            env.pop("RUSTFLAGS", None)
            env.pop("RUSTC_WRAPPER", None)
            env.pop("RUSTC_WORKSPACE_WRAPPER", None)
            env["RUSTC"] = str(rustc)
            env["RUSTUP_TOOLCHAIN"] = channel
            env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", "")
            flags = [
                f"--remap-path-prefix={root}=/astrolune",
                f"--remap-path-prefix={build}=/astrolune/target",
                "-Cstrip=debuginfo",
            ]
            if options.target.endswith("windows-msvc"):
                flags.append("-Clink-arg=/Brepro")
            env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
            env["CARGO_TARGET_DIR"] = str(build)
            env["CARGO_INCREMENTAL"] = "0"
            env["SOURCE_DATE_EPOCH"] = "0"
            subprocess.run(
                [
                    str(cargo),
                    "build",
                    "--locked",
                    "--workspace",
                    "--all-features",
                    "--release",
                    "--target",
                    options.target,
                ],
                env=env,
                check=True,
            )
            suffix = ".exe" if options.target.endswith("windows-msvc") else ""
            hashes = {}
            for name in BINARIES:
                binary = build / options.target / "release" / (name + suffix)
                with binary.open("rb") as stream:
                    hashes[name + suffix] = hashlib.file_digest(
                        stream, "sha256"
                    ).hexdigest()
                if options.binaries_output is not None and results:
                    verified_binaries[name + suffix] = binary.read_bytes()
            results.append(hashes)
    if results[0] != results[1]:
        raise SystemExit(
            "native reproducibility mismatch: " + json.dumps(results, indent=2)
        )
    if options.binaries_output is not None:
        options.binaries_output.mkdir(parents=True, exist_ok=True)
        for name, data in verified_binaries.items():
            binary = options.binaries_output / name
            binary.write_bytes(data)
            binary.chmod(0o755)
    report = {
        "target": options.target,
        "rustc": compiler_identity,
        "independent_builds": 2,
        "sha256": results[0],
    }
    (output / "native-reproducibility.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()