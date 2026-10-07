# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Deterministically package native binaries; no signing or publication occurs."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile

TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
BINARIES = ("cargo-contract", "cli", "daemon", "dns")


def package(
    root,
    binaries,
    output,
    target,
    revision,
    compiler,
    epoch=0,
    qualification=None,
):
    """Equal file bytes and explicit build identity produce equal archive bytes."""
    if target not in TARGETS:
        raise ValueError("unsupported native target")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("revision must be a full lowercase commit hash")
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH must fit the gzip timestamp")
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    entries = {
        name + suffix: (binaries / (name + suffix), 0o755) for name in BINARIES
    }
    for name in ("LICENSE", "README.md", "Cargo.lock", "rust-toolchain.toml"):
        entries[name] = (root / name, 0o644)
    for path in sorted((root / "docs").rglob("*")):
        if path.is_file() and path.suffix in (".md", ".png"):
            entries[path.relative_to(root).as_posix()] = (path, 0o644)
    payloads = {}
    for name, (path, mode) in sorted(entries.items()):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or linked input: {name}")
        payloads[name] = (path.read_bytes(), mode)
    if qualification is not None:
        expected = {
            name + suffix: hashlib.sha256(payloads[name + suffix][0]).hexdigest()
            for name in BINARIES
        }
        if (
            qualification.get("target") != target
            or qualification.get("independent_builds") != 2
            or qualification.get("sha256") != expected
            or qualification.get("rustc") != compiler.strip()
        ):
            raise ValueError(
                "build report does not qualify these exact binaries and compiler"
            )
    metadata = {
        "revision": revision,
        "target": target,
        "rustc": compiler.strip(),
        "profile": "release",
        "features": "all",
        "release": False,
        "source_date_epoch": epoch,
        "files": {
            name: hashlib.sha256(data).hexdigest()
            for name, (data, _) in sorted(payloads.items())
        },
    }
    payloads["BUILD.json"] = (
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode(),
        0o644,
    )
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"astrolune-{target}.tar.gz"
    # Never inherit host timestamps, usernames, permissions or temporary names.
    with tempfile.NamedTemporaryFile(dir=output, delete=False) as temporary:
        pending = Path(temporary.name)
    try:
        with pending.open("wb") as stream:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=stream, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as bundle:
                    for name, (data, mode) in sorted(payloads.items()):
                        info = tarfile.TarInfo(name)
                        info.size, info.mode, info.mtime = len(data), mode, epoch
                        bundle.addfile(info, io.BytesIO(data))
            stream.flush()
            os.fsync(stream.fileno())
        with pending.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        os.replace(pending, archive)
    finally:
        pending.unlink(missing_ok=True)
    (output / "SHA256SUMS").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n"
    )
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("--binaries", type=Path)
    parser.add_argument("--output", type=Path, default=Path("target/ci-artifacts"))
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument(
        "--build-report",
        type=Path,
        default=Path("target/native-reproducibility.json"),
    )
    options = parser.parse_args()
    if options.revision is None:
        parser.error("pass --revision or set GITHUB_SHA")
    qualification = json.loads(options.build_report.read_text(encoding="utf-8"))
    package(
        Path.cwd(),
        options.binaries or Path("target") / options.target / "release",
        options.output,
        options.target,
        options.revision,
        qualification["rustc"],
        int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        qualification,
    )


if __name__ == "__main__":
    main()