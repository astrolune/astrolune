# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Compose a stable-schema platform qualification report from build evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

SCHEMA = "astrolune.platform-qualification/1"
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
# Fields two builds of the same revision must match byte for byte, whatever host
# produced them. `rustc`, `host` and `machine` are reported and compared
# separately so a cross-host comparison stays distinguishable from a real
# reproducibility failure.
COMPARABLE = (
    "archive",
    "archive_sha256",
    "binaries",
    "features",
    "files",
    "independent_builds",
    "profile",
    "release_intent",
    "revision",
    "schema",
    "source_date_epoch",
    "target",
)


def compiler_identity(verbose):
    """Split a `rustc -Vv` block into its version line and its host triple."""
    lines = [line.strip() for line in verbose.strip().splitlines() if line.strip()]
    if not lines or not lines[0].startswith("rustc "):
        raise ValueError("build evidence carries no `rustc -Vv` version line")
    host = next(
        (line.split(":", 1)[1].strip() for line in lines if line.startswith("host:")),
        None,
    )
    if not host:
        raise ValueError("build evidence carries no rustc host triple")
    return lines[0], host


def checksum_entry(text, archive):
    """Read the single archive digest a SHA256SUMS file records."""
    rows = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if len(rows) != 1:
        raise ValueError(f"expected exactly one SHA256SUMS entry, found {len(rows)}")
    match = re.fullmatch(r"([0-9a-f]{64})\s+(\S+)", rows[0].strip())
    if match is None:
        raise ValueError(f"unparsable SHA256SUMS entry: {rows[0]!r}")
    if match.group(2) != archive:
        raise ValueError(
            f"SHA256SUMS names {match.group(2)}, the manifest names {archive}"
        )
    return match.group(1)


def qualify(build_report, manifest, checksums, machine, minimum_builds=2):
    """Cross-check the two build artefacts and emit one comparable record."""
    target = manifest.get("target")
    if target not in TARGETS:
        raise ValueError(f"unsupported native target: {target!r}")
    if build_report.get("target") != target:
        raise ValueError("build report and manifest describe different targets")
    if build_report.get("rustc") != manifest.get("rustc"):
        raise ValueError("build report and manifest record different compilers")
    builds = build_report.get("independent_builds")
    if not isinstance(builds, int) or builds < minimum_builds:
        raise ValueError(
            f"build report claims {builds} independent builds, "
            f"at least {minimum_builds} are required"
        )
    binaries = build_report.get("sha256")
    if not isinstance(binaries, dict) or not binaries:
        raise ValueError("build report records no binary digests")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("manifest records no packaged files")
    for name, value in sorted(binaries.items()):
        if files.get(name) != value:
            # The packaged bytes must be the bytes reproducibility was proven on.
            raise ValueError(f"packaged {name} is not the independently rebuilt binary")
    archive = manifest.get("archive")
    digest = checksum_entry(checksums, archive)
    if digest != manifest.get("archive_sha256"):
        raise ValueError("SHA256SUMS and the manifest disagree on the archive digest")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(manifest.get("revision"))):
        raise ValueError("manifest revision is not a full lowercase commit hash")
    if not machine:
        raise ValueError("a machine identity is required to compare independent runs")
    version, host = compiler_identity(manifest["rustc"])
    report = {
        "archive": archive,
        "archive_sha256": digest,
        "binaries": dict(sorted(binaries.items())),
        "features": manifest.get("features"),
        "files": dict(sorted(files.items())),
        "host": host,
        "independent_builds": builds,
        "machine": machine,
        "profile": manifest.get("profile"),
        "release_intent": bool(manifest.get("release", False)),
        "revision": manifest["revision"],
        "rustc": version,
        "schema": SCHEMA,
        "source_date_epoch": manifest.get("source_date_epoch"),
        "target": target,
    }
    report["reproducibility_digest"] = comparable_digest(report)
    return report


def comparable_digest(report):
    """Reduce the host-independent fields to one value two runs can compare."""
    missing = [field for field in COMPARABLE if field not in report]
    if missing:
        raise ValueError("report is missing comparable fields: " + ", ".join(missing))
    body = json.dumps(
        {field: report[field] for field in COMPARABLE},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def write(path, document):
    """Sorted keys and a fixed newline keep uploaded reports byte-comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-report",
        type=Path,
        default=Path("target/native-reproducibility.json"),
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("target/ci-artifacts/MANIFEST.json")
    )
    parser.add_argument(
        "--checksums", type=Path, default=Path("target/ci-artifacts/SHA256SUMS")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("target/ci-artifacts/QUALIFICATION.json")
    )
    parser.add_argument(
        "--machine",
        default=os.environ.get("ASTROLUNE_MACHINE"),
        help="identity of the machine that produced this evidence",
    )
    options = parser.parse_args()
    machine = options.machine
    if not machine:
        runner, run = os.environ.get("RUNNER_NAME"), os.environ.get("GITHUB_RUN_ID")
        machine = f"{runner}#{run}" if runner and run else None
    if not machine:
        parser.error("pass --machine or set ASTROLUNE_MACHINE")
    try:
        report = qualify(
            json.loads(options.build_report.read_text(encoding="utf-8")),
            json.loads(options.manifest.read_text(encoding="utf-8")),
            options.checksums.read_text(encoding="utf-8"),
            machine,
        )
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(f"platform qualification report failed: {error}")
    write(options.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
