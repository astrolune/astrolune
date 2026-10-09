# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Collect per-platform benchmark measurements from cargo bench output.

Unlike the suite result, this record carries timings, so two runs of the same
revision do not produce identical bytes. A shared hosted runner cannot establish
a comparable figure at all; the record exists to prove every benchmark executed
and to retain what it measured.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location(
    "qualification", Path(__file__).with_name("qualification-report.py")
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)

SCHEMA = "astrolune.benchmark-report/1"
MEASURED_SCHEMA = "astrolune.benchmark/1"
# `testkit::bench::Suite::report` prints exactly one of these per suite.
RECORD = re.compile(r'^\{"schema":"' + re.escape(MEASURED_SCHEMA) + r'".*\}$')
# Each `[[bench]]` target produces one suite, so the declared count is the
# expected count. Matching by name would be wrong: a target may name its suite
# differently, as `benches/potb.rs` reports `consensus-potb`.
BENCH_TARGET = re.compile(r"^\s*\[\[bench\]\]\s*$")


def declared_targets(root):
    """Counts `[[bench]]` targets per manifest, so a skipped suite is visible."""
    declared = {}
    for manifest in sorted(Path(root).glob("*/*/Cargo.toml")):
        targets = sum(
            1
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if BENCH_TARGET.match(line)
        )
        if targets:
            declared[manifest.parent.name] = targets
    return declared


def measurements(log):
    """Parses every emitted suite record, rejecting a malformed one loudly."""
    found = []
    for line in log.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if RECORD.match(line) is None:
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"a suite printed an unparsable record: {error}")
        if document.get("schema") != MEASURED_SCHEMA:
            raise ValueError(f"unexpected record schema: {document.get('schema')}")
        for field in ("suite", "measurements"):
            if field not in document:
                raise ValueError(f"a suite record is missing {field!r}")
        found.append(document)
    return found


def summarise(log, operating_system, verbose, exit_status, declared):
    """Builds the record; a missing or empty suite is a failure, not a gap."""
    found = measurements(log)
    if not found:
        raise ValueError("no benchmark record in the log; no suite is established")
    expected = sum(declared.values())
    empty = sorted(
        document["suite"] for document in found if not document["measurements"]
    )
    if empty:
        raise ValueError(f"suites reported no measurement: {', '.join(empty)}")
    version, host = QUALIFICATION.compiler_identity(verbose)
    outcome = "ok" if len(found) == expected and int(exit_status) == 0 else "failed"
    return {
        # Timings make this record non-reproducible by construction, and a
        # shared runner makes it incomparable. Both are stated in the record so
        # a consumer cannot mistake it for a bound.
        "comparability": "none: shared hosted runner, timings not reproducible",
        "declared_targets": dict(sorted(declared.items())),
        "exit_status": int(exit_status),
        "expected_suites": expected,
        "host": host,
        "measurements": sum(len(document["measurements"]) for document in found),
        "operating_system": operating_system,
        "outcome": outcome,
        "results": sorted(found, key=lambda document: document["suite"]),
        "rustc": version,
        "schema": SCHEMA,
        "suites": sorted(document["suite"] for document in found),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, action="append", required=True)
    parser.add_argument("--os", dest="operating_system", required=True)
    parser.add_argument("--exit-status", type=int, default=0)
    parser.add_argument("--rustc-verbose", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--output", type=Path, default=Path("target/bench/BENCHMARKS.json")
    )
    options = parser.parse_args()
    try:
        if options.rustc_verbose is not None:
            verbose = options.rustc_verbose.read_text(encoding="utf-8")
        else:
            verbose = subprocess.check_output(["rustc", "-Vv"], text=True)
        report = summarise(
            "\n".join(path.read_text(encoding="utf-8") for path in options.log),
            options.operating_system,
            verbose,
            options.exit_status,
            declared_targets(options.root),
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"benchmark record failed: {error}")
    QUALIFICATION.write(options.output, report)
    print(
        f"{len(report['suites'])} of {report['expected_suites']} benchmark suites "
        f"recorded {report['measurements']} measurements on "
        f"{report['operating_system']}"
    )
    if report["outcome"] != "ok":
        missing = report["expected_suites"] - len(report["suites"])
        raise SystemExit(
            f"benchmarks did not complete on {report['operating_system']}: "
            f"{missing} suite(s) absent, exit status {report['exit_status']}"
        )


if __name__ == "__main__":
    main()
