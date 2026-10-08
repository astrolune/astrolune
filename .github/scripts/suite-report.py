# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Record a deterministic per-platform suite result from cargo test output."""

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

SCHEMA = "astrolune.suite-result/1"
# libtest prints one of these per test binary and per documentation-test run.
SUMMARY = re.compile(
    r"^test result: (?P<outcome>\w+)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered_out>\d+) filtered out"
)
FAILED = re.compile(r"^test (?P<name>.+?) \.\.\. FAILED\s*$")
COUNTS = ("passed", "failed", "ignored", "measured", "filtered_out")


def summarise(log, operating_system, profile, verbose, exit_status):
    """Total every libtest summary in a captured log; an absent one raises."""
    totals = dict.fromkeys(COUNTS, 0)
    suites, failed_tests = 0, set()
    for line in log.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        match = SUMMARY.match(line)
        if match is not None:
            suites += 1
            for field in COUNTS:
                totals[field] += int(match.group(field))
            continue
        failure = FAILED.match(line)
        if failure is not None:
            failed_tests.add(failure.group("name"))
    if suites == 0:
        # A log with no summary means the suite never ran to a verdict, which
        # must never be recorded as a passing platform.
        raise ValueError("no libtest summary in the log; no suite result is established")
    version, host = QUALIFICATION.compiler_identity(verbose)
    # Timings are deliberately excluded: this record must be byte-identical for
    # two runs of the same revision on the same platform.
    report = {
        "exit_status": int(exit_status),
        "failed_tests": sorted(failed_tests),
        "host": host,
        "operating_system": operating_system,
        "outcome": "ok" if totals["failed"] == 0 and int(exit_status) == 0 else "failed",
        "profile": profile,
        "rustc": version,
        "schema": SCHEMA,
        "suites": suites,
        **totals,
    }
    if totals["failed"] and not failed_tests:
        report["failed_tests"] = ["<names absent from the captured log>"]
    return report


def write(path, document):
    """Sorted keys and a fixed newline keep uploaded results byte-comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, action="append", required=True)
    parser.add_argument("--os", dest="operating_system", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--exit-status", type=int, default=0)
    parser.add_argument("--rustc-verbose", type=Path, default=None)
    parser.add_argument(
        "--output", type=Path, default=Path("target/ci-artifacts/SUITE.json")
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
            options.profile,
            verbose,
            options.exit_status,
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"suite result record failed: {error}")
    write(options.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["outcome"] != "ok":
        raise SystemExit(
            f"{report['failed']} of {report['passed'] + report['failed']} tests failed "
            f"on {report['operating_system']} ({report['profile']})"
        )


if __name__ == "__main__":
    main()
