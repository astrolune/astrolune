# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Decide whether all four CI matrix legs of one revision ran a clean suite.

A missing leg is the failure this closes. Four uploaded results are the only
evidence that the suite ran everywhere, and three clean results look exactly
like four clean ones to anything that merely reads the files it was handed. The
expected leg set is therefore fixed here instead of being taken from the input,
and a comparison that cannot name every expected leg exactly once establishes
nothing.
"""

import argparse
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "suite", Path(__file__).with_name("suite-report.py")
)
SUITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUITE)

SCHEMA = "astrolune.suite-qualification/1"
LEG_SCHEMA = SUITE.SCHEMA
OPERATING_SYSTEMS = ("ubuntu-latest", "windows-latest")
PROFILES = ("dev", "release")
# The exact four legs `.github/workflows/ci.yml` declares. Deriving this set
# from the supplied files would make an absent leg unobservable.
EXPECTED_LEGS = tuple(
    f"{system}:{profile}" for system in OPERATING_SYSTEMS for profile in PROFILES
)
# Every emitted field a leg must carry before it can be counted at all.
REQUIRED = tuple(
    sorted(
        SUITE.COUNTS
        + (
            "exit_status",
            "failed_tests",
            "host",
            "operating_system",
            "outcome",
            "profile",
            "rustc",
            "schema",
            "suites",
        )
    )
)
# Each leg's own `rustc -Vv` host triple must match the platform it claims, so a
# result renamed or dropped into the wrong artefact directory cannot be counted
# as the leg its file name says it is.
HOST_TRIPLES = {
    "ubuntu-latest": "x86_64-unknown-linux-gnu",
    "windows-latest": "x86_64-pc-windows-msvc",
}
# Counts compared between the two legs of one profile.
COUNTED = ("passed", "suites")
# Both legs of one profile run the same commands over the same workspace, so
# their counts differ only by platform-gated tests. Five per cent of the larger
# leg allows that and still refuses a leg that ran a different test selection.
DRIFT_PERMILLE = 50
# Reported, but never a qualification failure on its own. `host` differs by
# platform by construction, and the release legs add a fifth `cargo test`
# invocation that filters one package down to its four ignored tests, so
# `ignored`, `measured` and `filtered_out` legitimately differ with the profile.
ADVISORY = ("filtered_out", "host", "ignored", "measured")
# Fields summed across the four legs and differenced between the two profiles.
TALLIED = tuple(sorted(SUITE.COUNTS + ("suites",)))


def leg(report):
    """Name one matrix leg the way `ci.yml` names its uploaded artefact."""
    return f"{report['operating_system']}:{report['profile']}"


def load(path):
    """Read one leg's result and refuse anything that is not this exact schema."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} is not a suite result")
    if document.get("schema") != LEG_SCHEMA:
        raise ValueError(
            f"{path.name} declares schema {document.get('schema')!r}, "
            f"this checker only compares {LEG_SCHEMA!r}"
        )
    missing = [field for field in REQUIRED if field not in document]
    if missing:
        raise ValueError(f"{path.name} omits required fields: " + ", ".join(missing))
    for field in SUITE.COUNTS + ("exit_status", "suites"):
        value = document[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{path.name} records a non-count {field}: {value!r}")
    if not isinstance(document["failed_tests"], list):
        raise ValueError(f"{path.name} does not record a list of failed tests")
    name = leg(document)
    if name not in EXPECTED_LEGS:
        raise ValueError(
            f"{path.name} reports leg {name!r}, which this matrix never runs; "
            "the declared legs are " + ", ".join(EXPECTED_LEGS)
        )
    expected_host = HOST_TRIPLES[document["operating_system"]]
    if document["host"] != expected_host:
        raise ValueError(
            f"{name} was produced by a {document['host']!r} compiler rather than "
            f"{expected_host!r}, so this result does not belong to that leg"
        )
    clean = document["failed"] == 0 and document["exit_status"] == 0
    if document["outcome"] != ("ok" if clean else "failed"):
        # A result whose outcome does not follow from its own counts has been
        # edited or truncated; counting it as a clean leg would establish nothing.
        raise ValueError(
            f"{name} declares outcome {document['outcome']!r} with "
            f"{document['failed']} failed and exit status {document['exit_status']}"
        )
    if (document["failed"] == 0) != (len(document["failed_tests"]) == 0):
        raise ValueError(
            f"{name} counts {document['failed']} failures and names "
            f"{len(document['failed_tests'])} of them"
        )
    return document


def collect(reports):
    """Index the supplied results by leg, refusing a duplicate or absent leg."""
    found = {}
    for report in reports:
        name = leg(report)
        if name in found:
            raise ValueError(
                f"leg {name} was supplied twice; one result per leg is the only "
                "way four files can describe four runs"
            )
        found[name] = report
    absent = [name for name in EXPECTED_LEGS if name not in found]
    if absent:
        raise ValueError(
            f"{len(absent)} of {len(EXPECTED_LEGS)} legs produced no result: "
            + ", ".join(absent)
        )
    return found


def drifts(found, failures):
    """Bound how far the two legs of one profile may disagree on their counts."""
    measured = {}
    for profile in PROFILES:
        group = [report for report in found.values() if report["profile"] == profile]
        measured[profile] = {}
        for field in COUNTED:
            values = sorted(report[field] for report in group)
            allowed = values[-1] * DRIFT_PERMILLE // 1000
            observed = values[-1] - values[0]
            measured[profile][field] = {
                "allowed": allowed,
                "largest": values[-1],
                "observed": observed,
                "smallest": values[0],
            }
            if values[0] == 0:
                failures.append(
                    f"a {profile} leg recorded zero {field}, so that leg "
                    "established no result"
                )
            elif observed > allowed:
                failures.append(
                    f"the two {profile} legs disagree on {field} by {observed}, "
                    f"above the {allowed} this matrix allows "
                    f"({values[0]} and {values[-1]})"
                )
    return measured


def compare(reports):
    """Name every leg that is absent, unclean, or inconsistent with the others."""
    found = collect(reports)
    failures = []
    for name in EXPECTED_LEGS:
        report = found[name]
        if report["outcome"] == "ok":
            continue
        failures.append(
            f"{name} failed {report['failed']} of "
            f"{report['passed'] + report['failed']} tests at exit status "
            f"{report['exit_status']}: "
            + ", ".join(report["failed_tests"] or ["no failure was named"])
        )
    identities = sorted({found[name]["rustc"] for name in EXPECTED_LEGS})
    if len(identities) > 1:
        failures.append(
            "the legs did not share one compiler identity, so they qualify no "
            "single toolchain: " + ", ".join(identities)
        )
    drift = drifts(found, failures)
    advisories = {}
    for field in ADVISORY:
        values = {name: found[name][field] for name in EXPECTED_LEGS}
        if len(set(values.values())) > 1:
            advisories[field] = values
    qualified = not failures
    return {
        "advisory_differences": advisories,
        "compared_legs": len(found),
        "count_drift": drift,
        "expected_legs": list(EXPECTED_LEGS),
        "failures": sorted(failures),
        "legs": {
            name: {
                field: found[name][field]
                for field in TALLIED
                + ("exit_status", "failed_tests", "host", "outcome")
            }
            for name in EXPECTED_LEGS
        },
        "profile_differences": {
            system: {
                field: found[f"{system}:release"][field] - found[f"{system}:dev"][field]
                for field in TALLIED
            }
            for system in OPERATING_SYSTEMS
        },
        "qualified": qualified,
        "rustc": identities[0] if len(identities) == 1 else None,
        "schema": SCHEMA,
        "totals": {
            field: sum(found[name][field] for name in EXPECTED_LEGS)
            for field in TALLIED
        },
        "verdict": (
            "all four legs ran clean under one compiler"
            if qualified
            else "four-leg suite qualification refused"
        ),
    }


def write(path, document):
    """Sorted keys and a fixed newline keep qualification verdicts byte-comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def discover(root):
    """List one result per downloaded `suite-<os>-<profile>` directory."""
    return sorted(root.glob("*/SUITE.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="*", type=Path)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=None,
        help="directory holding the downloaded suite-<os>-<profile> directories",
    )
    parser.add_argument("--output", type=Path, default=None)
    options = parser.parse_args()
    paths = list(options.results)
    if options.artifact_root is not None:
        paths.extend(discover(options.artifact_root))
    if not paths:
        parser.error("pass one SUITE.json per leg, or --artifact-root")
    try:
        verdict = compare([load(path) for path in paths])
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(f"suite qualification failed: {error}")
    if options.output is not None:
        write(options.output, verdict)
    print(json.dumps(verdict, indent=2, sort_keys=True))
    if not verdict["qualified"]:
        raise SystemExit(
            "four-leg suite qualification refused: " + "; ".join(verdict["failures"])
        )


if __name__ == "__main__":
    main()
