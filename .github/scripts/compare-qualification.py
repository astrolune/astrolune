# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Decide whether platform qualification reports from independent runs agree."""

import argparse
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "qualification", Path(__file__).with_name("qualification-report.py")
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)

SCHEMA = QUALIFICATION.SCHEMA
COMPARABLE = QUALIFICATION.COMPARABLE
# Reported, but never a reproducibility failure on its own: a cross-compiled
# build may legitimately come from a different host triple.
ADVISORY = ("host", "rustc")


def load(path):
    """Read one report and refuse anything that is not this exact schema."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} is not a qualification report")
    if document.get("schema") != SCHEMA:
        raise ValueError(
            f"{path.name} declares schema {document.get('schema')!r}, "
            f"this checker only compares {SCHEMA!r}"
        )
    recomputed = QUALIFICATION.comparable_digest(document)
    if document.get("reproducibility_digest") != recomputed:
        # A report whose own digest does not match its own fields has been
        # edited or truncated; comparing it would establish nothing.
        raise ValueError(f"{path.name} carries a digest its own fields do not produce")
    return document


def compare(reports, require_distinct_machines=True):
    """Report every field on which two or more runs of one target disagree."""
    if len(reports) < 2:
        raise ValueError("comparing independent runs needs at least two reports")
    targets = sorted({report["target"] for report in reports})
    if len(targets) != 1:
        raise ValueError(
            "reports describe different targets, which can never share bytes: "
            + ", ".join(targets)
        )
    machines = sorted({report["machine"] for report in reports})
    if require_distinct_machines and len(machines) != len(reports):
        raise ValueError(
            "reports do not come from distinct machines, so they establish "
            "nothing about independent-machine reproducibility: " + ", ".join(machines)
        )
    disagreements, advisories = {}, {}
    for field in COMPARABLE:
        values = sorted({json.dumps(report[field], sort_keys=True) for report in reports})
        if len(values) > 1:
            disagreements[field] = [json.loads(value) for value in values]
    for field in ADVISORY:
        values = sorted({str(report.get(field)) for report in reports})
        if len(values) > 1:
            advisories[field] = values
    digests = sorted({report["reproducibility_digest"] for report in reports})
    agree = not disagreements
    if agree != (len(digests) == 1):
        raise ValueError("field comparison and digest comparison disagree")
    return {
        "advisory_differences": advisories,
        "agree": agree,
        "compared_reports": len(reports),
        "disagreements": disagreements,
        "distinct_machines": len(machines),
        "machines": machines,
        "reproducibility_digests": digests,
        "revision": reports[0]["revision"] if agree else None,
        "schema": SCHEMA,
        "target": targets[0],
        "verdict": "independent runs agree" if agree else "independent runs disagree",
    }


def write(path, document):
    """Sorted keys and a fixed newline keep comparison verdicts byte-comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument(
        "--allow-same-machine",
        action="store_true",
        help="compare reports without requiring distinct machine identities",
    )
    parser.add_argument("--output", type=Path, default=None)
    options = parser.parse_args()
    try:
        verdict = compare(
            [load(path) for path in options.reports],
            not options.allow_same_machine,
        )
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(f"qualification comparison failed: {error}")
    if options.output is not None:
        write(options.output, verdict)
    print(json.dumps(verdict, indent=2, sort_keys=True))
    if not verdict["agree"]:
        raise SystemExit(
            f"{verdict['target']} is not reproducible across "
            f"{verdict['compared_reports']} runs: "
            + ", ".join(sorted(verdict["disagreements"]))
        )


if __name__ == "__main__":
    main()
