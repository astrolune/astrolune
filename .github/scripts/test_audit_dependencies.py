# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Bounded advisory lookup, offline snapshot and report determinism regression tests."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "advisories", Path(__file__).with_name("audit-dependencies.py")
)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)

ROOT = Path(__file__).resolve().parents[2]
LOCK = """\
version = 4

[[package]]
name = "types"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "time"
version = "0.1.44"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


class Response:
    def __init__(self, payload, status=200):
        self.payload, self.status = payload, status

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def responder(vulnerabilities):
    """Answer every batch with per-package advisory identifiers from a mapping."""

    def send(request, timeout=None):
        queries = json.loads(request.data)["queries"]
        results = []
        for entry in queries:
            key = f"{entry['package']['name']} {entry['version']}"
            identifiers = vulnerabilities.get(key, [])
            results.append(
                {"vulns": [{"id": i} for i in identifiers]} if identifiers else {}
            )
        return Response({"results": results})

    return send


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "Cargo.lock").write_text(LOCK, encoding="utf-8")
        self.addCleanup(self.directory.cleanup)
        self.canary = f"{AUDIT.CANARY[0]} {AUDIT.CANARY[1]}"

    def test_only_registry_packages_are_counted_and_digested(self):
        scope, packages = AUDIT.registry_packages(self.root, ("Cargo.lock",))
        self.assertEqual(packages, [("serde", "1.0.229"), ("time", "0.1.44")])
        self.assertEqual(
            scope["Cargo.lock"],
            {
                "packages_digest": AUDIT.digest(packages),
                "registry_packages": 2,
                "total_packages": 3,
            },
        )
        self.assertEqual(AUDIT.digest(packages), AUDIT.digest(reversed(packages)))
        self.assertNotEqual(AUDIT.digest(packages), AUDIT.digest(packages[:1]))
        with self.assertRaises(ValueError):
            AUDIT.registry_packages(self.root, ("Cargo.lock", "absent/Cargo.lock"))

    def test_request_cap_timeout_and_transport_failure_never_report_clean(self):
        packages = [("crate-%d" % index, "1.0.0") for index in range(10)]
        with mock.patch("urllib.request.urlopen", responder({})):
            with self.assertRaises(ValueError):
                AUDIT.query(packages, 5.0, 2, 4)
            found, requests = AUDIT.query(packages, 5.0, 2, 5)
            self.assertEqual((found, requests), ({}, 5))
        for failure in (TimeoutError("timed out"), OSError("network unreachable")):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch("urllib.request.urlopen", side_effect=failure):
                    with self.assertRaises(ValueError) as caught:
                        AUDIT.audit(self.root, ("Cargo.lock",))
                self.assertIn("no result is established", str(caught.exception))
        with mock.patch("urllib.request.urlopen", lambda *_, **__: Response({}, 503)):
            with self.assertRaises(ValueError):
                AUDIT.query([("serde", "1.0.229")], 5.0, 1, 1)

    def test_a_silent_database_fails_the_canary_before_any_package_is_cleared(self):
        with mock.patch("urllib.request.urlopen", responder({})):
            with self.assertRaises(ValueError) as caught:
                AUDIT.audit(self.root, ("Cargo.lock",))
        self.assertIn("not trustworthy", str(caught.exception))

    def test_live_query_records_advisories_and_bounded_request_accounting(self):
        advisories = {
            self.canary: ["RUSTSEC-2020-0071"],
            "time 0.1.44": ["RUSTSEC-2020-0071", "GHSA-wcg3-cvx6-7396"],
        }
        with mock.patch("urllib.request.urlopen", responder(advisories)):
            report, packages = AUDIT.audit(self.root, ("Cargo.lock",), batch_size=64)
        self.assertEqual(report["determination"], "queried live")
        self.assertEqual(report["requests"], 2)
        self.assertEqual(report["unique_registry_packages"], 2)
        self.assertEqual(report["vulnerable_packages"], 1)
        self.assertEqual(report["advisory_count"], 2)
        self.assertEqual(
            report["advisories"],
            {"time 0.1.44": ["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"]},
        )
        document = AUDIT.snapshot_document(report, packages, "2026-10-07")
        self.assertEqual(document["packages_digest"], report["packages_digest"])
        self.assertEqual(document["packages"], ["serde 1.0.229", "time 0.1.44"])

    def test_offline_mode_requires_a_snapshot_covering_these_exact_packages(self):
        snapshot = self.root / "snapshot.json"
        with self.assertRaises(ValueError) as caught:
            AUDIT.audit(self.root, ("Cargo.lock",), offline=True, snapshot_path=snapshot)
        self.assertIn("committed advisory snapshot", str(caught.exception))
        with mock.patch(
            "urllib.request.urlopen", responder({self.canary: ["RUSTSEC-2020-0071"]})
        ):
            live, packages = AUDIT.audit(self.root, ("Cargo.lock",))
        AUDIT.write(snapshot, AUDIT.snapshot_document(live, packages, "2026-10-07"))
        offline, _ = AUDIT.audit(
            self.root, ("Cargo.lock",), offline=True, snapshot_path=snapshot
        )
        self.assertEqual(offline["determination"], "verified against pinned snapshot")
        self.assertEqual(offline["requests"], 0)
        self.assertEqual(offline["snapshot_queried_on"], "2026-10-07")
        self.assertEqual(offline["advisories"], live["advisories"])
        self.assertEqual(offline["packages_digest"], live["packages_digest"])
        repeated, _ = AUDIT.audit(
            self.root, ("Cargo.lock",), offline=True, snapshot_path=snapshot
        )
        self.assertEqual(
            json.dumps(offline, indent=2, sort_keys=True),
            json.dumps(repeated, indent=2, sort_keys=True),
        )
        # A changed lockfile must invalidate the pin instead of reusing its verdict.
        (self.root / "Cargo.lock").write_text(
            LOCK + '\n[[package]]\nname = "ring"\nversion = "0.16.20"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError) as caught:
            AUDIT.audit(self.root, ("Cargo.lock",), offline=True, snapshot_path=snapshot)
        self.assertIn("exact locked packages", str(caught.exception))
        with self.assertRaises(ValueError):
            AUDIT.snapshot_document(offline, packages, "2026-10-07")

    def test_committed_snapshot_covers_both_repository_lockfiles(self):
        snapshot = Path(AUDIT.__file__).with_name("advisory-snapshot.json")
        report, _ = AUDIT.audit(ROOT, offline=True, snapshot_path=snapshot)
        self.assertEqual(report["scope"], list(AUDIT.LOCKFILES))
        self.assertEqual(report["advisories"], {})
        self.assertEqual(report["requests"], 0)
        self.assertGreater(report["unique_registry_packages"], 0)
        self.assertEqual(
            report["unique_registry_packages"],
            len(json.loads(snapshot.read_text(encoding="utf-8"))["packages"]),
        )


if __name__ == "__main__":
    unittest.main()
