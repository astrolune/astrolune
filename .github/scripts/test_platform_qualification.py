# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Platform qualification schema, cross-check and independent-run agreement tests."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name, module):
    spec = importlib.util.spec_from_file_location(
        module, Path(__file__).with_name(name)
    )
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


REPORTER = load("qualification-report.py", "qualification")
COMPARER = load("compare-qualification.py", "comparison")

RUSTC = (
    "rustc 1.99.0 (b940084d7 2026-09-28)\n"
    "binary: rustc\n"
    "commit-hash: b940084d7\n"
    "commit-date: 2026-09-28\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.99.0\n"
)
BINARIES = {"cargo-contract": "a" * 64, "cli": "b" * 64, "daemon": "c" * 64, "dns": "d" * 64}
ARCHIVE = "astrolune-x86_64-unknown-linux-gnu.tar.gz"
BUILD_REPORT = {
    "target": "x86_64-unknown-linux-gnu",
    "rustc": RUSTC,
    "independent_builds": 2,
    "sha256": BINARIES,
}
MANIFEST = {
    "archive": ARCHIVE,
    "archive_sha256": "e" * 64,
    "features": "all",
    "files": dict(BINARIES, **{"Cargo.lock": "f" * 64, "LICENSE": "0" * 64}),
    "profile": "release",
    "release": False,
    "revision": "1" * 40,
    "rustc": RUSTC,
    "source_date_epoch": 0,
    "target": "x86_64-unknown-linux-gnu",
}
CHECKSUMS = f"{'e' * 64}  {ARCHIVE}\n"


def report(machine="runner-a#1", **overrides):
    manifest = dict(MANIFEST, **overrides.pop("manifest", {}))
    build = dict(BUILD_REPORT, **overrides.pop("build", {}))
    return REPORTER.qualify(build, manifest, overrides.pop("checksums", CHECKSUMS), machine)


class ReportTests(unittest.TestCase):
    def test_a_report_records_the_schema_and_a_digest_of_its_own_fields(self):
        document = report()
        self.assertEqual(document["schema"], REPORTER.SCHEMA)
        self.assertEqual(document["host"], "x86_64-unknown-linux-gnu")
        self.assertEqual(document["rustc"], "rustc 1.99.0 (b940084d7 2026-09-28)")
        self.assertEqual(document["archive_sha256"], "e" * 64)
        self.assertEqual(document["independent_builds"], 2)
        self.assertFalse(document["release_intent"])
        self.assertEqual(
            document["reproducibility_digest"], REPORTER.comparable_digest(document)
        )
        # The machine identity must never enter the comparable digest.
        self.assertNotIn("machine", REPORTER.COMPARABLE)
        self.assertEqual(
            document["reproducibility_digest"],
            report(machine="runner-b#2")["reproducibility_digest"],
        )

    def test_two_runs_over_the_same_evidence_produce_identical_report_bytes(self):
        first, second = report(), report()
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )

    def test_packaged_bytes_must_be_the_independently_rebuilt_bytes(self):
        with self.assertRaises(ValueError) as caught:
            report(manifest={"files": dict(MANIFEST["files"], cli="9" * 64)})
        self.assertIn("independently rebuilt", str(caught.exception))

    def test_inconsistent_build_evidence_is_refused(self):
        cases = {
            "different targets": {"build": {"target": "x86_64-pc-windows-msvc"}},
            "different compilers": {"build": {"rustc": RUSTC + "extra: 1\n"}},
            "independent builds": {"build": {"independent_builds": 1}},
            "no binary digests": {"build": {"sha256": {}}},
            "no packaged files": {"manifest": {"files": {}}},
            "archive digest": {"checksums": f"{'9' * 64}  {ARCHIVE}\n"},
            "archive name": {"checksums": f"{'e' * 64}  other.tar.gz\n"},
            "commit hash": {"manifest": {"revision": "not-a-hash"}},
            "unsupported target": {
                "build": {"target": "mips-unknown-none"},
                "manifest": {"target": "mips-unknown-none"},
            },
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    report(**overrides)
        with self.assertRaises(ValueError):
            report(machine="")

    def test_a_checksum_file_must_carry_exactly_one_parsable_entry(self):
        for text in ("", f"{'e' * 64}  {ARCHIVE}\n{'e' * 64}  b\n", "garbage\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    REPORTER.checksum_entry(text, ARCHIVE)

    def test_a_compiler_block_without_a_host_triple_is_refused(self):
        for text in ("", "rustc 1.99.0\nbinary: rustc\n", "host: x\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    REPORTER.compiler_identity(text)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def store(self, name, document):
        path = self.root / name
        REPORTER.write(path, document)
        return path

    def test_two_machines_that_built_the_same_bytes_agree(self):
        verdict = COMPARER.compare([report("runner-a#1"), report("runner-b#2")])
        self.assertTrue(verdict["agree"])
        self.assertEqual(verdict["verdict"], "independent runs agree")
        self.assertEqual(verdict["compared_reports"], 2)
        self.assertEqual(verdict["distinct_machines"], 2)
        self.assertEqual(verdict["disagreements"], {})
        self.assertEqual(verdict["advisory_differences"], {})
        self.assertEqual(len(verdict["reproducibility_digests"]), 1)
        self.assertEqual(verdict["revision"], "1" * 40)

    def test_more_than_two_reports_are_compared_together(self):
        verdict = COMPARER.compare(
            [report("a#1"), report("b#2"), report("c#3")]
        )
        self.assertTrue(verdict["agree"])
        self.assertEqual(verdict["compared_reports"], 3)
        self.assertEqual(verdict["distinct_machines"], 3)

    def test_a_single_differing_binary_is_named_as_a_disagreement(self):
        other = report(
            "runner-b#2",
            build={"sha256": dict(BINARIES, cli="9" * 64)},
            manifest={"files": dict(MANIFEST["files"], cli="9" * 64)},
        )
        verdict = COMPARER.compare([report("runner-a#1"), other])
        self.assertFalse(verdict["agree"])
        self.assertEqual(verdict["verdict"], "independent runs disagree")
        self.assertEqual(sorted(verdict["disagreements"]), ["binaries", "files"])
        self.assertEqual(len(verdict["reproducibility_digests"]), 2)
        self.assertIsNone(verdict["revision"])

    def test_a_differing_archive_digest_or_revision_is_a_disagreement(self):
        for overrides, field in (
            ({"manifest": {"archive_sha256": "9" * 64}, "checksums": f"{'9' * 64}  {ARCHIVE}\n"}, "archive_sha256"),
            ({"manifest": {"revision": "2" * 40}}, "revision"),
            ({"manifest": {"release": True}}, "release_intent"),
            ({"manifest": {"source_date_epoch": 1}}, "source_date_epoch"),
        ):
            with self.subTest(field=field):
                verdict = COMPARER.compare(
                    [report("a#1"), report("b#2", **overrides)]
                )
                self.assertFalse(verdict["agree"])
                self.assertIn(field, verdict["disagreements"])

    def test_a_different_host_is_advisory_rather_than_a_reproducibility_failure(self):
        cross = RUSTC.replace("host: x86_64-unknown-linux-gnu", "host: aarch64-apple-darwin")
        verdict = COMPARER.compare(
            [
                report("a#1"),
                report("b#2", build={"rustc": cross}, manifest={"rustc": cross}),
            ]
        )
        self.assertTrue(verdict["agree"])
        self.assertEqual(
            verdict["advisory_differences"]["host"],
            ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"],
        )

    def test_comparing_one_report_or_two_targets_establishes_nothing(self):
        with self.assertRaises(ValueError):
            COMPARER.compare([report()])
        windows = dict(MANIFEST, target="x86_64-pc-windows-msvc")
        windows["archive"] = "astrolune-x86_64-pc-windows-msvc.tar.gz"
        other = REPORTER.qualify(
            dict(BUILD_REPORT, target="x86_64-pc-windows-msvc"),
            windows,
            f"{'e' * 64}  {windows['archive']}\n",
            "b#2",
        )
        with self.assertRaises(ValueError) as caught:
            COMPARER.compare([report("a#1"), other])
        self.assertIn("different targets", str(caught.exception))

    def test_one_machine_cannot_supply_independent_machine_evidence(self):
        with self.assertRaises(ValueError) as caught:
            COMPARER.compare([report("runner-a#1"), report("runner-a#1")])
        self.assertIn("distinct machines", str(caught.exception))
        verdict = COMPARER.compare(
            [report("runner-a#1"), report("runner-a#1")],
            require_distinct_machines=False,
        )
        self.assertTrue(verdict["agree"])
        self.assertEqual(verdict["distinct_machines"], 1)

    def test_a_foreign_schema_or_edited_report_is_refused(self):
        self.assertEqual(
            COMPARER.load(self.store("good.json", report()))["schema"], REPORTER.SCHEMA
        )
        for name, document in (
            ("old.json", dict(report(), schema="astrolune.platform-qualification/0")),
            ("bare.json", {"target": "x86_64-unknown-linux-gnu"}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    COMPARER.load(self.store(name, document))
        # A field edited after the fact must not survive the digest re-check.
        edited = report()
        edited["archive_sha256"] = "9" * 64
        with self.assertRaises(ValueError) as caught:
            COMPARER.load(self.store("edited.json", edited))
        self.assertIn("digest its own fields do not produce", str(caught.exception))

    def test_two_comparisons_over_the_same_reports_produce_identical_bytes(self):
        reports = [report("a#1"), report("b#2")]
        first, second = COMPARER.compare(reports), COMPARER.compare(reports)
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
