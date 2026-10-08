# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""SPDX evaluation, full-lockfile licence coverage and gap-bound regression tests."""

import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "coverage", Path(__file__).with_name("check-license-coverage.py")
)
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)

ROOT = Path(__file__).resolve().parents[2]
ALLOW = frozenset(
    ("Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "Unicode-3.0", "Zlib")
)
CONFIG = """\
[licenses]
version = 2
allow = ["Apache-2.0", "ISC", "MIT"]
"""
# One graph crate, one dev-dependency cargo-deny prunes, one disabled optional
# dependency, and a second version of a graph crate that only the lockfile holds.
METADATA = {
    "packages": [
        {"name": "graphed", "version": "1.0.0", "license": "MIT", "source": "registry+x"},
        {"name": "graphed", "version": "2.0.0", "license": "ISC", "source": "registry+x"},
        {"name": "devonly", "version": "0.3.0", "license": "MIT/Apache-2.0", "source": "registry+x"},
        {"name": "optional", "version": "0.1.0", "license": "GPL-3.0-only", "source": "registry+x"},
        {"name": "member", "version": "0.1.0", "license": "MIT", "source": None},
    ]
}
LISTING = "crate\tMIT\tISC\ngraphed@1.0.0\tX\t\nmember@0.1.0\tX\t\n"
BASELINE = {
    "duplicates": {"graphed": ["1.0.0", "2.0.0"]},
    "uncovered": [
        {
            "license": "MIT/Apache-2.0",
            "name": "devonly",
            "reason": "workspace dev-dependency",
            "version": "0.3.0",
        },
        {
            "license": "ISC",
            "name": "graphed",
            "reason": "disabled optional dependency",
            "version": "2.0.0",
        },
        {
            "license": "GPL-3.0-only",
            "name": "optional",
            "reason": "disabled optional dependency",
            "version": "0.1.0",
        },
    ],
}


class ExpressionTests(unittest.TestCase):
    def test_spdx_operators_parentheses_and_the_legacy_slash_form(self):
        cases = {
            "MIT": True,
            "MIT/Apache-2.0": True,
            "Apache-2.0 OR MIT": True,
            "Apache-2.0 AND ISC": True,
            "(MIT OR Apache-2.0) AND Unicode-3.0": True,
            "MIT OR Apache-2.0 OR LGPL-2.1-or-later": True,
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT": True,
            "Unlicense OR MIT": True,
            "Apache-2.0 WITH LLVM-exception": False,
            "GPL-3.0-only": False,
            "MIT AND GPL-3.0-only": False,
            "(MIT OR Apache-2.0) AND GPL-3.0-only": False,
            "MIT OR (GPL-3.0-only AND MIT)": True,
        }
        for expression, expected in cases.items():
            with self.subTest(expression=expression):
                self.assertEqual(
                    COVERAGE.satisfied(COVERAGE.parse(expression), ALLOW), expected
                )
        # AND binds tighter than OR, so a rejected conjunct cannot poison the
        # whole expression and an accepted one cannot rescue it.
        self.assertTrue(
            COVERAGE.satisfied(COVERAGE.parse("GPL-3.0-only AND ISC OR MIT"), ALLOW)
        )
        self.assertFalse(
            COVERAGE.satisfied(COVERAGE.parse("MIT AND GPL-3.0-only"), ALLOW)
        )

    def test_malformed_expressions_raise_instead_of_passing(self):
        for expression in ("", "   ", "MIT AND", "(MIT", "MIT)", "AND MIT", "MIT WITH"):
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    COVERAGE.parse(expression)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.config = self.root / "deny.toml"
        self.config.write_text(CONFIG, encoding="utf-8")

    def test_an_empty_allow_list_refuses_to_approve_anything(self):
        self.config.write_text(
            "[licenses]\nversion = 2\nallow = []\n", encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            COVERAGE.policy(self.config)

    def test_version_qualified_exceptions_are_refused_rather_than_widened(self):
        self.config.write_text(
            CONFIG + '\nexceptions = [{ crate = "a", version = "1", allow = ["MIT"] }]\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            COVERAGE.policy(self.config)
        self.config.write_text(
            CONFIG + '\nexceptions = [{ crate = "optional", allow = ["GPL-3.0-only"] }]\n',
            encoding="utf-8",
        )
        allowed, exceptions, ignore_private = COVERAGE.policy(self.config)
        self.assertEqual(allowed, frozenset(("Apache-2.0", "ISC", "MIT")))
        self.assertEqual(exceptions, {"optional": frozenset(("GPL-3.0-only",))})
        self.assertFalse(ignore_private)

    def test_a_package_without_a_licence_expression_is_never_approved(self):
        with self.assertRaises(ValueError):
            COVERAGE.locked_packages(
                {"packages": [{"name": "a", "version": "1", "source": None}]}
            )
        with self.assertRaises(ValueError):
            COVERAGE.locked_packages({"packages": []})

    def test_only_a_cargo_deny_tsv_listing_is_accepted(self):
        for text in ("", "not a listing\n", "crate\tMIT\nnoversion\tX\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    COVERAGE.deny_graph(text)
        self.assertEqual(
            COVERAGE.deny_graph("crate\tMIT\ntoml@1.1.6+spec-1.1.0\tX\r\n"),
            {("toml", "1.1.6+spec-1.1.0")},
        )


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.config = self.root / "deny.toml"
        self.config.write_text(CONFIG, encoding="utf-8")

    def run_check(self, baseline=None, metadata=None, listing=None):
        return COVERAGE.check(
            self.root,
            self.config,
            json.loads(json.dumps(BASELINE if baseline is None else baseline)),
            json.loads(json.dumps(METADATA if metadata is None else metadata)),
            LISTING if listing is None else listing,
        )

    def test_packages_outside_the_cargo_deny_graph_are_still_licence_checked(self):
        report = self.run_check()
        self.assertEqual(report["locked_packages"], 5)
        self.assertEqual(report["cargo_deny_graph_packages"], 2)
        self.assertEqual(report["uncovered_packages"], 3)
        # cargo-deny reaches neither of these, so only this check can reject them.
        self.assertEqual(report["rejected_licenses"], {"optional 0.1.0": "GPL-3.0-only"})
        self.assertIn("1 locked packages", report["failures"][0])
        self.assertEqual(report["uncovered_added"], [])
        self.assertEqual(report["uncovered_removed"], [])

    def test_a_crate_specific_exception_can_grant_an_uncovered_package(self):
        self.config.write_text(
            CONFIG + '\nexceptions = [{ crate = "optional", allow = ["GPL-3.0-only"] }]\n',
            encoding="utf-8",
        )
        report = self.run_check()
        self.assertEqual(report["rejected_licenses"], {})
        self.assertEqual(report["failures"], [])

    def test_the_bound_fails_when_the_uncovered_set_grows_or_shrinks(self):
        grown = dict(BASELINE, uncovered=BASELINE["uncovered"][:2])
        report = self.run_check(baseline=grown)
        self.assertEqual(report["uncovered_added"], ["optional 0.1.0"])
        self.assertTrue(any("gap grew" in failure for failure in report["failures"]))
        extra = dict(
            BASELINE,
            uncovered=BASELINE["uncovered"]
            + [
                {
                    "license": "MIT",
                    "name": "retired",
                    "reason": "workspace dev-dependency",
                    "version": "9.9.9",
                }
            ],
        )
        report = self.run_check(baseline=extra)
        self.assertEqual(report["uncovered_removed"], ["retired 9.9.9"])
        self.assertTrue(any("gap shrank" in failure for failure in report["failures"]))

    def test_a_relicensed_uncovered_package_invalidates_the_recorded_licence(self):
        stale = json.loads(json.dumps(BASELINE))
        stale["uncovered"][0]["license"] = "MIT"
        report = self.run_check(baseline=stale)
        self.assertEqual(report["uncovered_relicensed"], ["devonly 0.3.0"])
        self.assertTrue(
            any("no longer match" in failure for failure in report["failures"])
        )

    def test_an_unknown_recorded_reason_raises_rather_than_passing(self):
        bad = json.loads(json.dumps(BASELINE))
        bad["uncovered"][0]["reason"] = "because"
        with self.assertRaises(ValueError):
            self.run_check(baseline=bad)

    def test_duplicates_are_counted_over_the_whole_lock_not_the_graph(self):
        report = self.run_check()
        self.assertEqual(report["duplicates"], {"graphed": ["1.0.0", "2.0.0"]})
        self.assertEqual(report["new_duplicates"], [])
        report = self.run_check(baseline=dict(BASELINE, duplicates={}))
        self.assertEqual(report["new_duplicates"], ["graphed"])
        self.assertTrue(
            any("new duplicate versions" in failure for failure in report["failures"])
        )

    def test_a_graph_crate_missing_from_metadata_raises(self):
        with self.assertRaises(ValueError):
            self.run_check(listing=LISTING + "phantom@1.0.0\tX\t\n")

    def test_private_packages_are_skipped_only_when_the_policy_says_so(self):
        self.config.write_text(
            CONFIG + "\nprivate = { ignore = true }\n", encoding="utf-8"
        )
        report = self.run_check()
        self.assertTrue(report["ignored_private_packages"])
        self.assertEqual(report["licensed_packages"], 4)

    def test_two_runs_over_the_same_inputs_produce_identical_report_bytes(self):
        first, second = self.run_check(), self.run_check()
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )

    def test_a_baseline_is_only_pinned_from_an_accepting_run(self):
        with self.assertRaises(ValueError):
            COVERAGE.baseline_document(self.run_check(), "2026-10-08", "0.18.6")
        self.config.write_text(
            CONFIG + '\nexceptions = [{ crate = "optional", allow = ["GPL-3.0-only"] }]\n',
            encoding="utf-8",
        )
        document = COVERAGE.baseline_document(self.run_check(), "2026-10-08", "0.18.6")
        self.assertEqual(document["measured_on"], "2026-10-08")
        self.assertEqual(document["cargo_deny"], "0.18.6")
        self.assertEqual(document["locked_packages"], 5)
        self.assertEqual(document["graph_packages"], 2)
        self.assertEqual(len(document["uncovered"]), 3)
        self.assertEqual(document["uncovered_digest"], self.run_check()["uncovered_digest"])


class CommittedBaselineTests(unittest.TestCase):
    """The bound this repository commits to must stay internally consistent."""

    def setUp(self):
        self.baseline = json.loads(
            (Path(COVERAGE.__file__).with_name("deny-coverage-baseline.json")).read_text(
                encoding="utf-8"
            )
        )

    def test_the_committed_bound_is_self_consistent_and_exactly_sized(self):
        uncovered = {
            (entry["name"], entry["version"]) for entry in self.baseline["uncovered"]
        }
        self.assertEqual(len(uncovered), len(self.baseline["uncovered"]))
        self.assertEqual(
            self.baseline["uncovered_digest"], COVERAGE.digest(uncovered)
        )
        self.assertEqual(
            self.baseline["locked_packages"] - self.baseline["graph_packages"],
            len(uncovered),
        )
        for entry in self.baseline["uncovered"]:
            self.assertIn(entry["reason"], COVERAGE.REASONS)

    def test_every_uncovered_licence_satisfies_the_committed_allow_list(self):
        allowed, exceptions, _ = COVERAGE.policy(ROOT / "deny.toml")
        for entry in self.baseline["uncovered"]:
            with self.subTest(crate=entry["name"]):
                grant = allowed | exceptions.get(entry["name"], frozenset())
                self.assertTrue(
                    COVERAGE.satisfied(COVERAGE.parse(entry["license"]), grant),
                    f"{entry['name']} {entry['version']} offers {entry['license']}",
                )

    def test_the_recorded_duplicates_cover_every_crate_the_bound_duplicates(self):
        recorded = self.baseline["duplicates"]
        for name, versions in recorded.items():
            self.assertGreater(len(versions), 1)
            self.assertEqual(versions, sorted(versions))
        bans = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))["bans"]
        skipped = {str(entry["crate"]).split("@")[0] for entry in bans.get("skip", [])}
        # Every duplicate cargo-deny cannot see must still be a recorded one.
        self.assertTrue(skipped.issubset(set(recorded)))


if __name__ == "__main__":
    unittest.main()
