# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Four-leg suite qualification tests: absent, duplicate and inconsistent legs."""

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


REPORTER = load("suite-report.py", "suite")
COMPARER = load("compare-suites.py", "suite_comparison")

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows/ci.yml"
VERSION = "rustc 1.99.0 (b940084d7 2026-09-28)"
HOSTS = {
    "ubuntu-latest": "x86_64-unknown-linux-gnu",
    "windows-latest": "x86_64-pc-windows-msvc",
}
# Shaped like the counts `docs/39` records for the hosted matrix: the release
# legs run four extra ignored `cargo-contract` tests in their own invocation.
PASSED = {
    "ubuntu-latest:dev": 1184,
    "ubuntu-latest:release": 1188,
    "windows-latest:dev": 1185,
    "windows-latest:release": 1189,
}
SUITES = {"dev": 61, "release": 64}
IGNORED = {"dev": 9, "release": 5}
FILTERED_OUT = {"dev": 0, "release": 37}


def verbose(host, version=VERSION):
    return f"{version}\nbinary: rustc\nhost: {host}\nrelease: 1.99.0\n"


def captured(passed, failed, ignored, measured, filtered_out, suites, names):
    """Build a log libtest could have printed for exactly these totals."""
    named = "".join(f"test {name} ... FAILED\n" for name in names)
    first = (
        f"test result: {'FAILED' if failed else 'ok'}. {passed} passed; "
        f"{failed} failed; {ignored} ignored; {measured} measured; "
        f"{filtered_out} filtered out; finished in 0.42s\n"
    )
    empty = (
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.01s\n"
    )
    return named + first + empty * (suites - 1)


def result(
    system,
    profile,
    passed=None,
    suites=None,
    ignored=None,
    measured=0,
    filtered_out=None,
    failures=(),
    exit_status=None,
    host=None,
    version=VERSION,
    edits=None,
):
    """One leg's `SUITE.json` content, produced by the real reporter.

    `edits` is applied afterwards, so a field the reporter could never emit can
    still be presented to the comparer the way a hand-edited artefact would.
    """
    name = f"{system}:{profile}"
    log = captured(
        PASSED[name] if passed is None else passed,
        len(failures),
        IGNORED[profile] if ignored is None else ignored,
        measured,
        FILTERED_OUT[profile] if filtered_out is None else filtered_out,
        SUITES[profile] if suites is None else suites,
        failures,
    )
    report = REPORTER.summarise(
        log,
        system,
        profile,
        verbose(HOSTS[system] if host is None else host, version),
        (101 if failures else 0) if exit_status is None else exit_status,
    )
    report.update(edits or {})
    return report


def matrix(**replacements):
    """Every expected leg, with named legs replaced by the supplied overrides."""
    legs = []
    for name in COMPARER.EXPECTED_LEGS:
        system, profile = name.split(":")
        legs.append(result(system, profile, **replacements.get(name, {})))
    return legs


class ExpectedLegTests(unittest.TestCase):
    def test_the_expected_legs_are_the_four_the_workflow_declares(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("os: [ubuntu-latest, windows-latest]", text)
        self.assertIn("profile: [dev, release]", text)
        self.assertIn("name: suite-${{ matrix.os }}-${{ matrix.profile }}", text)
        self.assertEqual(
            COMPARER.EXPECTED_LEGS,
            (
                "ubuntu-latest:dev",
                "ubuntu-latest:release",
                "windows-latest:dev",
                "windows-latest:release",
            ),
        )
        self.assertEqual(COMPARER.SCHEMA, "astrolune.suite-qualification/1")
        self.assertEqual(COMPARER.LEG_SCHEMA, REPORTER.SCHEMA)

    def test_results_are_discovered_one_per_downloaded_artefact_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in COMPARER.EXPECTED_LEGS:
                system, profile = name.split(":")
                COMPARER.write(
                    root / f"suite-{system}-{profile}/SUITE.json",
                    result(system, profile),
                )
            (root / "unrelated.json").write_text("{}", encoding="utf-8")
            found = COMPARER.discover(root)
            self.assertEqual(
                [path.parent.name for path in found],
                [
                    "suite-ubuntu-latest-dev",
                    "suite-ubuntu-latest-release",
                    "suite-windows-latest-dev",
                    "suite-windows-latest-release",
                ],
            )
            verdict = COMPARER.compare([COMPARER.load(path) for path in found])
            self.assertTrue(verdict["qualified"])


class CleanMatrixTests(unittest.TestCase):
    def test_four_clean_legs_under_one_compiler_qualify(self):
        verdict = COMPARER.compare(matrix())
        self.assertTrue(verdict["qualified"])
        self.assertEqual(verdict["schema"], COMPARER.SCHEMA)
        self.assertEqual(verdict["verdict"], "all four legs ran clean under one compiler")
        self.assertEqual(verdict["compared_legs"], 4)
        self.assertEqual(verdict["failures"], [])
        self.assertEqual(verdict["rustc"], VERSION)
        self.assertEqual(verdict["expected_legs"], list(COMPARER.EXPECTED_LEGS))
        self.assertEqual(verdict["totals"]["passed"], 4746)
        self.assertEqual(verdict["totals"]["failed"], 0)
        self.assertEqual(verdict["totals"]["suites"], 250)
        self.assertEqual(
            sorted(verdict["legs"]), sorted(COMPARER.EXPECTED_LEGS)
        )
        self.assertEqual(verdict["legs"]["windows-latest:release"]["passed"], 1189)
        self.assertEqual(verdict["legs"]["windows-latest:release"]["outcome"], "ok")

    def test_the_legitimate_profile_and_platform_differences_stay_advisory(self):
        verdict = COMPARER.compare(matrix())
        self.assertTrue(verdict["qualified"])
        self.assertEqual(
            sorted(verdict["advisory_differences"]),
            ["filtered_out", "host", "ignored"],
        )
        self.assertEqual(
            verdict["advisory_differences"]["host"]["ubuntu-latest:dev"],
            "x86_64-unknown-linux-gnu",
        )
        self.assertEqual(
            verdict["advisory_differences"]["ignored"]["ubuntu-latest:release"], 5
        )
        # The release leg's extra ignored-test invocation is reported, not refused.
        self.assertEqual(
            verdict["profile_differences"]["ubuntu-latest"],
            {
                "failed": 0,
                "filtered_out": 37,
                "ignored": -4,
                "measured": 0,
                "passed": 4,
                "suites": 3,
            },
        )
        self.assertNotIn("measured", verdict["advisory_differences"])

    def test_the_count_drift_each_profile_allows_is_recorded_exactly(self):
        verdict = COMPARER.compare(matrix())
        self.assertEqual(
            verdict["count_drift"]["dev"]["passed"],
            {"allowed": 59, "largest": 1185, "observed": 1, "smallest": 1184},
        )
        self.assertEqual(
            verdict["count_drift"]["release"]["suites"],
            {"allowed": 3, "largest": 64, "observed": 0, "smallest": 64},
        )

    def test_two_comparisons_over_the_same_legs_produce_identical_bytes(self):
        legs = matrix()
        first, second = COMPARER.compare(legs), COMPARER.compare(legs)
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )

    def test_a_written_verdict_is_sorted_and_newline_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested/SUITE-QUALIFICATION.json"
            verdict = COMPARER.compare(matrix())
            COMPARER.write(path, verdict)
            raw = path.read_bytes()
            self.assertTrue(raw.endswith(b"\n"))
            self.assertNotIn(b"\r\n", raw)
            self.assertEqual(
                raw.decode("utf-8"),
                json.dumps(verdict, indent=2, sort_keys=True) + "\n",
            )


class RefusedLegSetTests(unittest.TestCase):
    def test_an_absent_leg_is_an_error_and_is_named(self):
        for absent in COMPARER.EXPECTED_LEGS:
            with self.subTest(absent=absent):
                kept = [leg for leg in matrix() if COMPARER.leg(leg) != absent]
                self.assertEqual(len(kept), 3)
                with self.assertRaises(ValueError) as caught:
                    COMPARER.compare(kept)
                self.assertIn("1 of 4 legs produced no result", str(caught.exception))
                self.assertIn(absent, str(caught.exception))

    def test_no_legs_at_all_can_never_look_like_a_pass(self):
        with self.assertRaises(ValueError) as caught:
            COMPARER.compare([])
        self.assertIn("4 of 4 legs produced no result", str(caught.exception))

    def test_a_duplicate_leg_cannot_stand_in_for_a_missing_one(self):
        legs = matrix()
        duplicated = [legs[0], legs[0], legs[1], legs[2]]
        with self.assertRaises(ValueError) as caught:
            COMPARER.compare(duplicated)
        self.assertIn("ubuntu-latest:dev was supplied twice", str(caught.exception))
        # Even a byte-identical second copy of a differently built leg is refused.
        with self.assertRaises(ValueError):
            COMPARER.compare(legs + [result("ubuntu-latest", "dev")])

    def test_an_unexpected_leg_is_refused_when_it_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SUITE.json"
            COMPARER.write(
                path, result("ubuntu-latest", "dev", edits={"profile": "bench"})
            )
            with self.assertRaises(ValueError) as caught:
                COMPARER.load(path)
            self.assertIn("ubuntu-latest:bench", str(caught.exception))
            self.assertIn("this matrix never runs", str(caught.exception))
            COMPARER.write(
                path,
                result(
                    "ubuntu-latest", "dev", edits={"operating_system": "macos-latest"}
                ),
            )
            with self.assertRaises(ValueError):
                COMPARER.load(path)


class RefusedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def store(self, document, name="SUITE.json"):
        path = self.root / name
        COMPARER.write(path, document)
        return path

    def test_a_foreign_schema_or_an_incomplete_result_is_refused(self):
        self.assertEqual(
            COMPARER.load(self.store(result("ubuntu-latest", "dev")))["profile"], "dev"
        )
        for label, document in (
            ("old schema", dict(result("ubuntu-latest", "dev"), schema="astrolune.suite-result/0")),
            ("no schema", {"operating_system": "ubuntu-latest", "profile": "dev"}),
            ("not an object", [result("ubuntu-latest", "dev")]),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    COMPARER.load(self.store(document))
        for field in COMPARER.REQUIRED:
            if field == "schema":
                continue
            incomplete = result("ubuntu-latest", "dev")
            del incomplete[field]
            with self.subTest(omitted=field):
                with self.assertRaises(ValueError) as caught:
                    COMPARER.load(self.store(incomplete))
                self.assertIn("omits required fields", str(caught.exception))

    def test_a_count_that_is_not_a_count_is_refused(self):
        for field, value in (
            ("passed", "1184"),
            ("failed", -1),
            ("suites", True),
            ("exit_status", None),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as caught:
                    COMPARER.load(
                        self.store(
                            result("ubuntu-latest", "dev", edits={field: value})
                        )
                    )
                self.assertIn(f"non-count {field}", str(caught.exception))
        with self.assertRaises(ValueError):
            COMPARER.load(
                self.store(
                    result("ubuntu-latest", "dev", edits={"failed_tests": "none"})
                )
            )

    def test_a_result_edited_after_the_fact_is_refused(self):
        # Suite results carry no self-digest, so their own fields must agree.
        edited = result("ubuntu-latest", "dev", failures=("consensus::vrf",))
        edited["outcome"] = "ok"
        with self.assertRaises(ValueError) as caught:
            COMPARER.load(self.store(edited))
        self.assertIn("declares outcome 'ok' with 1 failed", str(caught.exception))
        hidden = result("ubuntu-latest", "dev", failures=("consensus::vrf",))
        hidden["failed_tests"] = []
        with self.assertRaises(ValueError) as caught:
            COMPARER.load(self.store(hidden))
        self.assertIn("counts 1 failures and names 0", str(caught.exception))

    def test_a_result_whose_compiler_host_denies_its_platform_is_refused(self):
        swapped = result("ubuntu-latest", "dev", host="x86_64-pc-windows-msvc")
        with self.assertRaises(ValueError) as caught:
            COMPARER.load(self.store(swapped))
        self.assertIn("does not belong to that leg", str(caught.exception))


class RefusedQualificationTests(unittest.TestCase):
    def test_one_failed_leg_refuses_the_whole_matrix(self):
        verdict = COMPARER.compare(
            matrix(
                **{
                    "windows-latest:release": {
                        "failures": ("consensus::rotation", "consensus::vrf")
                    }
                }
            )
        )
        self.assertFalse(verdict["qualified"])
        self.assertEqual(verdict["verdict"], "four-leg suite qualification refused")
        self.assertEqual(len(verdict["failures"]), 1)
        self.assertIn("windows-latest:release failed 2 of 1191", verdict["failures"][0])
        self.assertIn("consensus::rotation, consensus::vrf", verdict["failures"][0])
        self.assertEqual(verdict["totals"]["failed"], 2)

    def test_a_leg_that_only_exited_nonzero_still_refuses_the_matrix(self):
        verdict = COMPARER.compare(
            matrix(**{"ubuntu-latest:dev": {"exit_status": 101}})
        )
        self.assertFalse(verdict["qualified"])
        self.assertIn("exit status 101", verdict["failures"][0])
        self.assertIn("no failure was named", verdict["failures"][0])

    def test_legs_that_disagree_on_their_compiler_qualify_no_toolchain(self):
        other = "rustc 1.99.1 (c0a1b2c3d 2026-10-05)"
        verdict = COMPARER.compare(
            matrix(**{"ubuntu-latest:release": {"version": other}})
        )
        self.assertFalse(verdict["qualified"])
        self.assertIsNone(verdict["rustc"])
        self.assertEqual(len(verdict["failures"]), 1)
        self.assertIn("did not share one compiler identity", verdict["failures"][0])
        self.assertIn(other, verdict["failures"][0])
        self.assertIn(VERSION, verdict["failures"][0])

    def test_two_legs_of_one_profile_may_not_disagree_wildly_on_their_counts(self):
        verdict = COMPARER.compare(matrix(**{"ubuntu-latest:dev": {"passed": 500}}))
        self.assertFalse(verdict["qualified"])
        self.assertIn(
            "the two dev legs disagree on passed by 685, above the 59 this "
            "matrix allows (500 and 1185)",
            verdict["failures"],
        )
        # A difference inside the bound stays a pass and is still reported.
        inside = COMPARER.compare(matrix(**{"ubuntu-latest:dev": {"passed": 1140}}))
        self.assertTrue(inside["qualified"])
        self.assertEqual(inside["count_drift"]["dev"]["passed"]["observed"], 45)

    def test_a_leg_that_ran_nothing_is_refused_rather_than_averaged_away(self):
        for field in ("passed", "suites"):
            with self.subTest(field=field):
                verdict = COMPARER.compare(
                    matrix(**{"windows-latest:dev": {"edits": {field: 0}}})
                )
                self.assertFalse(verdict["qualified"])
                self.assertIn(
                    f"a dev leg recorded zero {field}, so that leg established "
                    "no result",
                    verdict["failures"],
                )

    def test_every_refusal_is_named_rather_than_only_the_first(self):
        verdict = COMPARER.compare(
            matrix(
                **{
                    "ubuntu-latest:dev": {"failures": ("codec::round_trip",)},
                    "windows-latest:release": {"version": "rustc 1.98.1 (2026-08-01)"},
                }
            )
        )
        self.assertFalse(verdict["qualified"])
        self.assertEqual(len(verdict["failures"]), 2)
        self.assertEqual(verdict["failures"], sorted(verdict["failures"]))


if __name__ == "__main__":
    unittest.main()
