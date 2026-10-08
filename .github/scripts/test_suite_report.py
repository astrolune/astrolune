# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Per-platform suite result parsing, determinism and loud-failure tests."""

import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "suite", Path(__file__).with_name("suite-report.py")
)
SUITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUITE)

RUSTC = (
    "rustc 1.99.0 (b940084d7 2026-09-28)\n"
    "binary: rustc\n"
    "host: x86_64-pc-windows-msvc\n"
    "release: 1.99.0\n"
)
PASSING = """\
   Compiling types v0.1.0 (D:\\astrolune\\crates\\types)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 41.02s
     Running unittests src/lib.rs (target/debug/deps/types-1a2b3c)

running 12 tests
test encode::round_trips ... ok
test encode::rejects_trailing ... ignored

test result: ok. 11 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.04s

     Running tests/network.rs (target/debug/deps/network-4d5e6f)

running 3 tests

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.21s

   Doc-tests codec

running 2 tests
test src/lib.rs - encode (line 11) ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
"""
FAILING = """\
running 4 tests
test consensus::quorum ... ok
test consensus::rotation ... FAILED
test consensus::vrf ... FAILED

failures:
    consensus::rotation
    consensus::vrf

test result: FAILED. 1 passed; 2 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.09s
"""


def summarise(log, exit_status=0, profile="dev", operating_system="windows-latest"):
    return SUITE.summarise(log, operating_system, profile, RUSTC, exit_status)


class SuiteReportTests(unittest.TestCase):
    def test_every_libtest_summary_in_a_log_is_totalled(self):
        report = summarise(PASSING)
        self.assertEqual(report["schema"], SUITE.SCHEMA)
        self.assertEqual(report["suites"], 3)
        self.assertEqual(report["passed"], 16)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["ignored"], 1)
        self.assertEqual(report["measured"], 0)
        self.assertEqual(report["filtered_out"], 2)
        self.assertEqual(report["failed_tests"], [])
        self.assertEqual(report["outcome"], "ok")
        self.assertEqual(report["operating_system"], "windows-latest")
        self.assertEqual(report["profile"], "dev")
        self.assertEqual(report["rustc"], "rustc 1.99.0 (b940084d7 2026-09-28)")
        self.assertEqual(report["host"], "x86_64-pc-windows-msvc")
        self.assertEqual(report["exit_status"], 0)

    def test_failures_are_counted_and_named_in_a_stable_order(self):
        report = summarise(FAILING, exit_status=101)
        self.assertEqual(report["outcome"], "failed")
        self.assertEqual(report["failed"], 2)
        self.assertEqual(report["passed"], 1)
        self.assertEqual(
            report["failed_tests"], ["consensus::rotation", "consensus::vrf"]
        )
        self.assertEqual(report["exit_status"], 101)

    def test_several_logs_from_one_matrix_leg_are_totalled_together(self):
        report = summarise(PASSING + "\n" + PASSING)
        self.assertEqual(report["suites"], 6)
        self.assertEqual(report["passed"], 32)

    def test_a_log_without_a_verdict_never_records_a_passing_platform(self):
        for log in ("", "error: could not compile `node`\n", "running 3 tests\n"):
            with self.subTest(log=log):
                with self.assertRaises(ValueError) as caught:
                    summarise(log)
                self.assertIn("no suite result is established", str(caught.exception))

    def test_a_nonzero_exit_status_overrides_a_clean_looking_log(self):
        report = summarise(PASSING, exit_status=101)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["outcome"], "failed")

    def test_counted_failures_without_names_are_reported_rather_than_hidden(self):
        log = (
            "running 1 test\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 0.01s\n"
        )
        report = summarise(log, exit_status=101)
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["failed_tests"], ["<names absent from the captured log>"])

    def test_the_record_excludes_timings_so_two_runs_match_byte_for_byte(self):
        slower = PASSING.replace("finished in 0.04s", "finished in 9.87s").replace(
            "in 41.02s", "in 12.34s"
        )
        self.assertNotEqual(PASSING, slower)
        self.assertEqual(
            json.dumps(summarise(PASSING), indent=2, sort_keys=True),
            json.dumps(summarise(slower), indent=2, sort_keys=True),
        )

    def test_carriage_returns_from_a_windows_runner_parse_identically(self):
        self.assertEqual(
            json.dumps(summarise(PASSING), indent=2, sort_keys=True),
            json.dumps(
                summarise(PASSING.replace("\n", "\r\n")), indent=2, sort_keys=True
            ),
        )

    def test_a_compiler_block_without_a_host_triple_is_refused(self):
        with self.assertRaises(ValueError):
            SUITE.summarise(PASSING, "ubuntu-latest", "dev", "rustc 1.99.0\n", 0)


if __name__ == "__main__":
    unittest.main()
