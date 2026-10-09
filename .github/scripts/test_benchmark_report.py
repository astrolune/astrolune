# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Benchmark record parsing, missing-suite detection and loud-failure tests."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "benchmark", Path(__file__).with_name("benchmark-report.py")
)
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)

RUSTC = (
    "rustc 1.99.0 (b940084d7 2026-09-28)\n"
    "binary: rustc\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.99.0\n"
)


def record(suite, names):
    """Builds one suite record exactly as `Suite::to_json` emits it."""
    return json.dumps(
        {
            "schema": "astrolune.benchmark/1",
            "suite": suite,
            "rounds": 3,
            "target_round_us": 300,
            "measurements": [
                {
                    "name": name,
                    "batch": 16,
                    "rounds": 3,
                    "minimum_ns": 10,
                    "median_ns": 11,
                    "mean_ns": 11,
                    "maximum_ns": 12,
                }
                for name in names
            ],
        },
        separators=(",", ":"),
    )


def log(*records):
    """Wraps records in the surrounding cargo output a real run produces."""
    lines = ["    Finished `bench` profile [optimized] target(s) in 71.20s"]
    for entry in records:
        lines += [
            "     Running benches/x.rs (target/release/deps/x-1a2b3c)",
            "benchmark suite: noise",
            "name                     median ns",
            entry,
        ]
    return "\n".join(lines) + "\n"


class BenchmarkRecordTests(unittest.TestCase):
    """Covers the record a hosted benchmark run uploads."""

    def test_every_declared_suite_present_is_recorded_as_ok(self):
        document = BENCHMARK.summarise(
            log(record("crypto", ["a", "b"]), record("state", ["c"])),
            "ubuntu-latest",
            RUSTC,
            0,
            {"crypto": 1, "state": 1},
        )
        self.assertEqual(document["outcome"], "ok")
        self.assertEqual(document["schema"], "astrolune.benchmark-report/1")
        self.assertEqual(document["suites"], ["crypto", "state"])
        self.assertEqual(document["expected_suites"], 2)
        self.assertEqual(document["measurements"], 3)
        self.assertEqual(document["host"], "x86_64-unknown-linux-gnu")
        # The record must never read as a comparable or reproducible figure.
        self.assertIn("shared hosted runner", document["comparability"])

    def test_one_manifest_declaring_two_targets_expects_two_suites(self):
        document = BENCHMARK.summarise(
            log(record("consensus", ["a"]), record("consensus-potb", ["b"])),
            "ubuntu-latest",
            RUSTC,
            0,
            {"consensus": 2},
        )
        self.assertEqual(document["expected_suites"], 2)
        self.assertEqual(document["outcome"], "ok")

    def test_a_missing_suite_fails_instead_of_passing_quietly(self):
        document = BENCHMARK.summarise(
            log(record("crypto", ["a"])),
            "windows-latest",
            RUSTC,
            0,
            {"crypto": 1, "state": 1},
        )
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["expected_suites"], 2)
        self.assertEqual(document["suites"], ["crypto"])

    def test_a_nonzero_exit_status_fails_even_with_every_suite(self):
        document = BENCHMARK.summarise(
            log(record("crypto", ["a"])), "ubuntu-latest", RUSTC, 101, {"crypto": 1}
        )
        self.assertEqual(document["outcome"], "failed")

    def test_results_are_sorted_so_two_uploads_stay_diffable(self):
        document = BENCHMARK.summarise(
            log(record("state", ["a"]), record("codec", ["b"])),
            "ubuntu-latest",
            RUSTC,
            0,
            {"codec": 1, "state": 1},
        )
        self.assertEqual(
            [entry["suite"] for entry in document["results"]], ["codec", "state"]
        )

    def test_an_empty_log_establishes_nothing(self):
        with self.assertRaises(ValueError):
            BENCHMARK.summarise("", "ubuntu-latest", RUSTC, 0, {"crypto": 1})

    def test_a_suite_reporting_no_measurement_is_rejected(self):
        with self.assertRaises(ValueError):
            BENCHMARK.summarise(
                log(record("crypto", [])), "ubuntu-latest", RUSTC, 0, {"crypto": 1}
            )

    def test_a_malformed_record_is_rejected_rather_than_skipped(self):
        broken = '{"schema":"astrolune.benchmark/1","suite":"crypto",}'
        with self.assertRaises(ValueError):
            BENCHMARK.summarise(log(broken), "ubuntu-latest", RUSTC, 0, {"crypto": 1})

    def test_a_record_without_a_suite_name_is_rejected(self):
        nameless = '{"schema":"astrolune.benchmark/1","measurements":[]}'
        with self.assertRaises(ValueError):
            BENCHMARK.summarise(log(nameless), "ubuntu-latest", RUSTC, 0, {"crypto": 1})

    def test_windows_line_endings_parse_identically(self):
        text = log(record("crypto", ["a"]))
        self.assertEqual(
            BENCHMARK.measurements(text),
            BENCHMARK.measurements(text.replace("\n", "\r\n")),
        )


class DeclaredTargetTests(unittest.TestCase):
    """Covers discovery of the expected suite count from the manifests."""

    def test_only_manifests_declaring_a_bench_target_are_counted(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            for crate, body in (
                ("crypto", '[[bench]]\nname = "crypto"\nharness = false\n'),
                (
                    "consensus",
                    '[[bench]]\nname = "consensus"\nharness = false\n'
                    '[[bench]]\nname = "potb"\nharness = false\n',
                ),
                ("types", "[package]\nname = \"types\"\n"),
            ):
                directory = base / "crates" / crate
                directory.mkdir(parents=True)
                (directory / "Cargo.toml").write_text(body, encoding="utf-8")
            # A nested non-member manifest must not be discovered.
            fuzz = base / "crates" / "codec" / "fuzz"
            fuzz.mkdir(parents=True)
            (fuzz / "Cargo.toml").write_text(
                '[[bench]]\nname = "fuzz"\n', encoding="utf-8"
            )
            self.assertEqual(
                BENCHMARK.declared_targets(base), {"consensus": 2, "crypto": 1}
            )

    def test_the_real_workspace_declares_every_benched_crate(self):
        declared = BENCHMARK.declared_targets(Path(__file__).parents[2])
        self.assertEqual(
            declared,
            {
                "codec": 1,
                "consensus": 2,
                "crypto": 1,
                "execution": 1,
                "runtime": 1,
                "state": 1,
                "storage": 1,
                "transaction": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
