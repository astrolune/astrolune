#!/usr/bin/env python3
# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT
"""Dependency-free sampler qualification; all listeners bind IPv4 loopback."""

import contextlib
import importlib.util
import json
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "calibrate_network", Path(__file__).with_name("calibrate-network.py")
)
sampler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sampler)
BODY = (
    "# TYPE astrolune_finalized_height gauge\n"
    "astrolune_finalized_height 12\n"
    "astrolune_uptime_seconds 5\n"
    "astrolune_p2p_exchanges_total 42\n"
)


@contextlib.contextmanager
def endpoint_server(response, delay=0):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            self.request.recv(4096)
            chunks = response if isinstance(response, list) else [response]
            try:
                for chunk in chunks:
                    if delay:
                        time.sleep(delay)
                    self.request.sendall(chunk)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        worker.start()
        try:
            yield sampler.endpoint(f"node=http://127.0.0.1:{server.server_address[1]}/metrics")
        finally:
            server.shutdown()
            worker.join(timeout=2)


def http_response(body=BODY, headers=None, status="200 OK"):
    body = body.encode() if isinstance(body, str) else body
    headers = headers if headers is not None else f"Content-Length: {len(body)}\r\n"
    return f"HTTP/1.1 {status}\r\n{headers}\r\n".encode() + body


def sample(height, uptime, count, offset, ok=True, round_number=None):
    result = {
        "node": "node", "ok": ok, "observed_offset_seconds": offset,
        "observed_utc": f"sample-{offset}", "poll_duration_ms": 2.0,
    }
    if ok:
        result["metrics"] = {
            sampler.HEIGHT: height, sampler.UPTIME: uptime,
            "astrolune_p2p_exchanges_total": count,
        }
    if round_number is not None:
        result["round"] = round_number
    return result


class EndpointTests(unittest.TestCase):
    def test_numeric_ipv4_and_ipv6(self):
        self.assertEqual(sampler.endpoint("one=http://127.0.0.1:9000/metrics")["port"], 9000)
        self.assertEqual(sampler.endpoint("two=http://[::1]:9001/metrics")["address"], "::1")

    def test_endpoint_shape_is_checked_for_both_address_families(self):
        for host in ("127.0.0.1", "[::1]"):
            for bad in (
                f"https://{host}:1/metrics", f"http://{host}/metrics",
                f"http://{host}:0/metrics", f"http://{host}:65536/metrics",
                f"http://{host}:1/other", f"http://{host}:1/metrics?q=1",
                f"http://{host}:1/metrics#part", f"http://user@{host}:1/metrics",
            ):
                with self.subTest(url=bad), self.assertRaises(ValueError):
                    sampler.endpoint("node=" + bad)
        for bad in ("node=http://localhost:1/metrics", "node=http://[fe80::1%1]:1/metrics",
                    "bad name=http://127.0.0.1:1/metrics", "missing"):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                sampler.endpoint(bad)

    def test_current_exporter_text_and_metric_bounds(self):
        self.assertEqual(sampler.parse_metrics(BODY)[sampler.HEIGHT], 12)
        for body in (
            "astrolune_finalized_height 1\n", BODY + "astrolune_uptime_seconds 1\n",
            BODY + "astrolune_extra -1\n", BODY + "astrolune_extra 18446744073709551616\n",
            BODY + 'astrolune_extra{peer="a"} 1\n', BODY + "other_metric 1\n",
            BODY + "astrolune_extra 1.5\n",
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                sampler.parse_metrics(body)
        many = BODY + "".join(f"astrolune_extra_{'a' * n} 1\n" for n in range(1, 65))
        with self.assertRaises(ValueError):
            sampler.parse_metrics(many)


class PollTests(unittest.TestCase):
    def test_content_length_and_close_delimited_http(self):
        for response in (http_response(), http_response(headers="")):
            with self.subTest(response=response), endpoint_server(response) as target:
                self.assertEqual(sampler.read_metrics(target, time.monotonic() + 1), BODY)

    def test_http_errors_are_failed_samples(self):
        cases = (
            http_response(status="302 Found"),
            http_response(headers="Transfer-Encoding: chunked\r\n"),
            http_response(headers="Content-Length: 9999\r\n"),
            http_response(headers="Content-Length: 1\r\n"),
            http_response(headers="Content-Length: 1\r\nContent-Length: 1\r\n"),
            http_response(headers="Content-Length: invalid\r\n"),
            b"HTTP/1.1 200 OK\r\n", http_response(body=b"\xff"),
            http_response(body="x" * sampler.MAX_RESPONSE_BYTES),
            http_response(body="invalid metric"),
        )
        for response in cases:
            with self.subTest(response=response[:80]), endpoint_server(response) as target:
                started = time.monotonic()
                result = sampler.poll(target, started, started + 1, 0.5)
                self.assertFalse(result["ok"])
                self.assertIn("error", result)
                self.assertGreaterEqual(result["poll_duration_ms"], 0)

    def test_absolute_deadline_bounds_a_slow_response(self):
        response = [bytes([byte]) for byte in http_response()]
        with endpoint_server(response, delay=0.02) as target:
            began = time.monotonic()
            result = sampler.poll(target, began, began + 1, 0.08)
            self.assertFalse(result["ok"])
            self.assertLess(time.monotonic() - began, 0.75)

    def test_expired_global_deadline_does_not_open_socket(self):
        target = sampler.endpoint("node=http://127.0.0.1:1/metrics")
        with mock.patch.object(sampler.socket, "socket") as connection:
            result = sampler.poll(target, 0, 0, 0.1)
            self.assertFalse(result["ok"])
            connection.return_value.__enter__.return_value.connect.assert_not_called()


class SummaryTests(unittest.TestCase):
    def test_progress_and_nearest_rank_poll_quantiles(self):
        rows = [sample(10, 1, 20, 1), sample(14, 3, 27, 3), sample(16, 4, 31, 4)]
        report = sampler.summarize(rows, ["node"])["node"]
        self.assertEqual(report["observed_finalized_progress"], 6)
        self.assertEqual(report["finalized_blocks_per_second"], 2)
        self.assertEqual(report["counter_deltas_between_comparable_samples"],
                         {"astrolune_p2p_exchanges_total": 11})
        self.assertEqual(sampler.quantiles([3, 1, 2])["p50"], 2)
        self.assertEqual(sampler.quantiles([3, 1, 2])["p95"], 3)

    def test_restart_boundary_and_height_regression_excluded(self):
        rows = [sample(10, 10, 50, 1), sample(12, 11, 55, 2),
                sample(15, 1, 2, 3), sample(14, 2, 3, 4), sample(16, 3, 4, 5)]
        report = sampler.summarize(rows, ["node"])["node"]
        self.assertEqual(report["observed_finalized_progress"], 4)
        self.assertEqual(report["comparable_elapsed_seconds"], 2)
        self.assertEqual(len(report["observed_reset_boundaries"]), 1)
        self.assertEqual(report["height_regressions"], ["sample-4"])

    def test_failed_poll_and_missed_rounds_are_not_bridged(self):
        rows = [sample(1, 1, 1, 1, round_number=0),
                sample(0, 0, 0, 2, ok=False, round_number=1),
                sample(5, 3, 5, 3, round_number=2),
                sample(9, 5, 9, 5, round_number=4),
                sample(10, 6, 10, 6, round_number=5)]
        report = sampler.summarize(rows, ["node"])["node"]
        self.assertEqual(report["observed_finalized_progress"], 1)
        self.assertEqual(report["comparable_elapsed_seconds"], 1)
        self.assertEqual(len(report["excluded_gaps"]), 2)
        self.assertEqual(report["excluded_gaps"][0]["failed_polls"], 1)
        self.assertEqual(report["excluded_gaps"][1]["missing_rounds"], 1)

    def test_empty_failure_only_and_single_sample(self):
        for rows in ([], [sample(0, 0, 0, 1, ok=False)], [sample(3, 1, 2, 1)]):
            report = sampler.summarize(rows, ["node"])["node"]
            self.assertIsNone(report["finalized_blocks_per_second"])
            self.assertEqual(report["observed_finalized_progress"], 0)
        self.assertIsNone(sampler.quantiles([])["p99"])


class RunTests(unittest.TestCase):
    def args(self, output, url="http://127.0.0.1:1/metrics"):
        return sampler.parser().parse_args([
            "--endpoint", "node=" + url, "--duration", "0.22", "--interval", "0.1",
            "--timeout", "0.2", "--revision", "local-test", "--topology", "loopback test",
            "--output", str(output),
        ])

    def test_full_run_preserves_raw_samples_metadata_and_report(self):
        with tempfile.TemporaryDirectory() as directory, endpoint_server(http_response()) as target:
            output = Path(directory) / "new-run"
            args = self.args(output, target["url"])
            self.assertEqual(sampler.run(args), 0)
            metadata = json.loads((output / "metadata.json").read_text())
            report = json.loads((output / "report.json").read_text())
            rows = [json.loads(line) for line in (output / "samples.jsonl").read_text().splitlines()]
            self.assertGreaterEqual(len(rows), 1)
            self.assertLessEqual(len(rows), 3)
            self.assertEqual(report["nodes"]["node"]["attempts"], len(rows))
            self.assertEqual(metadata["revision"], "local-test")
            self.assertEqual(metadata["configuration"]["endpoints"][0]["url"], target["url"])
            self.assertTrue(all(row["raw_metrics"] == BODY and row["ok"] for row in rows))
            before = (output / "report.json").read_bytes()
            with self.assertRaises(FileExistsError):
                sampler.run(args)
            self.assertEqual((output / "report.json").read_bytes(), before)

    def test_failure_run_still_writes_report(self):
        with tempfile.TemporaryDirectory() as directory, endpoint_server(http_response(status="503 Unavailable")) as target:
            output = Path(directory) / "failed-run"
            self.assertEqual(sampler.run(self.args(output, target["url"])), 1)
            report = json.loads((output / "report.json").read_text())
            self.assertGreater(report["nodes"]["node"]["failed_samples"], 0)

    def test_queued_endpoints_share_the_global_deadline(self):
        with tempfile.TemporaryDirectory() as directory, endpoint_server([http_response()], delay=0.3) as target:
            args = self.args(Path(directory) / "deadline", target["url"])
            args.duration, args.timeout, args.workers = 0.08, 0.5, 2
            args.endpoint = [f"n{i}={target['url']}" for i in range(12)]
            began = time.monotonic()
            self.assertEqual(sampler.run(args), 1)
            self.assertLess(time.monotonic() - began, 0.75)
            report = json.loads((args.output / "report.json").read_text())
            self.assertEqual(sum(row["attempts"] for row in report["nodes"].values()), 12)

    def test_worker_count_limits_concurrency(self):
        lock = threading.Lock()
        active, peak = 0, 0

        def measured_poll(target, started, deadline, timeout):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(active, peak)
            time.sleep(0.01)
            with lock:
                active -= 1
            row = sample(1, 1, 1, time.monotonic() - started)
            row["node"] = target["name"]
            return row

        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory) / "workers")
            args.workers, args.duration = 2, 0.09
            args.endpoint = [f"n{i}=http://127.0.0.1:1/metrics" for i in range(8)]
            with mock.patch.object(sampler, "poll", side_effect=measured_poll):
                self.assertEqual(sampler.run(args), 0)
            self.assertEqual(peak, 2)

    def test_bounds_reject_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            for key, value in (
                ("duration", 3601), ("duration", float("nan")), ("duration", 0),
                ("interval", 0.01), ("timeout", 11), ("workers", 0), ("workers", 9),
                ("revision", " "), ("topology", "x" * 4097),
                ("endpoint", ["same=http://127.0.0.1:1/metrics"] * 2),
                ("endpoint", [f"n{i}=http://127.0.0.1:1/metrics" for i in range(33)]),
            ):
                args = self.args(output)
                setattr(args, key, value)
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    sampler.run(args)
                self.assertFalse(output.exists())
            args = self.args(output)
            args.duration = 1001
            with self.assertRaises(ValueError):
                sampler.run(args)
            self.assertFalse(output.exists())

    def test_keyboard_interrupt_writes_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "interrupted"
            with mock.patch.object(sampler, "poll", side_effect=KeyboardInterrupt):
                self.assertEqual(sampler.run(self.args(output)), 130)
            report = json.loads((output / "report.json").read_text())
            self.assertTrue(report["interrupted"])


if __name__ == "__main__":
    unittest.main()
