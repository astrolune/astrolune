#!/usr/bin/env python3
# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT
"""Read-only, bounded measurements of explicitly supplied node metrics endpoints."""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import math
import platform
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 16 * 1024
MAX_SAMPLES = 10_000
HEIGHT = "astrolune_finalized_height"
UPTIME = "astrolune_uptime_seconds"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
METRIC = re.compile(r"(astrolune_[a-z_]+) ([0-9]{1,20})\Z")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def endpoint(value):
    """Numeric addresses avoid an unbounded resolver stage; never follow redirects."""
    name, separator, url = value.partition("=")
    if not separator or not NAME.fullmatch(name):
        raise ValueError("endpoint must be NAME=http://NUMERIC-IP:PORT/metrics")
    parsed = urlsplit(url)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise ValueError("endpoint requires a numeric IP and valid port") from error
    if (
        parsed.scheme != "http"
        or parsed.path != "/metrics"
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or address.scope_id
        if isinstance(address, ipaddress.IPv6Address)
        else False
    ):
        # Scoped IPv6 requires an interface binding outside this portable sampler.
        raise ValueError("endpoint requires plain HTTP, explicit port and /metrics only")
    return {
        "name": name,
        "url": url,
        "address": str(address),
        "port": port,
        "family": socket.AF_INET6 if address.version == 6 else socket.AF_INET,
    }


def parse_metrics(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = METRIC.fullmatch(line)
        if match is None:
            raise ValueError("expected an unlabelled unsigned AstroLune metric")
        name, encoded = match.groups()
        value = int(encoded)
        if name in values or value > 2**64 - 1 or len(values) >= 64:
            raise ValueError("duplicate, oversized or excessive metrics")
        values[name] = value
    if HEIGHT not in values or UPTIME not in values:
        raise ValueError("missing finalized height or process uptime")
    return values


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("absolute polling deadline exceeded")
    return value


def read_metrics(target, deadline):
    """Read the current exporter's close-delimited/Content-Length HTTP response."""
    with socket.socket(target["family"], socket.SOCK_STREAM) as connection:
        connection.settimeout(remaining(deadline))
        connection.connect((target["address"], target["port"]))
        host = target["address"]
        if target["family"] == socket.AF_INET6:
            host = f"[{host}]"
        request = (
            f"GET /metrics HTTP/1.1\r\nHost: {host}:{target['port']}\r\n"
            "Connection: close\r\nAccept: text/plain\r\n\r\n"
        ).encode("ascii")
        connection.settimeout(remaining(deadline))
        connection.sendall(request)
        response = bytearray()
        body_at = None
        content_length = None
        while True:
            connection.settimeout(remaining(deadline))
            chunk = connection.recv(min(4096, MAX_RESPONSE_BYTES + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_RESPONSE_BYTES:
                raise ValueError("metrics HTTP response exceeds 16 KiB")
            if body_at is None and b"\r\n\r\n" in response:
                header, _ = response.split(b"\r\n\r\n", 1)
                lines = header.decode("ascii").split("\r\n")
                status = lines[0].split()
                if (
                    len(status) < 2
                    or status[0] not in ("HTTP/1.0", "HTTP/1.1")
                    or status[1] != "200"
                ):
                    raise ValueError("metrics endpoint did not return HTTP 200")
                headers = {}
                for line in lines[1:]:
                    key, separator, value = line.partition(":")
                    if not separator or key.lower() in headers:
                        raise ValueError("invalid or duplicate HTTP headers")
                    headers[key.lower()] = value.strip()
                if "transfer-encoding" in headers:
                    raise ValueError("chunked metrics responses are unsupported")
                if "content-length" in headers:
                    encoded = headers["content-length"]
                    if (
                        not encoded.isascii()
                        or not encoded.isdecimal()
                        or len(encoded) > 6
                    ):
                        raise ValueError("invalid metrics Content-Length")
                    content_length = int(encoded)
                body_at = len(header) + 4
                if (
                    content_length is not None
                    and body_at + content_length > MAX_RESPONSE_BYTES
                ):
                    raise ValueError("metrics HTTP response exceeds 16 KiB")
            if body_at is not None and content_length is not None:
                if len(response) >= body_at + content_length:
                    break
        if body_at is None:
            raise ValueError("incomplete metrics HTTP header")
        body = bytes(response[body_at:])
        if content_length is not None and len(body) != content_length:
            raise ValueError("metrics body differs from Content-Length")
        return body.decode("utf-8")


def poll(target, started, deadline, timeout):
    began = time.monotonic()
    sample = {
        "node": target["name"],
        "started_utc": utc_now(),
        "start_offset_seconds": began - started,
    }
    try:
        raw = read_metrics(target, min(deadline, began + timeout))
        sample["raw_metrics"] = raw
        sample["metrics"] = parse_metrics(raw)
        sample["ok"] = True
    except (OSError, ValueError, UnicodeError) as error:
        sample["ok"] = False
        sample["error"] = f"{type(error).__name__}: {error}"[:512]
    ended = time.monotonic()
    sample["observed_utc"] = utc_now()
    sample["observed_offset_seconds"] = ended - started
    sample["poll_duration_ms"] = (ended - began) * 1000
    return sample


def quantiles(values):
    """Nearest-rank quantiles, including failures when called for all polls."""
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "count": len(ordered),
        **{
            f"p{percent}": ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]
            for percent in (50, 95, 99)
        },
        "max": ordered[-1],
    }


def summarize(samples, names):
    report = {}
    for name in names:
        rows = sorted(
            (row for row in samples if row["node"] == name),
            key=lambda row: row["observed_offset_seconds"],
        )
        good = [row for row in rows if row["ok"]]
        resets, regressions, progress, elapsed = [], [], 0, 0.0
        counters = {}
        for previous, current in zip(good, good[1:]):
            before, after = previous["metrics"], current["metrics"]
            shared_counters = sorted(
                key for key in before.keys() & after.keys() if key.endswith("_total")
            )
            reset_keys = [key for key in shared_counters if after[key] < before[key]]
            if after[UPTIME] < before[UPTIME]:
                reset_keys.append(UPTIME)
            if after[HEIGHT] < before[HEIGHT]:
                regressions.append(current["observed_utc"])
            if reset_keys:
                resets.append(
                    {"observed_utc": current["observed_utc"], "decreased": reset_keys}
                )
            delta = (
                current["observed_offset_seconds"]
                - previous["observed_offset_seconds"]
            )
            if reset_keys or after[HEIGHT] < before[HEIGHT] or delta <= 0:
                continue
            progress += after[HEIGHT] - before[HEIGHT]
            elapsed += delta
            for key in shared_counters:
                counters[key] = counters.get(key, 0) + after[key] - before[key]
        report[name] = {
            "attempts": len(rows),
            "successful_samples": len(good),
            "failed_samples": len(rows) - len(good),
            "first_height": good[0]["metrics"][HEIGHT] if good else None,
            "last_height": good[-1]["metrics"][HEIGHT] if good else None,
            "height_change_first_last": (
                good[-1]["metrics"][HEIGHT] - good[0]["metrics"][HEIGHT]
                if good
                else None
            ),
            "observed_finalized_progress": progress,
            "comparable_elapsed_seconds": elapsed,
            "finalized_blocks_per_second": progress / elapsed if elapsed else None,
            "counter_deltas_between_comparable_samples": counters,
            "observed_reset_boundaries": resets,
            "height_regressions": regressions,
            "poll_duration_ms_all": quantiles([row["poll_duration_ms"] for row in rows]),
            "poll_duration_ms_successful": quantiles(
                [row["poll_duration_ms"] for row in good]
            ),
        }
    return report


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected a finite positive number")
    return number


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--endpoint",
        action="append",
        required=True,
        metavar="NAME=http://IP:PORT/metrics",
    )
    result.add_argument(
        "--duration",
        type=positive,
        default=60.0,
        help="sampling window, 0..3600 seconds",
    )
    result.add_argument(
        "--interval",
        type=positive,
        default=1.0,
        help="round interval, at least 0.1 seconds",
    )
    result.add_argument(
        "--timeout",
        type=positive,
        default=2.0,
        help="absolute per-poll deadline, at most 10 seconds",
    )
    result.add_argument("--workers", type=int, default=4, help="concurrent polls, 1..8")
    result.add_argument(
        "--revision",
        required=True,
        help="operator-supplied exact node build revision",
    )
    result.add_argument(
        "--topology",
        required=True,
        help="operator-supplied roles, hosts, routes and workload description",
    )
    result.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new output directory; never overwritten",
    )
    return result


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def run(args):
    targets = [endpoint(value) for value in args.endpoint]
    names = [target["name"] for target in targets]
    if not 1 <= len(targets) <= 32 or len(set(names)) != len(names):
        raise ValueError("supply 1..32 uniquely named endpoints")
    if (
        args.duration > 3600
        or args.interval < 0.1
        or args.timeout > 10
        or not 1 <= args.workers <= 8
    ):
        raise ValueError(
            "bounds: duration <=3600, interval >=0.1, timeout <=10, workers 1..8"
        )
    if math.ceil(args.duration / args.interval) * len(targets) > MAX_SAMPLES:
        raise ValueError(
            "configuration exceeds 10000 samples; shorten duration or increase interval"
        )
    if (
        not args.revision.strip()
        or not args.topology.strip()
        or len(args.revision) > 256
        or len(args.topology) > 4096
    ):
        raise ValueError(
            "revision/topology must be nonempty and bounded to 256/4096 characters"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {
        "schema_version": 1,
        "started_utc": utc_now(),
        "revision": args.revision,
        "topology": args.topology,
        "sampler_host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
        },
        "configuration": {
            "duration_seconds": args.duration,
            "interval_seconds": args.interval,
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "endpoints": [
                {"name": target["name"], "url": target["url"]}
                for target in targets
            ],
        },
        "interpretation": [
            "Metrics are process-local observations, not independently verified chain facts.",
            "Finalized progress includes catch-up; it is not transaction throughput.",
            "Polling duration quantiles measure HTTP sampling, not consensus latency.",
            "Rates exclude intervals with observed counter/uptime decreases or height regressions.",
            "Restarts without an observed decrease can be missed; gaps can hide activity and resets.",
            "Counters are not atomic snapshots; do not sum replicated node progress into network throughput.",
            "Revision and topology are operator-supplied; this sampler does not verify them.",
        ],
    }
    write_json(args.output / "metadata.json", metadata)
    samples = []
    started = time.monotonic()
    deadline = started + args.duration
    next_round = started
    interrupted = False
    with (args.output / "samples.jsonl").open(
        "x", encoding="utf-8", newline="\n"
    ) as raw:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            try:
                while time.monotonic() < deadline:
                    delay = next_round - time.monotonic()
                    if delay > 0:
                        time.sleep(min(delay, remaining(deadline)))
                    if time.monotonic() >= deadline:
                        break
                    futures = [
                        executor.submit(poll, target, started, deadline, args.timeout)
                        for target in targets
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        sample = future.result()
                        raw.write(
                            json.dumps(sample, sort_keys=True, allow_nan=False) + "\n"
                        )
                        raw.flush()
                        samples.append(
                            {
                                key: value
                                for key, value in sample.items()
                                if key != "raw_metrics"
                            }
                        )
                    next_round += args.interval
                    now = time.monotonic()
                    if next_round < now:
                        next_round += (
                            math.ceil((now - next_round) / args.interval) * args.interval
                        )
            except KeyboardInterrupt:
                interrupted = True
    report = {
        **metadata,
        "finished_utc": utc_now(),
        "elapsed_seconds": time.monotonic() - started,
        "interrupted": interrupted,
        "nodes": summarize(samples, names),
    }
    write_json(args.output / "report.json", report)
    return 130 if interrupted else (1 if any(not row["ok"] for row in samples) else 0)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as error:
        print(f"calibration error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())