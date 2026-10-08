# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Check every locked registry package against OSV under explicit request bounds."""

import argparse
import hashlib
import json
from pathlib import Path
import tomllib
import urllib.error
import urllib.request

LOCKFILES = ("Cargo.lock", "crates/codec/fuzz/Cargo.lock")
ECOSYSTEM = "crates.io"
ENDPOINT = "https://api.osv.dev/v1/querybatch"
REGISTRY = "registry+"
# A package known to carry advisories. An empty result for it proves the query
# path is not actually reaching the database, so "no advisories" is never
# reported from a broken or intercepted connection.
CANARY = ("time", "0.1.44")


def registry_packages(root, lockfiles):
    """Return per-lockfile counts and the union of locked registry name/version pairs."""
    scope, union = {}, set()
    for name in lockfiles:
        path = root / name
        if not path.is_file():
            raise ValueError(f"missing lockfile: {name}")
        packages = tomllib.loads(path.read_text(encoding="utf-8")).get("package", [])
        locked = sorted(
            (p["name"], p["version"])
            for p in packages
            if str(p.get("source", "")).startswith(REGISTRY)
        )
        scope[name] = {
            "packages_digest": digest(locked),
            "registry_packages": len(locked),
            "total_packages": len(packages),
        }
        union.update(locked)
    return scope, sorted(union)


def digest(locked):
    """Identify an exact checked package set independently of lockfile formatting."""
    body = "".join(f"{name}\t{version}\n" for name, version in sorted(locked))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def query(packages, timeout, batch_size, max_requests):
    """Query OSV in bounded batches; any failure or exceeded bound raises."""
    if batch_size < 1 or max_requests < 1:
        raise ValueError("batch size and request cap must be positive")
    batches = [
        packages[index : index + batch_size]
        for index in range(0, len(packages), batch_size)
    ]
    if len(batches) > max_requests:
        raise ValueError(
            f"{len(packages)} packages need {len(batches)} requests, "
            f"cap is {max_requests}"
        )
    found, requests = {}, 0
    for batch in batches:
        body = {
            "queries": [
                {"package": {"name": name, "ecosystem": ECOSYSTEM}, "version": version}
                for name, version in batch
            ]
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "astrolune-advisory-audit",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status != 200:
                    raise ValueError(f"OSV returned status {response.status}")
                results = json.load(response).get("results", [])
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # Never degrade an unreachable database into an empty advisory set.
            raise ValueError(f"OSV query failed, no result is established: {error}")
        requests += 1
        if len(results) != len(batch):
            raise ValueError("OSV returned a result count that does not match the batch")
        for (name, version), result in zip(batch, results):
            if result.get("next_page_token"):
                raise ValueError(f"paged OSV result for {name} {version} is unbounded")
            identifiers = sorted(
                {vulnerability["id"] for vulnerability in result.get("vulns", [])}
            )
            if identifiers:
                found[f"{name} {version}"] = identifiers
    return found, requests


def audit(
    root,
    lockfiles=LOCKFILES,
    offline=False,
    snapshot_path=None,
    timeout=30.0,
    batch_size=64,
    max_requests=16,
):
    """Produce a deterministic advisory report from a live query or a pinned snapshot."""
    scope, packages = registry_packages(root, lockfiles)
    union = digest(packages)
    report = {
        "batch_size": batch_size,
        "database": "OSV" if not offline else "pinned OSV snapshot",
        "ecosystem": ECOSYSTEM,
        "endpoint": ENDPOINT,
        "lockfiles": scope,
        "packages_digest": union,
        "request_cap": max_requests,
        "scope": list(lockfiles),
        "timeout_seconds": timeout,
        "unique_registry_packages": len(packages),
    }
    if offline:
        if snapshot_path is None or not snapshot_path.is_file():
            raise ValueError("offline mode requires a committed advisory snapshot")
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        if snapshot.get("packages_digest") != union:
            raise ValueError(
                "snapshot does not cover these exact locked packages; "
                "re-run without --offline to refresh it"
            )
        if snapshot.get("ecosystem") != ECOSYSTEM:
            raise ValueError("snapshot records a different ecosystem")
        report["determination"] = "verified against pinned snapshot"
        report["requests"] = 0
        report["snapshot_queried_on"] = snapshot["queried_on"]
        report["advisories"] = dict(sorted(snapshot.get("advisories", {}).items()))
    else:
        canary, _ = query([CANARY], timeout, 1, 1)
        if not canary:
            raise ValueError(
                f"canary {CANARY[0]} {CANARY[1]} returned no advisory; "
                "the database path is not trustworthy"
            )
        advisories, requests = query(packages, timeout, batch_size, max_requests)
        report["determination"] = "queried live"
        report["requests"] = requests + 1
        report["advisories"] = dict(sorted(advisories.items()))
    report["advisory_count"] = sum(len(ids) for ids in report["advisories"].values())
    report["vulnerable_packages"] = len(report["advisories"])
    return report, packages


def snapshot_document(report, packages, queried_on):
    """Pin exactly what a live query established, for later offline verification."""
    if report["determination"] != "queried live":
        raise ValueError("only a live query may pin a snapshot")
    return {
        "advisories": report["advisories"],
        "copyright": "Copyright (c) 2026 Ankerin",
        "ecosystem": ECOSYSTEM,
        "endpoint": ENDPOINT,
        "license": "MIT",
        "packages": [f"{name} {version}" for name, version in packages],
        "packages_digest": report["packages_digest"],
        "queried_on": queried_on,
        "scope": report["scope"],
    }


def write(path, document):
    """Sorted keys and a fixed newline keep committed reports byte-comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lockfile", action="append", default=None)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=Path(__file__).with_name("advisory-snapshot.json"),
    )
    parser.add_argument("--write-snapshot", action="store_true")
    parser.add_argument("--queried-on", default=None)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--max-requests", type=int, default=16)
    parser.add_argument(
        "--output", type=Path, default=Path("target/dependency-advisories.json")
    )
    options = parser.parse_args()
    if options.write_snapshot and (options.offline or options.queried_on is None):
        parser.error("--write-snapshot needs a live query and an explicit --queried-on")
    try:
        report, packages = audit(
            Path.cwd(),
            tuple(options.lockfile or LOCKFILES),
            options.offline,
            options.snapshot,
            options.timeout,
            options.batch_size,
            options.max_requests,
        )
    except ValueError as error:
        raise SystemExit(f"dependency advisory audit failed: {error}")
    write(options.output, report)
    if options.write_snapshot:
        write(
            options.snapshot,
            snapshot_document(report, packages, options.queried_on),
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["advisory_count"]:
        raise SystemExit(
            f"{report['advisory_count']} advisories affect "
            f"{report['vulnerable_packages']} locked packages"
        )


if __name__ == "__main__":
    main()
