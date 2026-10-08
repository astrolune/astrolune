# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Licence-check every locked package and bound exactly what cargo-deny omits."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

# cargo-deny builds its crate graph from what cargo would actually compile, so
# its licence and ban policy never reaches lockfile entries that no target and
# feature combination pulls in, nor any dev-dependency edge. Those omissions are
# recorded in the committed baseline with the reason measured for each, and this
# script evaluates the full locked set itself so the policy verdict covers it.
REASONS = (
    # Declared under [dev-dependencies] of a workspace member. Compiled by
    # `cargo test`, yet absent from the cargo-deny graph.
    "workspace dev-dependency",
    # Reached only through an optional dependency of a third-party crate whose
    # activating feature is never enabled. Never compiled.
    "disabled optional dependency",
    # Reached only through a [target.'cfg(any())'] edge, which is false for every
    # platform. Never compiled.
    "cfg(any()) gated dependency",
)
OPERATORS = ("AND", "OR", "WITH")


def tokenize(expression):
    """Split an SPDX expression, treating the legacy slash form as OR."""
    text = expression.replace("/", " OR ").replace("(", " ( ").replace(")", " ) ")
    tokens = text.split()
    if not tokens:
        raise ValueError("empty licence expression")
    return tokens


def parse(expression):
    """Parse an SPDX expression into a tree; a malformed expression raises."""
    tokens = tokenize(expression)
    position = 0

    def take():
        nonlocal position
        if position >= len(tokens):
            raise ValueError(f"truncated licence expression: {expression!r}")
        position += 1
        return tokens[position - 1]

    def peek():
        return tokens[position] if position < len(tokens) else None

    def atom():
        token = take()
        if token == "(":
            inner = disjunction()
            if take() != ")":
                raise ValueError(f"unbalanced parentheses: {expression!r}")
            return inner
        if token in OPERATORS or token == ")":
            raise ValueError(f"operator in licence position: {expression!r}")
        if peek() == "WITH":
            take()
            exception = take()
            if exception in OPERATORS or exception in ("(", ")"):
                raise ValueError(f"missing WITH exception: {expression!r}")
            return ("id", f"{token} WITH {exception}")
        return ("id", token)

    def conjunction():
        nodes = [atom()]
        while peek() == "AND":
            take()
            nodes.append(atom())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def disjunction():
        nodes = [conjunction()]
        while peek() == "OR":
            take()
            nodes.append(conjunction())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    tree = disjunction()
    if position != len(tokens):
        raise ValueError(f"trailing tokens in licence expression: {expression!r}")
    return tree


def satisfied(tree, allowed):
    """Decide whether an allow list satisfies a parsed SPDX expression."""
    kind, value = tree
    if kind == "id":
        return value in allowed
    if kind == "or":
        return any(satisfied(node, allowed) for node in value)
    return all(satisfied(node, allowed) for node in value)


def policy(path):
    """Read the allow list and per-crate exceptions this repository enforces."""
    document = tomllib.loads(path.read_text(encoding="utf-8")).get("licenses", {})
    allowed = frozenset(document.get("allow", []))
    if not allowed:
        raise ValueError("deny.toml grants no licences; refusing to pass anything")
    exceptions = {}
    for entry in document.get("exceptions", []):
        name = entry.get("crate") or entry.get("name")
        if name is None or "@" in str(name) or entry.get("version") is not None:
            # A version-qualified exception would apply to fewer packages than
            # this script would grant it to; never widen policy by accident.
            raise ValueError(f"unsupported version-qualified exception: {entry}")
        exceptions[name] = frozenset(entry.get("allow", []))
    return allowed, exceptions, bool(document.get("private", {}).get("ignore", False))


def locked_packages(metadata):
    """Return every resolved package as name, version, licence and locality."""
    packages = {}
    for package in metadata["packages"]:
        key = (package["name"], package["version"])
        expression = package.get("license")
        if not expression:
            # cargo-deny falls back to scoring license-file text. This script has
            # no licence corpus, so an absent expression is never approved here.
            raise ValueError(f"{key[0]} {key[1]} declares no license expression")
        packages[key] = {"license": expression, "local": package["source"] is None}
    if not packages:
        raise ValueError("cargo metadata resolved no packages")
    return packages


def deny_graph(text):
    """Read the crate graph cargo-deny actually evaluated from its TSV listing."""
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if not lines or not lines[0].startswith("crate\t"):
        raise ValueError("not a `cargo deny list --format tsv` listing")
    graph = set()
    for line in lines[1:]:
        crate = line.split("\t", 1)[0]
        name, separator, version = crate.rpartition("@")
        if not separator:
            raise ValueError(f"unparsable crate column: {crate!r}")
        graph.add((name, version))
    if not graph:
        raise ValueError("cargo-deny listed an empty crate graph")
    return graph


def deny_listing(root, config):
    """Ask cargo-deny which crates its policy reaches; any failure raises."""
    command = [
        "cargo",
        "deny",
        "--locked",
        "list",
        "--config",
        str(config),
        "--format",
        "tsv",
    ]
    try:
        finished = subprocess.run(
            command, cwd=root, capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"cargo-deny crate listing failed, no bound is established: {error}")
    return finished.stdout


def cargo_metadata(root):
    """Resolve the locked, all-features package set; any failure raises."""
    command = [
        "cargo",
        "metadata",
        "--all-features",
        "--locked",
        "--format-version",
        "1",
    ]
    try:
        finished = subprocess.run(
            command, cwd=root, capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"cargo metadata failed, no result is established: {error}")
    return json.loads(finished.stdout)


def digest(entries):
    """Identify an exact package set independently of file formatting."""
    body = "".join(f"{name}\t{version}\n" for name, version in sorted(entries))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def duplicates(packages):
    """Name every crate resolved at more than one version across the whole lock."""
    versions = {}
    for name, version in packages:
        versions.setdefault(name, []).append(version)
    return {
        name: sorted(found)
        for name, found in sorted(versions.items())
        if len(found) > 1
    }


def evaluate(packages, allowed, exceptions, ignore_private):
    """Apply the allow list to every locked package, not just the graph."""
    rejected = {}
    for (name, version), facts in sorted(packages.items()):
        if ignore_private and facts["local"]:
            continue
        grant = allowed | exceptions.get(name, frozenset())
        if not satisfied(parse(facts["license"]), grant):
            rejected[f"{name} {version}"] = facts["license"]
    return rejected


def coverage(packages, graph, baseline):
    """Compare the uncovered set against the committed bound and name any drift."""
    recorded = {
        (entry["name"], entry["version"]): entry
        for entry in baseline.get("uncovered", [])
    }
    for entry in recorded.values():
        if entry.get("reason") not in REASONS:
            raise ValueError(f"baseline records an unknown reason: {entry.get('reason')}")
    uncovered = set(packages) - graph
    unknown = graph - set(packages)
    if unknown:
        raise ValueError(
            "cargo-deny evaluated crates absent from cargo metadata: "
            + ", ".join(f"{name} {version}" for name, version in sorted(unknown))
        )
    added = sorted(uncovered - set(recorded))
    removed = sorted(set(recorded) - uncovered)
    relicensed = sorted(
        f"{name} {version}"
        for name, version in sorted(uncovered & set(recorded))
        if recorded[(name, version)].get("license") != packages[(name, version)]["license"]
    )
    return {
        "added": [f"{name} {version}" for name, version in added],
        "digest": digest(uncovered),
        "graph_packages": len(graph),
        "locked_packages": len(packages),
        "relicensed": relicensed,
        "removed": [f"{name} {version}" for name, version in removed],
        "uncovered": [
            {
                "license": packages[(name, version)]["license"],
                "name": name,
                "reason": recorded.get((name, version), {}).get("reason"),
                "version": version,
            }
            for name, version in sorted(uncovered)
        ],
        "uncovered_packages": len(uncovered),
    }


def check(root, config, baseline, metadata=None, listing=None):
    """Produce a deterministic verdict over the full locked package set."""
    allowed, exceptions, ignore_private = policy(config)
    packages = locked_packages(metadata or cargo_metadata(root))
    graph = deny_graph(listing if listing is not None else deny_listing(root, config))
    bound = coverage(packages, graph, baseline)
    rejected = evaluate(packages, allowed, exceptions, ignore_private)
    recorded_duplicates = {
        name: sorted(versions)
        for name, versions in sorted(baseline.get("duplicates", {}).items())
    }
    found_duplicates = duplicates(packages)
    report = {
        "allowed_licenses": sorted(allowed),
        "baseline_duplicates": recorded_duplicates,
        "cargo_deny_graph_packages": bound["graph_packages"],
        "duplicates": found_duplicates,
        "ignored_private_packages": ignore_private,
        "licensed_packages": len(packages) - (
            sum(1 for facts in packages.values() if facts["local"])
            if ignore_private
            else 0
        ),
        "locked_packages": bound["locked_packages"],
        "new_duplicates": sorted(set(found_duplicates) - set(recorded_duplicates)),
        "rejected_licenses": rejected,
        "uncovered_added": bound["added"],
        "uncovered_digest": bound["digest"],
        "uncovered_packages": bound["uncovered_packages"],
        "uncovered_relicensed": bound["relicensed"],
        "uncovered_removed": bound["removed"],
        "uncovered_set": bound["uncovered"],
    }
    failures = []
    if rejected:
        failures.append(
            f"{len(rejected)} locked packages carry licences the policy does not allow"
        )
    if bound["added"]:
        failures.append(
            "the cargo-deny coverage gap grew: " + ", ".join(bound["added"])
        )
    if bound["removed"]:
        failures.append(
            "the cargo-deny coverage gap shrank, refresh the baseline: "
            + ", ".join(bound["removed"])
        )
    if bound["relicensed"]:
        failures.append(
            "baseline licences no longer match the manifests: "
            + ", ".join(bound["relicensed"])
        )
    if report["new_duplicates"]:
        failures.append(
            "new duplicate versions outside the cargo-deny graph: "
            + ", ".join(report["new_duplicates"])
        )
    report["failures"] = failures
    return report


def baseline_document(report, measured_on, cargo_deny):
    """Pin the exact bound a measurement established, for later comparison."""
    if report["rejected_licenses"]:
        raise ValueError("refusing to pin a baseline over rejected licences")
    return {
        "cargo_deny": cargo_deny,
        "copyright": "Copyright (c) 2026 Ankerin",
        "duplicates": report["duplicates"],
        "graph_packages": report["cargo_deny_graph_packages"],
        "license": "MIT",
        "locked_packages": report["locked_packages"],
        "measured_on": measured_on,
        "uncovered": report["uncovered_set"],
        "uncovered_digest": report["uncovered_digest"],
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
    parser.add_argument("--config", type=Path, default=Path("deny.toml"))
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).with_name("deny-coverage-baseline.json"),
    )
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument("--deny-list", type=Path, default=None)
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--measured-on", default=None)
    parser.add_argument("--cargo-deny-version", default=None)
    parser.add_argument(
        "--output", type=Path, default=Path("target/dependency-license-coverage.json")
    )
    options = parser.parse_args()
    if options.write_baseline and (
        options.measured_on is None or options.cargo_deny_version is None
    ):
        parser.error(
            "--write-baseline needs explicit --measured-on and --cargo-deny-version"
        )
    try:
        baseline = (
            json.loads(options.baseline.read_text(encoding="utf-8"))
            if options.baseline.is_file()
            else {}
        )
        if not baseline and not options.write_baseline:
            raise ValueError(
                "no committed coverage baseline; the gap would be unbounded"
            )
        report = check(
            Path.cwd(),
            options.config,
            baseline,
            json.loads(options.metadata.read_text(encoding="utf-8"))
            if options.metadata
            else None,
            options.deny_list.read_text(encoding="utf-8")
            if options.deny_list
            else None,
        )
    except ValueError as error:
        raise SystemExit(f"dependency licence coverage check failed: {error}")
    write(options.output, report)
    if options.write_baseline:
        write(
            options.baseline,
            baseline_document(report, options.measured_on, options.cargo_deny_version),
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["failures"] and not options.write_baseline:
        raise SystemExit("; ".join(report["failures"]))


if __name__ == "__main__":
    main()
