# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Native archive contents, identity and reproducibility regression tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "packager", Path(__file__).with_name("package-build.py")
)
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class PackageTests(unittest.TestCase):
    def test_metadata_cannot_change_archive_and_every_file_is_committed(self):
        for target in PACKAGER.TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binaries = root / "bin"
                binaries.mkdir()
                suffix = ".exe" if "windows" in target else ""
                for name in PACKAGER.BINARIES:
                    (binaries / (name + suffix)).write_bytes(
                        b"native-test-input:" + name.encode()
                    )
                for name in ("LICENSE", "README.md", "Cargo.lock", "rust-toolchain.toml"):
                    (root / name).write_bytes(name.encode())
                (root / "docs/assets").mkdir(parents=True)
                (root / "docs/assets/banner.png").write_bytes(b"image-fixture")
                (root / "docs/protocol.md").write_bytes(b"protocol-fixture")
                identity = (target, "a" * 40, "rustc fixture\n")
                first = PACKAGER.package(root, binaries, root / "first", *identity)
                for path in (*binaries.iterdir(), root / "README.md"):
                    os.utime(path, (1_234_567_890, 1_234_567_890))
                    path.chmod(0o777)
                second = PACKAGER.package(root, binaries, root / "second", *identity)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                digest = hashlib.sha256(first.read_bytes()).hexdigest()
                self.assertEqual(
                    (first.parent / "SHA256SUMS").read_text(),
                    f"{digest}  {first.name}\n",
                )
                with tarfile.open(first) as archive:
                    members = archive.getmembers()
                    self.assertEqual(
                        [m.name for m in members],
                        sorted(m.name for m in members),
                    )
                    metadata = json.load(archive.extractfile("BUILD.json"))
                    self.assertEqual(
                        set(metadata["files"]),
                        {m.name for m in members} - {"BUILD.json"},
                    )
                    self.assertIn("dns" + suffix, metadata["files"])
                    for member in members:
                        self.assertEqual(
                            (member.uid, member.gid, member.mtime), (0, 0, 0)
                        )
                        self.assertEqual((member.uname, member.gname), ("", ""))
                        self.assertTrue(member.isfile())
                        if member.name != "BUILD.json":
                            self.assertEqual(
                                hashlib.sha256(
                                    archive.extractfile(member).read()
                                ).hexdigest(),
                                metadata["files"][member.name],
                            )
                (binaries / ("dns" + suffix)).write_bytes(b"changed-binary")
                changed = PACKAGER.package(root, binaries, root / "changed", *identity)
                self.assertNotEqual(first.read_bytes(), changed.read_bytes())

    def test_qualification_binds_compiler_target_and_exact_binary_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            target = PACKAGER.TARGETS[1]
            for name in PACKAGER.BINARIES:
                (binaries / (name + ".exe")).write_bytes(name.encode())
            for name in ("LICENSE", "README.md", "Cargo.lock", "rust-toolchain.toml"):
                (root / name).write_bytes(name.encode())
            report = {
                "target": target,
                "independent_builds": 2,
                "rustc": "rustc pinned fixture",
                "sha256": {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in binaries.iterdir()
                },
            }
            arguments = (root, binaries, root / "valid", target, "a" * 40, report["rustc"])
            archive = PACKAGER.package(*arguments, qualification=report)
            with tarfile.open(archive) as bundle:
                self.assertEqual(
                    json.load(bundle.extractfile("BUILD.json"))["rustc"],
                    report["rustc"],
                )
            for change in (
                {"target": PACKAGER.TARGETS[0]},
                {"independent_builds": 1},
                {"sha256": {}},
                {"rustc": "rustc shadow"},
            ):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    PACKAGER.package(
                        root,
                        binaries,
                        root / "rejected",
                        target,
                        "a" * 40,
                        report["rustc"],
                        qualification=report | change,
                    )
                self.assertFalse((root / "rejected").exists())
            (binaries / "cli.exe").write_bytes(b"changed after qualification")
            with self.assertRaises(ValueError):
                PACKAGER.package(
                    root,
                    binaries,
                    root / "rejected",
                    target,
                    "a" * 40,
                    report["rustc"],
                    qualification=report,
                )
            self.assertFalse((root / "rejected").exists())

    def test_incomplete_build_or_invalid_identity_never_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target, revision, epoch in (
                ("../escape", "a" * 40, 0),
                (PACKAGER.TARGETS[0], "main", 0),
                (PACKAGER.TARGETS[0], "a" * 40, -1),
                (PACKAGER.TARGETS[0], "a" * 40, 0),
            ):
                with self.subTest(target=target, revision=revision, epoch=epoch):
                    with self.assertRaises(ValueError):
                        PACKAGER.package(
                            root,
                            root,
                            root / "output",
                            target,
                            revision,
                            "rustc",
                            epoch,
                        )
                    self.assertFalse((root / "output").exists())

    def test_signable_manifest_commits_to_the_archive_and_every_packaged_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            for name in PACKAGER.BINARIES:
                (binaries / name).write_bytes(b"native-test-input:" + name.encode())
            for name in ("LICENSE", "README.md", "Cargo.lock", "rust-toolchain.toml"):
                (root / name).write_bytes(name.encode())
            identity = (PACKAGER.TARGETS[0], "b" * 40, "rustc fixture\n")
            archive = PACKAGER.package(root, binaries, root / "first", *identity)
            output = archive.parent
            manifest = json.loads((output / "MANIFEST.json").read_bytes())
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(manifest["archive"], archive.name)
            self.assertEqual(manifest["archive_sha256"], digest)
            self.assertFalse(manifest["release"])
            self.assertEqual((output / "SHA256SUMS").read_text(), f"{digest}  {archive.name}\n")
            with tarfile.open(archive) as bundle:
                build = json.load(bundle.extractfile("BUILD.json"))
                for member in bundle.getmembers():
                    if member.name != "BUILD.json":
                        self.assertEqual(
                            hashlib.sha256(bundle.extractfile(member).read()).hexdigest(),
                            manifest["files"][member.name],
                        )
            # The manifest adds exactly the archive binding to the in-archive record.
            self.assertEqual(
                {k: v for k, v in manifest.items() if k not in ("archive", "archive_sha256")},
                build,
            )
            # Manifest bytes are a deterministic function of the inputs alone, so a
            # reproduced build yields an identical manifest and an identical signature.
            repeated = PACKAGER.package(root, binaries, root / "second", *identity)
            self.assertEqual(
                (output / "MANIFEST.json").read_bytes(),
                (repeated.parent / "MANIFEST.json").read_bytes(),
            )
            # Only the explicit flag records release intent; nothing is published.
            flagged = PACKAGER.package(
                root, binaries, root / "third", *identity, release=True
            )
            marked = json.loads((flagged.parent / "MANIFEST.json").read_bytes())
            self.assertTrue(marked["release"])
            self.assertNotEqual(
                (output / "MANIFEST.json").read_bytes(),
                (flagged.parent / "MANIFEST.json").read_bytes(),
            )
            # The flag is inside the archive too, so it changes the archive digest.
            self.assertNotEqual(archive.read_bytes(), flagged.read_bytes())
            self.assertNotEqual(marked["archive_sha256"], manifest["archive_sha256"])
            # No signature is produced, and no authority key exists in this repository.
            for produced in (output, flagged.parent):
                self.assertFalse((produced / PACKAGER.SIGNATURE_NAME).exists())
                self.assertEqual(
                    sorted(p.name for p in produced.iterdir()),
                    ["MANIFEST.json", "SHA256SUMS", archive.name],
                )


if __name__ == "__main__":
    unittest.main()