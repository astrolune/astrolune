# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Independent framing, commitments and epoch boundaries; not signature verification."""
import hashlib
from pathlib import Path
import struct
import unittest

from test_protocol_fixtures import Reader, digest

ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests/integration/fixtures/governance-v1"
)


class GovernanceFixtureTests(unittest.TestCase):
    def test_manifest_and_next_epoch_parameters(self):
        names = set()
        for line in (
            (ROOT / "MANIFEST.blake2s")
            .read_text(encoding="utf-8")
            .splitlines()
        ):
            expected, size, name = line.split()
            self.assertNotIn(name, names)
            path = ROOT / name
            self.assertTrue(path.resolve().is_relative_to(ROOT.resolve()))
            data = path.read_bytes()
            self.assertEqual(
                (len(data), hashlib.blake2s(data).hexdigest()),
                (int(size), expected),
            )
            names.add(name)
        self.assertEqual(names, {path.name for path in ROOT.glob("*.bin")})
        self.assertEqual(len(names), 18)
        read = lambda name: (ROOT / name).read_bytes()
        config = Reader(read("configuration.bin"))
        self.assertEqual(config.take(8), b"ALPTCF02")
        config.blob()
        config.take(56)
        policy = config.take(104)
        config.finish()
        self.assertEqual(int.from_bytes(policy[:8], "little"), 2)
        namespace = digest(
            b"astrolune.potb.configuration.v2", read("configuration.bin")
        )
        request = read("request.bin")
        self.assertEqual(len(request), 188)
        self.assertEqual(request[:8], b"ALGVRQ01")
        self.assertEqual(request[12:44], namespace)
        self.assertEqual(int.from_bytes(request[44:52], "little"), 1)
        self.assertEqual(request[52:84], namespace)
        self.assertEqual(int.from_bytes(request[116:124], "little"), 3)
        capacity, prices = request[124:156], request[156:188]
        self.assertEqual(struct.unpack("<QQQQ", prices), (2, 1, 2, 1))
        request_id = digest(b"astrolune.governance.request.v1", request)
        certificate = Reader(read("certificate.bin"))
        self.assertEqual(certificate.take(8), b"ALGVCF01")
        self.assertEqual(certificate.take(188), request)
        self.assertEqual(certificate.take(1), b"\x04")
        voters = []
        for _ in range(4):
            self.assertEqual(certificate.take(8), b"ALGVAP01")
            self.assertEqual(certificate.take(32), request_id)
            voters.append(certificate.take(32))
            self.assertNotEqual(certificate.take(64), bytes(64))
        certificate.finish()
        self.assertEqual(voters, sorted(set(voters)))
        network = Reader(read("network.bin"))
        self.assertEqual(network.take(8), b"ALNX\x01\0\0\0")
        self.assertEqual(network.take(32), namespace)
        self.assertEqual(network.u32(), 1)
        self.assertEqual(network.take(1), b"\x08")
        self.assertEqual(network.blob(), read("certificate.bin"))
        network.finish()
        parent = namespace
        for height in range(1, 4):
            parameters = Reader(read(f"height-{height}-parameters.bin"))
            self.assertEqual(parameters.take(8), b"ALGVST01")
            self.assertEqual(parameters.take(104), policy)
            active = parameters.take(64)
            self.assertEqual(parameters.take(1), bytes([int(height == 1)]))
            if height == 1:
                self.assertEqual(
                    active,
                    struct.pack("<QQQQQQQQ", *([1000000] * 4), 1, 0, 0, 0),
                )
                self.assertEqual(
                    int.from_bytes(parameters.take(8), "little"), 3
                )
                self.assertEqual(parameters.take(64), capacity + prices)
            else:
                self.assertEqual(active, capacity + prices)
            parameters.finish()
            handoff = Reader(read(f"height-{height}-handoff.bin"))
            self.assertEqual(handoff.take(8), b"ALPTHF01")
            header = handoff.take(200)
            self.assertEqual(int.from_bytes(header[:8], "little"), height)
            self.assertEqual(header[8:40], parent)
            self.assertEqual(
                header[168:200],
                struct.pack("<QQQQ", *([1000000] * 4))
                if height < 3
                else capacity,
            )
            parent = digest(b"astrolune.block.v1", header)
            self.assertEqual(handoff.blob()[56:88], parent)
            self.assertEqual(handoff.blob(), read(f"height-{height}-batch.bin"))
            self.assertIn(read(f"height-{height}-state.bin"), handoff.blob())
            handoff.finish()


if __name__ == "__main__":
    unittest.main()