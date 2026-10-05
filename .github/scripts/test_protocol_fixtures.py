# Copyright (c) 2026 Astrolune contributors
# SPDX-License-Identifier: MIT

"""Independent stdlib checks for frozen framing and BLAKE2s commitments.

This is deliberately not an Ed25519/VRF or execution implementation. Those
properties are checked by authenticated replay in the Rust compatibility suite.
"""
import hashlib
from pathlib import Path
import struct
import unittest

ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests/integration/fixtures/protocol-v1"
)


def digest(domain, message):
    return hashlib.blake2s(
        b"astrolune.v1."
        + struct.pack("<Q", len(domain))
        + domain
        + message
    ).digest()


def merkle(leaves):
    while len(leaves) > 1:
        leaves = [
            hashlib.blake2s(
                b"\x01" + leaves[i] + leaves[i + 1] + bytes(4)
            ).digest()
            if i + 1 < len(leaves)
            else leaves[i]
            for i in range(0, len(leaves), 2)
        ]
    return leaves[0] if leaves else bytes(32)


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        end = self.offset + count
        if count < 0 or end > len(self.data):
            raise ValueError("truncated fixture")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def blob(self):
        return self.take(self.u32())

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError("trailing fixture data")


class ProtocolFixtureTests(unittest.TestCase):
    def test_manifest_is_complete_and_matches_an_independent_hash_provider(self):
        names = set()
        for line in (
            (ROOT / "MANIFEST.blake2s")
            .read_text(encoding="utf-8")
            .splitlines()
        ):
            expected, length, name = line.split()
            path = ROOT / name
            self.assertTrue(path.resolve().is_relative_to(ROOT.resolve()))
            self.assertNotIn(name, names)
            names.add(name)
            payload = path.read_bytes()
            self.assertEqual(len(payload), int(length), name)
            self.assertEqual(
                hashlib.blake2s(payload).hexdigest(), expected, name
            )
        self.assertEqual(
            names,
            {
                path.relative_to(ROOT).as_posix()
                for path in ROOT.rglob("*.bin")
            },
        )
        self.assertEqual(len(names), 50)

    def test_genesis_network_headers_transactions_and_receipts_are_consistent(self):
        for version in (1, 2):
            directory = ROOT / f"genesis-v{version}"
            genesis = (directory / "genesis.bin").read_bytes()
            self.assertEqual(len(genesis), 306)
            self.assertEqual(struct.unpack_from("<HI", genesis), (version, 7))
            self.assertEqual(
                struct.unpack_from("<QQIQ", genesis, 38),
                (4 if version == 1 else 3, 1, 2, 4),
            )
            identities = [
                genesis[66 + i * 48 : 98 + i * 48] for i in range(4)
            ]
            self.assertEqual(identities, sorted(identities))
            keys = (directory / "public-keys.bin").read_bytes()
            self.assertEqual(
                set(identities),
                {
                    hashlib.blake2s(keys[i : i + 32]).digest()
                    for i in range(0, 128, 32)
                },
            )
            parent = network = digest(b"astrolune.genesis.v1", genesis)
            for height in (1, 2):
                with self.subTest(profile=version, height=height):
                    parent = self.check_block(
                        directory,
                        version,
                        height,
                        network,
                        parent,
                        genesis[6:38],
                    )

    def check_block(self, directory, version, height, network, parent, capacity):
        def read(kind):
            return (directory / f"height-{height}-{kind}.bin").read_bytes()

        header = read("header")
        self.assertEqual(len(header), 200)
        self.assertEqual(int.from_bytes(header[:8], "little"), height)
        self.assertEqual(header[8:40], parent)
        self.assertEqual(header[168:], capacity)
        block_hash = digest(b"astrolune.block.v1", header)
        cert = read("certificate")
        self.assertEqual(cert[:8], b"ALFC\x01\0\0\0")
        self.assertEqual(struct.unpack_from("<IQI", cert, 8), (7, height, 0))
        self.assertEqual(cert[24:56], header[136:168])
        self.assertEqual(cert[56:88], block_hash)
        count = int.from_bytes(cert[88:92], "little")
        self.assertEqual(len(cert), 92 + count * 96)
        envelope = Reader(read("network"))
        self.assertEqual(envelope.take(8), b"ALNX\x01\0\0\0")
        self.assertEqual(envelope.take(32), network)
        self.assertEqual(envelope.u32(), 1)
        self.assertEqual(envelope.take(1), b"\x02")
        body = Reader(envelope.blob())
        self.assertEqual(envelope.blob(), cert)
        envelope.finish()
        self.assertEqual(body.blob(), header)
        transactions = [body.blob() for _ in range(body.u32())]
        body.finish()
        self.assertEqual(len(transactions), version)
        self.assertEqual(transactions[-1], read("transaction"))
        ids = [digest(b"astrolune.tx.id.v1", tx) for tx in transactions]
        self.assertEqual(merkle(ids), header[40:72])
        effects = Reader(read("effects"))
        self.assertEqual(
            effects.take(8), b"ALEFFECT" if version == 1 else b"ALEFF002"
        )
        receipts = [effects.take(97) for _ in range(effects.u32())]
        self.assertEqual([receipt[:32] for receipt in receipts], ids)
        self.assertEqual(
            merkle(
                [
                    digest(b"astrolune.receipt.v1", receipt)
                    for receipt in receipts
                ]
            ),
            header[104:136],
        )
        effects.blob()  # genesis membership witness is authenticated by the Rust test
        if version == 2:
            effects.blob()  # exact next-committee witness
        effects.finish()
        return block_hash


if __name__ == "__main__":
    unittest.main()