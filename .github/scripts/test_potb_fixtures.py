# Copyright (c) 2026 Astrolune contributors
# SPDX-License-Identifier: MIT

"""Independent framing, namespace, batch and history checks; not signature verification."""
import hashlib
from pathlib import Path
import struct
import unittest

from test_protocol_fixtures import Reader, digest

ROOT = Path(__file__).resolve().parents[2] / "tests/integration/fixtures/potb-v1"


class PotbFixtureTests(unittest.TestCase):
    def test_manifest_covers_exactly_eight_independently_hashed_objects(self):
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
            self.assertEqual(len(data), int(size))
            self.assertEqual(hashlib.blake2s(data).hexdigest(), expected)
            names.add(name)
        self.assertEqual(names, {path.name for path in ROOT.glob("*.bin")})
        self.assertEqual(len(names), 8)

    def test_configuration_inclusion_history_and_age_match_frozen_handoffs(self):
        def read(name):
            return (ROOT / name).read_bytes()

        config_bytes = read("configuration.bin")
        config = Reader(config_bytes)
        self.assertEqual(config.take(8), b"ALPTCF01")
        genesis, policy = config.blob(), config.take(56)
        config.finish()
        self.assertEqual(struct.unpack_from("<HI", genesis), (2, 71))
        self.assertEqual(int.from_bytes(policy[:8], "little"), 2)
        self.assertEqual(
            [
                int.from_bytes(policy[i : i + 16], "little")
                for i in (8, 24, 40)
            ],
            [10, 3, 20],
        )
        namespace = digest(b"astrolune.potb.configuration.v1", config_bytes)
        self.assertNotEqual(namespace, digest(b"astrolune.genesis.v1", genesis))
        parent = namespace
        previous_age = self.check_state(
            read("initial-state.bin"), policy, namespace, 1, bytes(32), b""
        )
        roots = []
        for height in (1, 2):
            handoff = Reader(read(f"height-{height}-handoff.bin"))
            self.assertEqual(handoff.take(8), b"ALPTHF01")
            header = handoff.take(200)
            cert, batch, witness = handoff.blob(), handoff.blob(), handoff.blob()
            handoff.finish()
            self.assertEqual(int.from_bytes(header[:8], "little"), height)
            self.assertEqual(header[8:40], parent)
            parent = digest(b"astrolune.block.v1", header)
            self.assertEqual(cert[56:88], parent)
            self.assertEqual(cert[24:56], header[136:168])
            self.assertEqual(batch, read(f"height-{height}-batch.bin"))
            self.assertEqual(batch[:8], b"ALPTBT01")
            roots.append(
                digest(
                    b"astrolune.committee.history.leaf.v1",
                    struct.pack("<I", 71)
                    + namespace
                    + struct.pack("<Q", height)
                    + header[136:168],
                )
            )
            frontier = (
                roots[0]
                if height == 1
                else digest(
                    b"astrolune.committee.history.node.v1", b"".join(roots)
                )
            )
            state_bytes = read(f"height-{height}-state.bin")
            self.assertIn(state_bytes, witness)
            ages = self.check_state(
                state_bytes,
                policy,
                namespace,
                height + 1,
                digest(b"astrolune.potb.batch.v1", batch),
                frontier,
            )
            if height == 1:
                self.assertEqual(set(ages), set(previous_age))
                self.assertEqual(set(ages.values()), {1})
            else:
                self.assertEqual(len(ages), 5)
                self.assertEqual(sorted(ages.values()), [0, 1, 2, 2, 2])
            previous_age = ages

    def check_state(self, data, policy, namespace, height, batch_hash, frontier):
        state = Reader(data)
        self.assertEqual(state.take(8), b"ALPTST01")
        self.assertEqual(state.take(56), policy)
        self.assertEqual(state.take(32), batch_hash)
        committee, history = state.blob(), state.blob()
        self.assertEqual(committee[:8], b"ALCMST01")
        self.assertEqual(struct.unpack_from("<I", committee, 8), (71,))
        self.assertEqual(committee[12:44], namespace)
        self.assertEqual(int.from_bytes(committee[44:52], "little"), height)
        self.assertEqual(
            history,
            b"ALCHST01"
            + struct.pack("<I", 71)
            + namespace
            + struct.pack("<Q", height - 1)
            + frontier,
        )
        records, ages, exclusions = {}, {}, 0
        for _ in range(state.take(1)[0]):
            key = state.take(32)
            identity = hashlib.blake2s(key).digest()
            admitted, age = struct.unpack("<QQ", state.take(16))
            excluded = state.take(1)[0]
            self.assertIn(excluded, (0, 1))
            if excluded:
                self.assertNotEqual(state.take(32), bytes(32))
                exclusions += 1
            self.assertLessEqual(age, height - 1 - admitted)
            self.assertNotIn(identity, records)
            records[identity] = None if excluded else min(10 + (age // 2) * 3, 20)
            ages[identity] = age
        state.finish()
        self.assertEqual(list(records), sorted(records))
        self.assertEqual(exclusions, int(height == 3))
        roster_count, member_count = committee[118], committee[119]
        self.assertEqual(len(committee), 152 + roster_count * 48 + member_count * 32)
        roster = {}
        for offset in range(152, 152 + roster_count * 48, 48):
            identity = hashlib.blake2s(committee[offset : offset + 32]).digest()
            roster[identity] = int.from_bytes(
                committee[offset + 32 : offset + 48], "little"
            )
        self.assertEqual(
            roster,
            {
                identity: weight
                for identity, weight in records.items()
                if weight is not None
            },
        )
        return ages


if __name__ == "__main__":
    unittest.main()