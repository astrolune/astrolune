# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Release-authority identity, ceremony transcript and offline verifier tests.

Every seed here is a published RFC 8032 test vector, not operator material, and
no document in this file names a real maintainer, organisation or key. The
signing side is implemented in the test rather than in the script, so the
script that verifies an authority never contains code that could use a secret.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "release_authority", Path(__file__).with_name("release-authority.py")
)
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)

# RFC 8032 section 7.1, TEST 1 through TEST SHA(abc): secret, public, message
# and signature, all lowercase hex. These are public vectors.
RFC8032 = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
        "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
        "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21"
        "92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909"
        "351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
)
SEED = bytes.fromhex(RFC8032[0][0])
FOREIGN_SEED = bytes.fromhex(RFC8032[1][0])
WINDOW = {"not_before": "2026-11-01T00:00:00Z", "not_after": "2027-11-01T00:00:00Z"}
INSIDE = "2026-12-01T00:00:00Z"
REVISION = "1" * 40
TARGETS = ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"]
CEREMONY = {
    "date": "2026-11-01",
    "entropy": "operating-system CSPRNG, read once on the offline machine",
    "hardware": "offline machine, model and serial recorded in this transcript",
    "custody": [
        "copy 1: sealed envelope, safe A",
        "copy 2: sealed envelope, safe B",
    ],
    "witnesses": ["Witness A (observer)", "Witness B (recorder)"],
    "steps": [
        "disconnect the machine from every network",
        "cli consensus-vault-create authority.vault",
        "record the derived authority public key and read it back aloud",
        "seal one copy of the vault and its password into each envelope",
    ],
    "verified": [
        "the derived public key was read back and matched by both witnesses",
        "cli verify-release reproduced the identity signature offline",
    ],
}
MANIFEST = {
    "archive": "astrolune-x86_64-unknown-linux-gnu.tar.gz",
    "archive_sha256": "e" * 64,
    "features": "all",
    "files": {"cli": "a" * 64},
    "profile": "release",
    "release": True,
    "revision": REVISION,
    "rustc": "rustc 1.99.0 (b940084d7 2026-09-28)",
    "source_date_epoch": 0,
    "target": "x86_64-unknown-linux-gnu",
}


def expanded(seed):
    """RFC 8032 secret-scalar expansion; test-only, never in the script."""
    digest = hashlib.sha512(seed).digest()
    scalar = (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    return scalar, digest[32:]


def public_key(seed):
    scalar, _ = expanded(seed)
    return AUTHORITY.encode_point(AUTHORITY.multiply(scalar, AUTHORITY.BASE))


def sign(seed, message):
    scalar, prefix = expanded(seed)
    key = public_key(seed)
    nonce = (
        int.from_bytes(hashlib.sha512(prefix + message).digest(), "little")
        % AUTHORITY.L
    )
    point = AUTHORITY.encode_point(AUTHORITY.multiply(nonce, AUTHORITY.BASE))
    challenge = (
        int.from_bytes(hashlib.sha512(point + key + message).digest(), "little")
        % AUTHORITY.L
    )
    return point + int.to_bytes(
        (nonce + challenge * scalar) % AUTHORITY.L, 32, "little"
    )


def seal(seed, body):
    """Build the 136-byte `ALRS0001` artefact the frozen Rust signer produces."""
    digest = AUTHORITY.commitment(body)
    return AUTHORITY.MAGIC + public_key(seed) + digest + sign(seed, digest)


class Ed25519Tests(unittest.TestCase):
    def test_every_rfc_8032_vector_verifies_under_this_implementation(self):
        for index, (secret, key, message, signature) in enumerate(RFC8032, 1):
            with self.subTest(vector=index):
                self.assertEqual(public_key(bytes.fromhex(secret)).hex(), key)
                self.assertEqual(sign(bytes.fromhex(secret), bytes.fromhex(message)).hex(), signature)
                self.assertTrue(
                    AUTHORITY.ed25519_verify(
                        bytes.fromhex(key),
                        bytes.fromhex(message),
                        bytes.fromhex(signature),
                    )
                )

    def test_a_single_flipped_bit_anywhere_in_a_signature_fails(self):
        key, message = bytes.fromhex(RFC8032[2][1]), bytes.fromhex(RFC8032[2][2])
        signature = bytearray(bytes.fromhex(RFC8032[2][3]))
        for offset in range(len(signature)):
            with self.subTest(offset=offset):
                mutated = bytearray(signature)
                mutated[offset] ^= 1
                self.assertFalse(
                    AUTHORITY.ed25519_verify(key, message, bytes(mutated))
                )
        self.assertFalse(AUTHORITY.ed25519_verify(key, message + b"!", bytes(signature)))
        self.assertFalse(
            AUTHORITY.ed25519_verify(bytes.fromhex(RFC8032[1][1]), message, bytes(signature))
        )

    def test_weak_keys_noncanonical_points_and_wild_scalars_fail_closed(self):
        key, message = bytes.fromhex(RFC8032[2][1]), bytes.fromhex(RFC8032[2][2])
        signature = bytes.fromhex(RFC8032[2][3])
        # The all-zero encoding is the order-1 point; y = 2^255 - 1 is above the
        # field prime and therefore not a canonical encoding of anything.
        self.assertFalse(AUTHORITY.ed25519_verify(bytes(32), message, signature))
        self.assertFalse(AUTHORITY.ed25519_verify(b"\xff" * 32, message, signature))
        self.assertIsNone(AUTHORITY.decode_point(b"\xff" * 32))
        self.assertIsNone(AUTHORITY.decode_point(bytes(31)))
        # A scalar at or above the group order is refused rather than reduced.
        order = signature[:32] + int.to_bytes(AUTHORITY.L, 32, "little")
        self.assertFalse(AUTHORITY.ed25519_verify(key, message, order))
        for length in (0, 31, 33, 63, 65):
            with self.subTest(length=length):
                self.assertFalse(
                    AUTHORITY.ed25519_verify(key, message, bytes(length))
                )
                self.assertFalse(
                    AUTHORITY.ed25519_verify(bytes(length), message, signature)
                )

    def test_a_decoded_point_always_re_encodes_to_its_own_bytes(self):
        for _, key, _, signature in RFC8032:
            for encoded in (bytes.fromhex(key), bytes.fromhex(signature)[:32]):
                with self.subTest(point=encoded.hex()):
                    self.assertEqual(
                        AUTHORITY.encode_point(AUTHORITY.decode_point(encoded)), encoded
                    )


class FramingTests(unittest.TestCase):
    def test_the_commitment_is_the_frozen_domain_separated_digest(self):
        self.assertEqual(AUTHORITY.DOMAIN, b"astrolune.release.manifest.v1")
        self.assertEqual(AUTHORITY.SIGNATURE_BYTES, 136)
        self.assertEqual(AUTHORITY.MAGIC, b"ALRS0001")
        # Frozen vector: the digest over the two bytes of an empty JSON object
        # plus its newline. A change in framing, domain or length prefix moves it.
        self.assertEqual(
            AUTHORITY.commitment(b"{}\n").hex(),
            hashlib.blake2s(
                b"astrolune.v1."
                + len(AUTHORITY.DOMAIN).to_bytes(8, "little")
                + AUTHORITY.DOMAIN
                + b"{}\n"
            ).hexdigest(),
        )
        self.assertEqual(len(AUTHORITY.commitment(b"{}\n")), 32)

    def test_an_empty_or_oversized_document_commits_to_nothing(self):
        with self.assertRaises(ValueError):
            AUTHORITY.commitment(b"")
        with self.assertRaises(ValueError) as caught:
            AUTHORITY.commitment(b"x" * (AUTHORITY.MAX_SIGNED_BYTES + 1))
        self.assertIn("above the 1048576", str(caught.exception))

    def test_a_misframed_or_mislengthed_signature_is_refused(self):
        good = seal(SEED, b"{}\n")
        self.assertEqual(len(good), 136)
        for label, raw in (
            ("short", good[:-1]),
            ("long", good + b"\x00"),
            ("magic", b"ALRS0002" + good[8:]),
            ("empty", b""),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    AUTHORITY.parse_signature(raw, "identity")


class DocumentTests(unittest.TestCase):
    def test_canonical_bytes_are_sorted_two_space_and_newline_terminated(self):
        body = AUTHORITY.canonical({"b": 1, "a": [2, 3]})
        self.assertEqual(body, b'{\n  "a": [\n    2,\n    3\n  ],\n  "b": 1\n}\n')
        self.assertNotIn(b"\r", body)

    def test_a_transcript_records_the_ceremony_in_a_deterministic_order(self):
        first = AUTHORITY.compose_transcript(
            public_key(SEED).hex(),
            CEREMONY["date"],
            CEREMONY["entropy"],
            CEREMONY["hardware"],
            list(reversed(CEREMONY["custody"])),
            list(reversed(CEREMONY["witnesses"])),
            CEREMONY["steps"],
            CEREMONY["verified"],
        )
        second = AUTHORITY.compose_transcript(
            public_key(SEED).hex(),
            CEREMONY["date"],
            CEREMONY["entropy"],
            CEREMONY["hardware"],
            CEREMONY["custody"],
            CEREMONY["witnesses"],
            CEREMONY["steps"],
            CEREMONY["verified"],
        )
        self.assertEqual(AUTHORITY.canonical(first), AUTHORITY.canonical(second))
        self.assertEqual(first["schema"], AUTHORITY.CEREMONY_SCHEMA)
        self.assertEqual(sorted(first), sorted(AUTHORITY.KEYS[AUTHORITY.CEREMONY_SCHEMA]))
        # Steps are a procedure, so their order is evidence and is preserved.
        self.assertEqual(first["steps"], CEREMONY["steps"])
        self.assertEqual(first["witnesses"], sorted(CEREMONY["witnesses"]))

    def test_an_identity_binds_one_key_to_one_scope_window_and_ceremony(self):
        identity = self.identity()
        self.assertEqual(identity["schema"], AUTHORITY.IDENTITY_SCHEMA)
        self.assertEqual(sorted(identity), sorted(AUTHORITY.KEYS[AUTHORITY.IDENTITY_SCHEMA]))
        self.assertEqual(identity["authority_public_key"], public_key(SEED).hex())
        self.assertEqual(identity["serial"], 1)
        self.assertIsNone(identity["predecessor"])
        self.assertEqual(identity["scope"]["targets"], TARGETS)
        self.assertEqual(identity["scope"]["revisions"], "any")
        self.assertEqual(identity["scope"]["artifacts"], ["MANIFEST.json"])
        self.assertEqual(
            identity["ceremony"], AUTHORITY.commitment(AUTHORITY.canonical(self.transcript())).hex()
        )

    def transcript(self):
        return AUTHORITY.compose_transcript(
            public_key(SEED).hex(),
            CEREMONY["date"],
            CEREMONY["entropy"],
            CEREMONY["hardware"],
            CEREMONY["custody"],
            CEREMONY["witnesses"],
            CEREMONY["steps"],
            CEREMONY["verified"],
        )

    def identity(self, **overrides):
        settings = {
            "authority": public_key(SEED).hex(),
            "ceremony": AUTHORITY.commitment(
                AUTHORITY.canonical(self.transcript())
            ).hex(),
            "not_before": WINDOW["not_before"],
            "not_after": WINDOW["not_after"],
            "serial": 1,
            "predecessor": None,
            "targets": TARGETS,
            "revisions": "any",
            "artifacts": ["MANIFEST.json"],
        }
        settings.update(overrides)
        return AUTHORITY.compose_identity(**settings)

    def test_an_unusable_identity_is_refused_as_it_is_composed(self):
        cases = {
            "reversed window": {"not_before": WINDOW["not_after"], "not_after": WINDOW["not_before"]},
            "empty window": {"not_after": WINDOW["not_before"]},
            "offset instant": {"not_before": "2026-11-01T00:00:00+01:00"},
            "fractional instant": {"not_before": "2026-11-01T00:00:00.000Z"},
            "impossible day": {"not_before": "2026-02-30T00:00:00Z"},
            "serial zero": {"serial": 0},
            "serial one rotates": {"serial": 1, "predecessor": "b" * 64},
            "serial two orphaned": {"serial": 2, "predecessor": None},
            "boolean serial": {"serial": True},
            "unknown target": {"targets": ["mips-unknown-none"]},
            "no target": {"targets": []},
            "no artifact": {"artifacts": []},
            "bad artifact": {"artifacts": ["../etc/passwd"]},
            "short key": {"authority": "ab"},
            "uppercase key": {"authority": public_key(SEED).hex().upper()},
            "bad ceremony": {"ceremony": "not-a-digest"},
            "bad revision": {"revisions": ["nope"]},
            "empty revisions": {"revisions": []},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    self.identity(**overrides)

    def test_an_unusable_transcript_or_revocation_is_refused(self):
        for label, overrides in (
            ("no witness", {"witnesses": []}),
            ("blank witness", {"witnesses": ["  "]}),
            ("no step", {"steps": []}),
            ("no custody", {"custody": []}),
            ("no verification", {"verified": []}),
            ("bad date", {"date": "2026-13-01"}),
            ("instant as date", {"date": "2026-11-01T00:00:00Z"}),
        ):
            settings = dict(CEREMONY, **overrides)
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    AUTHORITY.compose_transcript(
                        public_key(SEED).hex(),
                        settings["date"],
                        settings["entropy"],
                        settings["hardware"],
                        settings["custody"],
                        settings["witnesses"],
                        settings["steps"],
                        settings["verified"],
                    )
        digest = AUTHORITY.commitment(AUTHORITY.canonical(self.identity())).hex()
        revocation = AUTHORITY.compose_revocation(
            public_key(SEED).hex(), digest, "2027-01-04", "compromise", None
        )
        self.assertEqual(revocation["schema"], AUTHORITY.REVOCATION_SCHEMA)
        self.assertEqual(
            sorted(revocation), sorted(AUTHORITY.KEYS[AUTHORITY.REVOCATION_SCHEMA])
        )
        for label, args in (
            ("unknown reason", (public_key(SEED).hex(), digest, "2027-01-04", "bored", None)),
            ("bad identity", (public_key(SEED).hex(), "nope", "2027-01-04", "rotation", None)),
            ("self succession", (
                public_key(SEED).hex(), digest, "2027-01-04", "rotation",
                public_key(SEED).hex(),
            )),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    AUTHORITY.compose_revocation(*args)


class CeremonyFixture(unittest.TestCase):
    """Writes a complete signed ceremony to a temporary directory."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.authority = public_key(SEED).hex()
        self.transcript = self.store(
            "TRANSCRIPT.json",
            AUTHORITY.compose_transcript(
                self.authority,
                CEREMONY["date"],
                CEREMONY["entropy"],
                CEREMONY["hardware"],
                CEREMONY["custody"],
                CEREMONY["witnesses"],
                CEREMONY["steps"],
                CEREMONY["verified"],
            ),
        )
        self.identity = self.store(
            "AUTHORITY.json",
            AUTHORITY.compose_identity(
                self.authority,
                AUTHORITY.commitment(self.transcript.read_bytes()).hex(),
                WINDOW["not_before"],
                WINDOW["not_after"],
                1,
                None,
                TARGETS,
                "any",
                ["MANIFEST.json"],
            ),
        )

    def store(self, name, document, seed=SEED):
        path = self.root / name
        AUTHORITY.write(path, document)
        (self.root / f"{name}.sig").write_bytes(seal(seed, path.read_bytes()))
        return path

    def signature(self, name):
        return self.root / f"{name}.sig"

    def check(self, **overrides):
        settings = {
            "identity_path": self.identity,
            "identity_signature": self.signature("AUTHORITY.json"),
            "transcript_path": self.transcript,
            "transcript_signature": self.signature("TRANSCRIPT.json"),
            "authority": public_key(SEED),
            "evaluated_at": INSIDE,
        }
        settings.update(overrides)
        return AUTHORITY.verify(**settings)


class VerificationTests(CeremonyFixture):
    def test_a_complete_signed_ceremony_establishes_the_supplied_key(self):
        record = self.check()
        self.assertTrue(record["trusted"])
        self.assertEqual(record["schema"], AUTHORITY.VERIFICATION_SCHEMA)
        self.assertEqual(record["verdict"], "the supplied key is this release authority")
        self.assertEqual(record["refusals"], [])
        self.assertEqual(record["authority_public_key"], self.authority)
        self.assertEqual(record["serial"], 1)
        self.assertEqual(record["evaluated_at"], INSIDE)
        self.assertTrue(record["validity"]["within"])
        self.assertIsNone(record["manifest_digest"])
        self.assertIsNone(record["revocation_digest"])
        self.assertEqual(
            record["identity_digest"],
            AUTHORITY.commitment(self.identity.read_bytes()).hex(),
        )
        self.assertEqual(
            record["checked"],
            ["ceremony binding", "identity signature", "scope", "transcript signature", "validity window"],
        )

    def test_the_record_is_deterministic_and_written_canonically(self):
        output = self.root / "nested/VERIFICATION.json"
        AUTHORITY.write(output, self.check())
        raw = output.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r\n", raw)
        self.assertEqual(raw, AUTHORITY.canonical(self.check()))

    def test_a_key_that_is_not_this_authority_is_refused(self):
        record = self.check(authority=public_key(FOREIGN_SEED))
        self.assertFalse(record["trusted"])
        self.assertEqual(
            record["verdict"],
            "the supplied key is not established as this release authority",
        )
        self.assertTrue(
            any("names authority" in reason for reason in record["refusals"])
        )
        self.assertTrue(
            any("carries authority" in reason for reason in record["refusals"])
        )
        self.assertTrue(
            any("does not authenticate" in reason for reason in record["refusals"])
        )

    def test_a_signature_from_another_holder_of_no_authority_is_refused(self):
        forged = seal(FOREIGN_SEED, self.identity.read_bytes())
        self.signature("AUTHORITY.json").write_bytes(forged)
        record = self.check()
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any(
                "the identity signature carries authority" in reason
                for reason in record["refusals"]
            )
        )

    def test_an_edited_identity_cannot_keep_its_signature(self):
        edited = json.loads(self.identity.read_text(encoding="utf-8"))
        edited["not_after"] = "2099-01-01T00:00:00Z"
        self.identity.write_bytes(AUTHORITY.canonical(edited))
        record = self.check()
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any("commits to" in reason for reason in record["refusals"])
        )

    def test_a_document_that_is_not_canonical_is_refused_before_any_check(self):
        parsed = json.loads(self.identity.read_text(encoding="utf-8"))
        reversed_keys = {key: parsed[key] for key in sorted(parsed, reverse=True)}
        for label, body in (
            ("four-space", (json.dumps(parsed, indent=4, sort_keys=True) + "\n").encode()),
            ("compact", json.dumps(parsed, sort_keys=True).encode()),
            ("unsorted", (json.dumps(reversed_keys, indent=2) + "\n").encode()),
            ("no newline", json.dumps(parsed, indent=2, sort_keys=True).encode()),
            ("crlf", AUTHORITY.canonical(parsed).replace(b"\n", b"\r\n")),
        ):
            with self.subTest(case=label):
                self.assertNotEqual(body, AUTHORITY.canonical(parsed))
                self.identity.write_bytes(body)
                with self.assertRaises(ValueError) as caught:
                    self.check()
                self.assertIn("canonical", str(caught.exception))

    def test_a_foreign_schema_or_an_altered_key_set_is_refused(self):
        parsed = json.loads(self.identity.read_text(encoding="utf-8"))
        for label, document in (
            ("old schema", dict(parsed, schema="astrolune.release-authority/0")),
            ("extra key", dict(parsed, note="trust me")),
            ("transcript as identity", json.loads(self.transcript.read_text(encoding="utf-8"))),
        ):
            with self.subTest(case=label):
                self.identity.write_bytes(AUTHORITY.canonical(document))
                with self.assertRaises(ValueError):
                    self.check()
        trimmed = dict(parsed)
        del trimmed["scope"]
        self.identity.write_bytes(AUTHORITY.canonical(trimmed))
        with self.assertRaises(ValueError) as caught:
            self.check()
        self.assertIn("carries keys", str(caught.exception))

    def test_a_transcript_from_another_ceremony_breaks_the_binding(self):
        other = AUTHORITY.compose_transcript(
            self.authority,
            "2026-11-02",
            CEREMONY["entropy"],
            CEREMONY["hardware"],
            CEREMONY["custody"],
            CEREMONY["witnesses"],
            CEREMONY["steps"],
            CEREMONY["verified"],
        )
        self.store("OTHER.json", other)
        record = self.check(
            transcript_path=self.root / "OTHER.json",
            transcript_signature=self.signature("OTHER.json"),
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any("binds ceremony" in reason for reason in record["refusals"])
        )

    def test_a_transcript_naming_a_different_key_breaks_the_binding(self):
        other = AUTHORITY.compose_transcript(
            public_key(FOREIGN_SEED).hex(),
            CEREMONY["date"],
            CEREMONY["entropy"],
            CEREMONY["hardware"],
            CEREMONY["custody"],
            CEREMONY["witnesses"],
            CEREMONY["steps"],
            CEREMONY["verified"],
        )
        self.store("OTHER.json", other)
        record = self.check(
            transcript_path=self.root / "OTHER.json",
            transcript_signature=self.signature("OTHER.json"),
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any("different authority keys" in reason for reason in record["refusals"])
        )

    def test_an_instant_outside_the_validity_window_is_refused(self):
        for instant in ("2026-10-31T23:59:59Z", "2027-11-01T00:00:01Z"):
            with self.subTest(at=instant):
                record = self.check(evaluated_at=instant)
                self.assertFalse(record["trusted"])
                self.assertFalse(record["validity"]["within"])
                self.assertTrue(
                    any("validity window" in reason for reason in record["refusals"])
                )
        for instant in (WINDOW["not_before"], WINDOW["not_after"]):
            with self.subTest(at=instant):
                self.assertTrue(self.check(evaluated_at=instant)["trusted"])
        with self.assertRaises(ValueError):
            self.check(evaluated_at="2026-12-01")


class ScopedManifestTests(CeremonyFixture):
    def manifest(self, **overrides):
        path = self.root / "MANIFEST.json"
        path.write_bytes(AUTHORITY.canonical(dict(MANIFEST, **overrides)))
        (self.root / "MANIFEST.json.sig").write_bytes(seal(SEED, path.read_bytes()))
        return path

    def test_a_manifest_signature_is_checked_against_the_identity(self):
        path = self.manifest()
        record = self.check(
            manifest_path=path, manifest_signature=self.signature("MANIFEST.json")
        )
        self.assertTrue(record["trusted"])
        self.assertEqual(
            record["manifest_digest"], AUTHORITY.commitment(path.read_bytes()).hex()
        )
        self.assertIn("manifest signature", record["checked"])

    def test_a_manifest_outside_the_declared_scope_is_refused(self):
        AUTHORITY.write(
            self.identity,
            AUTHORITY.compose_identity(
                self.authority,
                AUTHORITY.commitment(self.transcript.read_bytes()).hex(),
                WINDOW["not_before"],
                WINDOW["not_after"],
                1,
                None,
                ["x86_64-pc-windows-msvc"],
                [REVISION],
                ["MANIFEST.json"],
            ),
        )
        self.signature("AUTHORITY.json").write_bytes(
            seal(SEED, self.identity.read_bytes())
        )
        path = self.manifest(target="x86_64-unknown-linux-gnu", revision="2" * 40)
        record = self.check(
            manifest_path=path, manifest_signature=self.signature("MANIFEST.json")
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any("outside the authority's scope" in reason for reason in record["refusals"])
        )
        self.assertEqual(
            len([r for r in record["refusals"] if "outside the authority's scope" in r]),
            2,
        )

    def test_a_manifest_signed_by_another_key_is_refused(self):
        path = self.manifest()
        (self.root / "MANIFEST.json.sig").write_bytes(
            seal(FOREIGN_SEED, path.read_bytes())
        )
        record = self.check(
            manifest_path=path, manifest_signature=self.signature("MANIFEST.json")
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any(
                "the manifest signature carries authority" in reason
                for reason in record["refusals"]
            )
        )

    def test_a_manifest_without_a_target_or_revision_decides_no_scope(self):
        path = self.root / "MANIFEST.json"
        path.write_bytes(AUTHORITY.canonical({"archive": "a.tar.gz"}))
        (self.root / "MANIFEST.json.sig").write_bytes(seal(SEED, path.read_bytes()))
        with self.assertRaises(ValueError) as caught:
            self.check(
                manifest_path=path, manifest_signature=self.signature("MANIFEST.json")
            )
        self.assertIn("no scope decision can be made", str(caught.exception))

    def test_a_manifest_without_its_signature_is_an_error(self):
        with self.assertRaises(ValueError):
            self.check(manifest_path=self.manifest())


class RevocationAndRotationTests(CeremonyFixture):
    def test_a_self_revocation_withdraws_the_authority(self):
        digest = AUTHORITY.commitment(self.identity.read_bytes()).hex()
        self.store(
            "REVOCATION.json",
            AUTHORITY.compose_revocation(
                self.authority, digest, "2027-01-04", "compromise", None
            ),
        )
        record = self.check(
            revocation_path=self.root / "REVOCATION.json",
            revocation_signature=self.signature("REVOCATION.json"),
        )
        self.assertFalse(record["trusted"])
        self.assertIn("revocation", record["checked"])
        self.assertIn(
            "this authority was revoked on 2027-01-04 for compromise",
            record["refusals"],
        )
        self.assertEqual(
            record["revocation_digest"],
            AUTHORITY.commitment((self.root / "REVOCATION.json").read_bytes()).hex(),
        )

    def test_a_revocation_of_a_different_identity_withdraws_nothing(self):
        self.store(
            "REVOCATION.json",
            AUTHORITY.compose_revocation(
                self.authority, "c" * 64, "2027-01-04", "rotation", None
            ),
        )
        record = self.check(
            revocation_path=self.root / "REVOCATION.json",
            revocation_signature=self.signature("REVOCATION.json"),
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(
            any("names identity" in reason for reason in record["refusals"])
        )
        self.assertFalse(
            any("was revoked" in reason for reason in record["refusals"])
        )

    def test_an_unsigned_revocation_is_an_error_rather_than_an_assumption(self):
        self.store(
            "REVOCATION.json",
            AUTHORITY.compose_revocation(
                self.authority,
                AUTHORITY.commitment(self.identity.read_bytes()).hex(),
                "2027-01-04",
                "rotation",
                None,
            ),
        )
        with self.assertRaises(ValueError):
            self.check(revocation_path=self.root / "REVOCATION.json")

    def rotated(self, serial=2, not_before="2027-10-01T00:00:00Z", predecessor=None):
        previous = self.identity.read_bytes()
        document = AUTHORITY.compose_identity(
            self.authority,
            AUTHORITY.commitment(self.transcript.read_bytes()).hex(),
            not_before,
            "2028-10-01T00:00:00Z",
            serial,
            predecessor or AUTHORITY.commitment(previous).hex(),
            TARGETS,
            "any",
            ["MANIFEST.json"],
        )
        (self.root / "PREVIOUS.json").write_bytes(previous)
        return self.store("ROTATED.json", document)

    def test_a_rotated_identity_follows_the_predecessor_it_names(self):
        rotated = self.rotated()
        record = self.check(
            identity_path=rotated,
            identity_signature=self.signature("ROTATED.json"),
            predecessor_path=self.root / "PREVIOUS.json",
            evaluated_at="2027-12-01T00:00:00Z",
        )
        self.assertTrue(record["trusted"])
        self.assertEqual(record["serial"], 2)
        self.assertIn("rotation chain", record["checked"])

    def test_a_rotation_that_does_not_follow_its_predecessor_is_refused(self):
        rotated = self.rotated(predecessor="d" * 64)
        record = self.check(
            identity_path=rotated,
            identity_signature=self.signature("ROTATED.json"),
            predecessor_path=self.root / "PREVIOUS.json",
            evaluated_at="2027-12-01T00:00:00Z",
        )
        self.assertFalse(record["trusted"])
        self.assertTrue(any("rotates" in reason for reason in record["refusals"]))

    def test_a_rotation_must_begin_after_the_predecessor_it_replaces(self):
        rotated = self.rotated(serial=2, not_before="2026-01-01T00:00:00Z")
        record = self.check(
            identity_path=rotated,
            identity_signature=self.signature("ROTATED.json"),
            predecessor_path=self.root / "PREVIOUS.json",
            evaluated_at="2027-12-01T00:00:00Z",
        )
        self.assertFalse(record["trusted"])
        self.assertIn(
            "the rotated identity does not begin after its predecessor",
            record["refusals"],
        )

    def test_a_rotation_must_increase_the_serial(self):
        # A predecessor further along the chain than its own successor is the
        # replay case: an older identity must never supersede a newer one.
        previous = AUTHORITY.compose_identity(
            self.authority,
            AUTHORITY.commitment(self.transcript.read_bytes()).hex(),
            "2026-10-01T00:00:00Z",
            "2027-10-01T00:00:00Z",
            3,
            "e" * 64,
            TARGETS,
            "any",
            ["MANIFEST.json"],
        )
        (self.root / "PREVIOUS.json").write_bytes(AUTHORITY.canonical(previous))
        rotated = self.store(
            "ROTATED.json",
            AUTHORITY.compose_identity(
                self.authority,
                AUTHORITY.commitment(self.transcript.read_bytes()).hex(),
                "2027-10-01T00:00:00Z",
                "2028-10-01T00:00:00Z",
                2,
                AUTHORITY.commitment((self.root / "PREVIOUS.json").read_bytes()).hex(),
                TARGETS,
                "any",
                ["MANIFEST.json"],
            ),
        )
        record = self.check(
            identity_path=rotated,
            identity_signature=self.signature("ROTATED.json"),
            predecessor_path=self.root / "PREVIOUS.json",
            evaluated_at="2027-12-01T00:00:00Z",
        )
        self.assertFalse(record["trusted"])
        self.assertIn(
            "serial 2 does not follow its predecessor's 3", record["refusals"]
        )


if __name__ == "__main__":
    unittest.main()
