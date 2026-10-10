# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Compose and verify release-authority identity documents and ceremony transcripts.

This script defines the format and performs the checks. It never generates,
reads, holds or derives a private key, and it never decides which key is
authoritative: the authority public key must be supplied on every verification
and is compared with the key the signature artefact carries, exactly as
`cli verify-release` does. A document that establishes its own authority would
establish nothing.

The Ed25519 verifier here is a deliberately independent stdlib implementation of
RFC 8032 with `verify_strict` semantics, so an identity document can be checked
on a machine that has no Rust toolchain and without trusting the same code that
produced the signature. It is not constant-time and must never see secret key
material.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import re
import struct

SPEC = importlib.util.spec_from_file_location(
    "qualification", Path(__file__).with_name("qualification-report.py")
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)

IDENTITY_SCHEMA = "astrolune.release-authority/1"
CEREMONY_SCHEMA = "astrolune.release-ceremony/1"
REVOCATION_SCHEMA = "astrolune.release-authority-revocation/1"
VERIFICATION_SCHEMA = "astrolune.release-authority-verification/1"
# The frozen framing of `keystore::release`. Nothing here may change either.
MAGIC = b"ALRS0001"
SIGNATURE_BYTES = 8 + 32 + 32 + 64
MAX_SIGNED_BYTES = 1 << 20
DOMAIN = b"astrolune.release.manifest.v1"
FRAMING = b"astrolune.v1."
REASONS = ("compromise", "retirement", "rotation")
INSTANT = "%Y-%m-%dT%H:%M:%SZ"
DAY = "%Y-%m-%d"
HEX32 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ARTIFACT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# Exactly the keys each document carries. An extra key would change the signed
# bytes without changing anything a verifier checks, so it is refused.
KEYS = {
    IDENTITY_SCHEMA: (
        "authority_public_key",
        "ceremony",
        "not_after",
        "not_before",
        "predecessor",
        "schema",
        "scope",
        "serial",
    ),
    CEREMONY_SCHEMA: (
        "authority_public_key",
        "custody",
        "date",
        "entropy",
        "hardware",
        "schema",
        "steps",
        "verification",
        "witnesses",
    ),
    REVOCATION_SCHEMA: (
        "authority_public_key",
        "date",
        "identity",
        "reason",
        "schema",
        "successor",
    ),
}
# Ordered sequences describe a procedure, so their given order is preserved.
# Sets of operator facts are sorted, so equal inputs produce equal bytes.
SEQUENCES = ("steps", "verification")
SETS = ("custody", "witnesses")

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inverse(value):
    return pow(value, P - 2, P)


CURVE_D = -121665 * _inverse(121666) % P
SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)
IDENTITY_POINT = (0, 1, 1, 0)


def _add(left, right):
    """Extended-coordinate twisted Edwards addition, as in RFC 8032."""
    a = (left[1] - left[0]) * (right[1] - right[0]) % P
    b = (left[1] + left[0]) * (right[1] + right[0]) % P
    c = 2 * left[3] * right[3] * CURVE_D % P
    d = 2 * left[2] * right[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def multiply(scalar, point):
    total = IDENTITY_POINT
    while scalar > 0:
        if scalar & 1:
            total = _add(total, point)
        point = _add(point, point)
        scalar >>= 1
    return total


def _same(left, right):
    return (left[0] * right[2] - right[0] * left[2]) % P == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % P == 0


def _recover_x(y, sign):
    """Rejects a non-canonical encoding by refusing to recover its x."""
    if y >= P:
        return None
    square = (y * y - 1) * _inverse(CURVE_D * y * y + 1) % P
    if square == 0:
        return None if sign else 0
    x = pow(square, (P + 3) // 8, P)
    if (x * x - square) % P != 0:
        x = x * SQRT_MINUS_ONE % P
    if (x * x - square) % P != 0:
        return None
    return P - x if (x & 1) != sign else x


def decode_point(encoded):
    """Decompresses a point, returning None for any non-canonical encoding."""
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def encode_point(point):
    """Compresses a point to its one canonical 32-byte encoding."""
    scale = _inverse(point[2])
    x, y = point[0] * scale % P, point[1] * scale % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


BASE_Y = 4 * _inverse(5) % P
BASE = (_recover_x(BASE_Y, 0), BASE_Y, 1, _recover_x(BASE_Y, 0) * BASE_Y % P)


def ed25519_verify(public_key, message, signature):
    """Strict RFC 8032 verification: canonical encodings, no small-order points.

    This matches `crypto::blake2s::ed25519_verify`: a key or commitment that
    does not re-encode to its own bytes, a small-order key or commitment, and a
    scalar at or above the group order all fail, and verification is
    cofactorless, so a signature is never malleable into a second valid form.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    key = decode_point(public_key)
    if key is None or _same(multiply(8, key), IDENTITY_POINT):
        return False
    nonce = decode_point(signature[:32])
    if nonce is None or _same(multiply(8, nonce), IDENTITY_POINT):
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    challenge = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % L
    )
    return _same(multiply(scalar, BASE), _add(nonce, multiply(challenge, key)))


def canonical(document):
    """The one byte string a document may be signed as."""
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def commitment(body):
    """The digest `keystore::release` signs: a length-framed domain hash."""
    if not body:
        raise ValueError("an empty document commits to nothing")
    if len(body) > MAX_SIGNED_BYTES:
        raise ValueError(
            f"{len(body)} bytes is above the {MAX_SIGNED_BYTES} a signable "
            "document may occupy"
        )
    return hashlib.blake2s(
        FRAMING + struct.pack("<Q", len(DOMAIN)) + DOMAIN + body
    ).digest()


def parse_signature(raw, name):
    """Split one frozen 136-byte detached signature into its fields."""
    if len(raw) != SIGNATURE_BYTES:
        raise ValueError(
            f"the {name} signature is {len(raw)} bytes, not {SIGNATURE_BYTES}"
        )
    if raw[:8] != MAGIC:
        raise ValueError(f"the {name} signature is not {MAGIC.decode()}-framed")
    return raw[8:40], raw[40:72], raw[72:]


def check_hex(name, field, value, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise ValueError(f"{name}: {field} is not 64 lowercase hex characters")


def check_text(name, field, value):
    if not isinstance(value, str) or not value.strip() or "\n" in value:
        raise ValueError(f"{name}: {field} is not a single non-empty line")


def check_lines(name, field, value, ordered):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name}: {field} records nothing")
    for entry in value:
        check_text(f"{name}: {field}", "entry", entry)
    if not ordered and (sorted(set(value)) != value):
        raise ValueError(f"{name}: {field} is not a sorted list of distinct entries")


def check_time(name, field, value, layout):
    if not isinstance(value, str):
        raise ValueError(f"{name}: {field} is not a timestamp")
    try:
        parsed = datetime.strptime(value, layout)
    except ValueError:
        raise ValueError(f"{name}: {field} is not exactly {layout} in UTC: {value!r}")
    if parsed.strftime(layout) != value:
        raise ValueError(f"{name}: {field} is not canonically written: {value!r}")
    return parsed.replace(tzinfo=timezone.utc)


def check_scope(name, scope):
    """Bound what the authority may sign: artefacts, revisions and targets."""
    if not isinstance(scope, dict) or sorted(scope) != [
        "artifacts",
        "revisions",
        "targets",
    ]:
        raise ValueError(f"{name}: scope must carry artifacts, revisions and targets")
    for field, pattern in (("artifacts", ARTIFACT), ("targets", None)):
        values = scope[field]
        if not isinstance(values, list) or not values:
            raise ValueError(f"{name}: scope.{field} names nothing")
        if sorted(set(values)) != values:
            raise ValueError(f"{name}: scope.{field} is not sorted and distinct")
        for value in values:
            if pattern is None:
                if value not in QUALIFICATION.TARGETS:
                    raise ValueError(f"{name}: scope.targets names {value!r}")
            elif not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise ValueError(f"{name}: scope.artifacts names {value!r}")
    revisions = scope["revisions"]
    if revisions == "any":
        return
    if not isinstance(revisions, list) or not revisions:
        raise ValueError(f"{name}: scope.revisions is neither \"any\" nor a list")
    if sorted(set(revisions)) != revisions:
        raise ValueError(f"{name}: scope.revisions is not sorted and distinct")
    for value in revisions:
        if not isinstance(value, str) or REVISION.fullmatch(value) is None:
            raise ValueError(f"{name}: scope.revisions names {value!r}")


def validate(name, document):
    """Check every field of one document against its declared schema."""
    schema = document["schema"]
    check_hex(name, "authority_public_key", document["authority_public_key"])
    if schema == IDENTITY_SCHEMA:
        check_hex(name, "ceremony", document["ceremony"])
        check_hex(name, "predecessor", document["predecessor"], optional=True)
        serial = document["serial"]
        if isinstance(serial, bool) or not isinstance(serial, int) or serial < 1:
            raise ValueError(f"{name}: serial is not a positive integer")
        if serial == 1 and document["predecessor"] is not None:
            raise ValueError(f"{name}: serial 1 cannot rotate a predecessor")
        if serial > 1 and document["predecessor"] is None:
            raise ValueError(f"{name}: serial {serial} must name its predecessor")
        start = check_time(name, "not_before", document["not_before"], INSTANT)
        end = check_time(name, "not_after", document["not_after"], INSTANT)
        if start >= end:
            raise ValueError(f"{name}: the validity window is empty or reversed")
        check_scope(name, document["scope"])
    elif schema == CEREMONY_SCHEMA:
        check_time(name, "date", document["date"], DAY)
        for field in ("entropy", "hardware"):
            check_text(name, field, document[field])
        for field in SEQUENCES:
            check_lines(name, field, document[field], ordered=True)
        for field in SETS:
            check_lines(name, field, document[field], ordered=False)
    else:
        check_time(name, "date", document["date"], DAY)
        check_hex(name, "identity", document["identity"])
        check_hex(name, "successor", document["successor"], optional=True)
        if document["reason"] not in REASONS:
            raise ValueError(f"{name}: reason must be one of " + ", ".join(REASONS))
        if document["successor"] == document["authority_public_key"]:
            raise ValueError(f"{name}: a key cannot succeed itself")


def read(path, schema):
    """Read one document, refusing a foreign schema or non-canonical bytes."""
    body = path.read_bytes()
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.name} is not UTF-8 JSON: {error}")
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    if document.get("schema") != schema:
        raise ValueError(
            f"{path.name} declares schema {document.get('schema')!r}, "
            f"this checker reads only {schema!r}"
        )
    if sorted(document) != sorted(KEYS[schema]):
        raise ValueError(
            f"{path.name} carries keys {', '.join(sorted(document))}; "
            f"{schema} is exactly {', '.join(sorted(KEYS[schema]))}"
        )
    if canonical(document) != body:
        # The signature commits to these exact bytes. A document that is not in
        # canonical form cannot be re-derived from its own fields, so no later
        # reader could reproduce what was signed.
        raise ValueError(
            f"{path.name} is not canonical sorted-key two-space LF-terminated JSON"
        )
    validate(path.name, document)
    return document, body


def authenticate(name, body, raw, authority, refusals):
    """Check one detached signature against the explicitly supplied authority."""
    embedded, committed, signature = parse_signature(raw, name)
    expected = commitment(body)
    if embedded != authority:
        refusals.append(
            f"the {name} signature carries authority {embedded.hex()}, not the "
            f"supplied {authority.hex()}"
        )
    if committed != expected:
        refusals.append(
            f"the {name} signature commits to {committed.hex()}, not to the "
            f"{len(body)} bytes of {name} ({expected.hex()})"
        )
    elif not ed25519_verify(authority, expected, signature):
        refusals.append(
            f"the {name} signature does not authenticate {expected.hex()} under "
            f"{authority.hex()}"
        )
    return expected


def compose_transcript(
    authority, date, entropy, hardware, custody, witnesses, steps, verification
):
    """Record what the ceremony did and who observed it, deterministically."""
    document = {
        "authority_public_key": authority,
        "custody": sorted(set(custody)),
        "date": date,
        "entropy": entropy,
        "hardware": hardware,
        "schema": CEREMONY_SCHEMA,
        "steps": list(steps),
        "verification": list(verification),
        "witnesses": sorted(set(witnesses)),
    }
    validate("transcript", document)
    return document


def compose_identity(
    authority,
    ceremony,
    not_before,
    not_after,
    serial,
    predecessor,
    targets,
    revisions,
    artifacts,
):
    """Bind one authority key to one scope, one window and one ceremony."""
    document = {
        "authority_public_key": authority,
        "ceremony": ceremony,
        "not_after": not_after,
        "not_before": not_before,
        "predecessor": predecessor,
        "schema": IDENTITY_SCHEMA,
        "scope": {
            "artifacts": sorted(set(artifacts)),
            "revisions": "any"
            if revisions == "any"
            else sorted(set(revisions or [])),
            "targets": sorted(set(targets)),
        },
        "serial": serial,
    }
    validate("identity", document)
    return document


def compose_revocation(authority, identity, date, reason, successor):
    """State that one identity document is no longer authoritative."""
    document = {
        "authority_public_key": authority,
        "date": date,
        "identity": identity,
        "reason": reason,
        "schema": REVOCATION_SCHEMA,
        "successor": successor,
    }
    validate("revocation", document)
    return document


def check_scope_use(scope, target, revision, artifact, refusals):
    """Refuse a use the identity's own scope does not cover."""
    if target is not None and target not in scope["targets"]:
        refusals.append(
            f"target {target} is outside the authority's scope "
            f"({', '.join(scope['targets'])})"
        )
    if revision is not None and scope["revisions"] != "any":
        if revision not in scope["revisions"]:
            refusals.append(
                f"revision {revision} is outside the authority's scope "
                f"({', '.join(scope['revisions'])})"
            )
    if artifact is not None and artifact not in scope["artifacts"]:
        refusals.append(
            f"artefact {artifact} is outside the authority's scope "
            f"({', '.join(scope['artifacts'])})"
        )


def verify(
    identity_path,
    identity_signature,
    transcript_path,
    transcript_signature,
    authority,
    evaluated_at,
    revocation_path=None,
    revocation_signature=None,
    manifest_path=None,
    manifest_signature=None,
    predecessor_path=None,
    target=None,
    revision=None,
):
    """Decide whether a supplied key is this authority, and what it may sign."""
    identity, identity_body = read(identity_path, IDENTITY_SCHEMA)
    transcript, transcript_body = read(transcript_path, CEREMONY_SCHEMA)
    refusals, checked = [], ["identity signature", "ceremony binding"]
    if identity["authority_public_key"] != authority.hex():
        refusals.append(
            f"the identity document names authority "
            f"{identity['authority_public_key']}, not the supplied {authority.hex()}"
        )
    identity_digest = authenticate(
        "identity", identity_body, identity_signature.read_bytes(), authority, refusals
    )
    transcript_digest = authenticate(
        "transcript",
        transcript_body,
        transcript_signature.read_bytes(),
        authority,
        refusals,
    )
    checked.append("transcript signature")
    if identity["ceremony"] != transcript_digest.hex():
        refusals.append(
            f"the identity binds ceremony {identity['ceremony']}, but this "
            f"transcript hashes to {transcript_digest.hex()}"
        )
    if transcript["authority_public_key"] != identity["authority_public_key"]:
        refusals.append(
            "the transcript and the identity name different authority keys"
        )
    instant = check_time("verification", "--at", evaluated_at, INSTANT)
    start = datetime.strptime(identity["not_before"], INSTANT).replace(
        tzinfo=timezone.utc
    )
    end = datetime.strptime(identity["not_after"], INSTANT).replace(tzinfo=timezone.utc)
    within = start <= instant <= end
    checked.append("validity window")
    if not within:
        refusals.append(
            f"{evaluated_at} is outside the authority's validity window "
            f"{identity['not_before']}..{identity['not_after']}"
        )
    manifest_digest = None
    if manifest_path is not None:
        if manifest_signature is None:
            raise ValueError("--manifest requires --manifest-signature")
        manifest_body = manifest_path.read_bytes()
        manifest_digest = authenticate(
            "manifest", manifest_body, manifest_signature.read_bytes(), authority,
            refusals,
        )
        try:
            manifest = json.loads(manifest_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{manifest_path.name} is not UTF-8 JSON: {error}")
        if not isinstance(manifest, dict):
            raise ValueError(f"{manifest_path.name} is not a JSON object")
        for field in ("revision", "target"):
            if not isinstance(manifest.get(field), str):
                raise ValueError(
                    f"{manifest_path.name} records no {field}, so no scope "
                    "decision can be made about it"
                )
        target = target or manifest["target"]
        revision = revision or manifest["revision"]
        checked.append("manifest signature")
    check_scope_use(
        identity["scope"],
        target,
        revision,
        manifest_path.name if manifest_path is not None else None,
        refusals,
    )
    checked.append("scope")
    revocation_digest = None
    if revocation_path is not None:
        if revocation_signature is None:
            raise ValueError("--revocation requires --revocation-signature")
        revocation, revocation_body = read(revocation_path, REVOCATION_SCHEMA)
        revocation_digest = authenticate(
            "revocation", revocation_body, revocation_signature.read_bytes(),
            authority, refusals,
        )
        checked.append("revocation")
        if revocation["identity"] != identity_digest.hex():
            refusals.append(
                f"the revocation names identity {revocation['identity']}, not "
                f"this {identity_digest.hex()}"
            )
        else:
            refusals.append(
                f"this authority was revoked on {revocation['date']} for "
                f"{revocation['reason']}"
            )
    if predecessor_path is not None:
        previous, previous_body = read(predecessor_path, IDENTITY_SCHEMA)
        checked.append("rotation chain")
        if identity["predecessor"] != commitment(previous_body).hex():
            refusals.append(
                f"the identity rotates {identity['predecessor']}, not the supplied "
                f"{commitment(previous_body).hex()}"
            )
        if previous["serial"] >= identity["serial"]:
            refusals.append(
                f"serial {identity['serial']} does not follow its predecessor's "
                f"{previous['serial']}"
            )
        if previous["not_before"] >= identity["not_before"]:
            refusals.append(
                "the rotated identity does not begin after its predecessor"
            )
    trusted = not refusals
    return {
        "authority_public_key": authority.hex(),
        "checked": sorted(set(checked)),
        "evaluated_at": evaluated_at,
        "identity_digest": identity_digest.hex(),
        "manifest_digest": None if manifest_digest is None else manifest_digest.hex(),
        "refusals": sorted(refusals),
        "revocation_digest": (
            None if revocation_digest is None else revocation_digest.hex()
        ),
        "schema": VERIFICATION_SCHEMA,
        "scope": identity["scope"],
        "serial": identity["serial"],
        "transcript_digest": transcript_digest.hex(),
        "trusted": trusted,
        "validity": {
            "not_after": identity["not_after"],
            "not_before": identity["not_before"],
            "within": within,
        },
        "verdict": (
            "the supplied key is this release authority"
            if trusted
            else "the supplied key is not established as this release authority"
        ),
    }


def write(path, document):
    """Sorted keys and a fixed newline keep every signable document comparable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(document))


def key_bytes(text):
    """Read one 64-hex authority key; nothing here ever reads a secret."""
    if HEX32.fullmatch(text.strip()) is None:
        raise ValueError("an authority public key is 64 lowercase hex characters")
    return bytes.fromhex(text.strip())


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    transcript = commands.add_parser("transcript", help="compose a ceremony transcript")
    transcript.add_argument("--authority-public-key", required=True)
    transcript.add_argument("--date", required=True, help="ceremony date, YYYY-MM-DD")
    transcript.add_argument("--entropy", required=True)
    transcript.add_argument("--hardware", required=True)
    transcript.add_argument("--custody", action="append", required=True)
    transcript.add_argument("--witness", action="append", required=True)
    transcript.add_argument("--step", action="append", required=True)
    transcript.add_argument("--verified", action="append", required=True)
    transcript.add_argument("--output", type=Path, required=True)

    identity = commands.add_parser("identity", help="compose an identity document")
    identity.add_argument("--authority-public-key", required=True)
    identity.add_argument("--transcript", type=Path, required=True)
    identity.add_argument("--not-before", required=True)
    identity.add_argument("--not-after", required=True)
    identity.add_argument("--serial", type=int, default=1)
    identity.add_argument("--predecessor", type=Path, default=None)
    identity.add_argument("--target", action="append", required=True)
    identity.add_argument("--revision", action="append", default=None)
    identity.add_argument("--artifact", action="append", default=None)
    identity.add_argument("--output", type=Path, required=True)

    revoke = commands.add_parser("revoke", help="compose a revocation statement")
    revoke.add_argument("--authority-public-key", required=True)
    revoke.add_argument("--identity", type=Path, required=True)
    revoke.add_argument("--date", required=True)
    revoke.add_argument("--reason", choices=REASONS, required=True)
    revoke.add_argument("--successor-public-key", default=None)
    revoke.add_argument("--output", type=Path, required=True)

    check = commands.add_parser("verify", help="verify an authority offline")
    check.add_argument("--authority-public-key", required=True)
    check.add_argument("--identity", type=Path, required=True)
    check.add_argument("--identity-signature", type=Path, required=True)
    check.add_argument("--transcript", type=Path, required=True)
    check.add_argument("--transcript-signature", type=Path, required=True)
    check.add_argument("--manifest", type=Path, default=None)
    check.add_argument("--manifest-signature", type=Path, default=None)
    check.add_argument("--revocation", type=Path, default=None)
    check.add_argument("--revocation-signature", type=Path, default=None)
    check.add_argument("--predecessor", type=Path, default=None)
    check.add_argument("--target", default=None)
    check.add_argument("--revision", default=None)
    check.add_argument(
        "--at",
        default=None,
        help="instant to evaluate the validity window at (default: now, UTC)",
    )
    check.add_argument("--output", type=Path, default=None)
    return parser.parse_args()


def run(options):
    """Dispatch one subcommand, returning the document it produced."""
    authority = key_bytes(options.authority_public_key)
    if options.command == "transcript":
        return compose_transcript(
            authority.hex(),
            options.date,
            options.entropy,
            options.hardware,
            options.custody,
            options.witness,
            options.step,
            options.verified,
        )
    if options.command == "identity":
        transcript, body = read(options.transcript, CEREMONY_SCHEMA)
        if transcript["authority_public_key"] != authority.hex():
            raise ValueError("the transcript records a different authority key")
        predecessor = None
        if options.predecessor is not None:
            predecessor = commitment(read(options.predecessor, IDENTITY_SCHEMA)[1]).hex()
        return compose_identity(
            authority.hex(),
            commitment(body).hex(),
            options.not_before,
            options.not_after,
            options.serial,
            predecessor,
            options.target,
            options.revision if options.revision else "any",
            options.artifact or ["MANIFEST.json"],
        )
    if options.command == "revoke":
        identity, body = read(options.identity, IDENTITY_SCHEMA)
        if identity["authority_public_key"] != authority.hex():
            raise ValueError("the identity document records a different authority key")
        successor = (
            None
            if options.successor_public_key is None
            else key_bytes(options.successor_public_key).hex()
        )
        return compose_revocation(
            authority.hex(), commitment(body).hex(), options.date, options.reason,
            successor,
        )
    return verify(
        options.identity,
        options.identity_signature,
        options.transcript,
        options.transcript_signature,
        authority,
        options.at or datetime.now(timezone.utc).strftime(INSTANT),
        options.revocation,
        options.revocation_signature,
        options.manifest,
        options.manifest_signature,
        options.predecessor,
        options.target,
        options.revision,
    )


def main():
    options = arguments()
    try:
        document = run(options)
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(f"release authority {options.command} failed: {error}")
    if options.output is not None:
        write(options.output, document)
    print(json.dumps(document, indent=2, sort_keys=True))
    if options.command != "verify":
        print(f"sign {options.output} with cli release-sign")
    elif not document["trusted"]:
        raise SystemExit(
            "release authority not established: " + "; ".join(document["refusals"])
        )


if __name__ == "__main__":
    main()
