# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Passkey credential descriptors: the structural check is as strict as the
reference's isValidCredentialDescriptor (src/core/webauthn.ts). A P-256
descriptor is ``webauthn-p256:`` + canonical base64url of a 65-byte uncompressed
point (first byte 0x04); an ed25519 one wraps a canonical 32-byte key.
Passkey receipt verification itself still fails closed in this client.
"""
import pytest

from conftest import load_vectors, vector_key

from countersign import CountersignError, assert_intent_invariants
from countersign.countersignature import is_valid_credential_descriptor
from countersign.keys import b64url_encode

CEO = vector_key("ceo")
POINT = bytes([4]) + bytes(range(1, 65))  # 65 bytes, uncompressed marker
GOOD_P256 = "webauthn-p256:" + b64url_encode(POINT)


def _vector_p256_descriptors():
    out = set()
    for section in ("receipts", "resolutions"):
        for case in load_vectors()["webauthn"].get(section, []):
            for k in _walk_strings(case):
                if k.startswith("webauthn-p256:"):
                    out.add(k)
    return sorted(out)


def _walk_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _walk_strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk_strings(v)


def test_the_committed_p256_vector_descriptors_are_well_formed():
    found = _vector_p256_descriptors()
    assert found, "the vectors carry at least one P-256 passkey descriptor"
    for d in found:
        assert is_valid_credential_descriptor(d), d


@pytest.mark.parametrize("good", [
    GOOD_P256,
    "webauthn-ed25519:" + CEO["public"],
])
def test_well_formed_descriptors_pass(good):
    assert is_valid_credential_descriptor(good) is True


@pytest.mark.parametrize("name,bad", [
    ("empty-p256", "webauthn-p256:"),
    ("one-char", "webauthn-p256:x"),
    ("64-bytes", "webauthn-p256:" + b64url_encode(POINT[:64])),
    ("66-bytes", "webauthn-p256:" + b64url_encode(POINT + b"\x00")),
    ("compressed-marker", "webauthn-p256:" + b64url_encode(b"\x02" + POINT[1:])),
    ("zero-marker", "webauthn-p256:" + b64url_encode(b"\x00" + POINT[1:])),
    ("padded", GOOD_P256 + "="),
    ("standard-alphabet", "webauthn-p256:" + b64url_encode(b"\x04" + b"\xfb" * 64).replace("-", "+").replace("_", "/")),
    ("non-canonical-tail", GOOD_P256[:-1] + chr(ord(GOOD_P256[-1]) + 1)),
    ("whitespace", GOOD_P256 + " "),
    ("ed25519-short", "webauthn-ed25519:" + CEO["public"][:-2]),
    ("unknown-alg", "webauthn-rsa:" + b64url_encode(POINT)),
    ("not-a-string", None),
])
def test_malformed_descriptors_fail(name, bad):
    assert is_valid_credential_descriptor(bad) is False


def test_an_intent_with_a_malformed_p256_approver_fails_invariants():
    intent = {
        "countersign": "0.2",
        "intent_id": "11111111-1111-4111-8111-111111111111",
        "agent": {"id": "agent:x", "public_key": vector_key("agent")["public"]},
        "action": "a", "summary": "s", "risk_tier": "low",
        "approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "webauthn-p256:x"}],
        "quorum": 1, "timeout": 60, "default": "reject", "callback": None,
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    with pytest.raises(CountersignError, match="non-canonical or malformed"):
        assert_intent_invariants(intent)
    intent["approvers"][0]["public_key"] = GOOD_P256
    assert_intent_invariants(intent)
