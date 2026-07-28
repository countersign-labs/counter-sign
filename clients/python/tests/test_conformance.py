# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Conformance: run the Python client against the committed, language-neutral vectors
(../../../vectors/countersign-vectors.json) — the same file the TypeScript reference
checks itself against. Passing this proves the Python client interoperates
byte-for-byte with the reference implementation.
"""
import json
import sys
from pathlib import Path

import pytest

# Make the `countersign` package importable regardless of the pytest invocation dir.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from countersign import (  # noqa: E402
    ReceiptLog,
    b64url_encode,
    canonicalize,
    public_key_from_secret,
    sign_context,
    utf8,
    verify_context,
    verify_countersignature,
    verify_intent,
    verify_resolution,
)

VECTORS_PATH = Path(__file__).resolve().parents[3] / "vectors" / "countersign-vectors.json"
V = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _ids(section):
    return [c.get("name", str(i)) for i, c in enumerate(section)]


@pytest.mark.parametrize("case", V["keys"], ids=_ids(V["keys"]))
def test_keys(case):
    assert public_key_from_secret(case["secret"]) == case["public"]


@pytest.mark.parametrize("case", V["canonical"], ids=_ids(V["canonical"]))
def test_canonical(case):
    # The interop-critical one: key ordering, Unicode, and number formatting.
    assert canonicalize(case["value"]) == case["canonical"]


@pytest.mark.parametrize("case", V["signing"], ids=_ids(V["signing"]))
def test_signing(case):
    message = b64url_encode(utf8(f'{case["context"]}\n{case["canonical"]}'))
    assert message == case["message_base64url"]
    assert sign_context(case["secret_key"], case["context"], case["canonical"]) == case["signature"]
    assert verify_context(case["public_key"], case["context"], case["canonical"], case["signature"]) is True


@pytest.mark.parametrize("case", V["intents"], ids=_ids(V["intents"]))
def test_intents(case):
    unsigned = {k: v for k, v in case["intent"].items() if k != "signature"}
    assert canonicalize(unsigned) == case["canonical_unsigned"]
    assert verify_intent(case["intent"]) is case["valid"]


@pytest.mark.parametrize("case", V["countersignatures"], ids=_ids(V["countersignatures"]))
def test_countersignatures(case):
    ok = verify_countersignature(case["receipt"], trusted_keys=[case["signer_public_key"]])
    assert ok is case["valid"]


@pytest.mark.parametrize("case", V["resolutions"], ids=_ids(V["resolutions"]))
def test_resolutions(case):
    valid = True
    try:
        verify_resolution(case["intent"], case["resolution"], case["expected_authority_public_key"])
    except Exception:
        valid = False
    assert valid is (case["expect"] == "valid")


def test_chain():
    log = ReceiptLog()
    for receipt in V["chain"]["receipts"]:
        log.append(receipt)
    assert log.head() == V["chain"]["expected_head"]


@pytest.mark.skip(reason="WebAuthn/passkey verification is deferred in the core client (fail-closed).")
def test_webauthn():  # pragma: no cover
    pass
