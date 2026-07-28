# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Countersignature (receipt) build + verify — matches src/core/countersignature.ts.

Raw-ed25519 keyed and vouched receipts are fully supported. Passkey / WebAuthn
receipts are NOT verified by this core client: they fail closed (return False),
exactly as the reference verifier does without an RP policy. WebAuthn support is a
planned follow-up; the raw-ed25519 keyed path here is the base signer it layers on.
"""
import unicodedata

from .canonical import canonicalize
from .constants import COUNTERSIGN_VERSION, COUNTERSIGNATURE_CONTEXT
from .keys import is_canonical_public_key, public_key_from_secret, sign_context, verify_context

_WEBAUTHN_PREFIXES = ("webauthn-ed25519:", "webauthn-p256:")


def normalize_actor(actor: str) -> str:
    """
    Canonical form of an ``actor`` for distinct-approver counting: NFC-fold, trim,
    casefold. Defeats case/format-variant spoofing without merging genuinely distinct
    approvers (every shipped channel's address is numeric or case-assigned-unique).
    """
    return unicodedata.normalize("NFC", str(actor)).strip().lower()


def is_webauthn_credential(key) -> bool:
    return isinstance(key, str) and key.startswith(_WEBAUTHN_PREFIXES)


def is_valid_credential_descriptor(key) -> bool:
    """
    True iff ``key`` is a well-formed passkey credential descriptor. An ed25519
    passkey wraps a canonical raw key (``webauthn-ed25519:<canonical-key>``); a P-256
    passkey carries a non-empty COSE key blob. (Full WebAuthn assertion verification
    is a follow-up; this only validates the descriptor shape used by keyed approvers.)
    """
    if not is_webauthn_credential(key):
        return False
    material = key.split(":", 1)[1]
    if key.startswith("webauthn-ed25519:"):
        return is_canonical_public_key(material)
    return isinstance(material, str) and len(material) > 0


def credential_key_material(key: str) -> str:
    """
    The underlying key material of a credential: a raw ed25519 key is its own
    material; a ``webauthn-<alg>:<key>`` descriptor's material is the embedded key.
    Lets a raw key and its passkey wrapper be recognized as the same key.
    """
    if is_webauthn_credential(key):
        return key.split(":", 1)[1]
    return key


def sign_decision(intent, decision, actor, authority_secret, policy="approver", timestamp=None):
    """Produce a signed Countersignature over an Intent (vouched or keyed)."""
    if timestamp is None:
        from datetime import datetime, timezone

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
            f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
        )
    unsigned = {
        "countersign": COUNTERSIGN_VERSION,
        "intent_id": intent["intent_id"],
        "decision": decision,
        "actor": actor,
        "policy": policy,
        "timestamp": timestamp,
        "public_key": public_key_from_secret(authority_secret),
    }
    signature = sign_context(authority_secret, COUNTERSIGNATURE_CONTEXT, canonicalize(unsigned))
    return {**unsigned, "signature": signature}


def verify_countersignature(cs, trusted_keys=None, webauthn=None) -> bool:
    """
    Verify a Countersignature.

    With no ``trusted_keys`` this checks INTEGRITY only (the embedded public_key
    signed the canonical receipt) — which is not authority. Pass ``trusted_keys`` so
    verification also proves the signer is an authority you trust for this Route.
    Passkey receipts fail closed here (see module docstring).
    """
    try:
        if not isinstance(cs, dict):
            return False
        signature = cs.get("signature")
        unsigned = {k: v for k, v in cs.items() if k not in ("signature", "webauthn")}
        public_key = unsigned.get("public_key")
        if not isinstance(signature, str) or not isinstance(public_key, str):
            return False
        if trusted_keys is not None:
            trusted = [trusted_keys] if isinstance(trusted_keys, str) else list(trusted_keys)
            if public_key not in trusted:
                return False
        # Passkey (WebAuthn) receipt or a webauthn block: not supported by the core
        # client — fail closed (the reference verifier also fails closed without a policy).
        if is_webauthn_credential(public_key) or cs.get("webauthn") is not None:
            return False
        return verify_context(public_key, COUNTERSIGNATURE_CONTEXT, canonicalize(unsigned), signature)
    except Exception:
        return False
