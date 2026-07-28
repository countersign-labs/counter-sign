# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
ed25519 keys and domain-separated signing — matches src/core/keys.ts.

Keys are exchanged as base64url of the raw 32-byte value (no padding): a 32-byte
seed for a secret, the 32-byte public key for a public key. The signed bytes for
every counter-sign signature are ``utf8(context + "\\n" + canonical)``.
"""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def utf8(s: str) -> bytes:
    return s.encode("utf-8")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def is_canonical_public_key(s) -> bool:
    """
    True iff ``s`` is the canonical base64url encoding of a raw 32-byte ed25519 key.
    base64url is not injective, so requiring canonicality (re-encoding the decoded
    bytes yields the identical string) gives every key exactly one string form —
    making exact-string comparison of keys sound.
    """
    if not isinstance(s, str):
        return False
    try:
        raw = b64url_decode(s)
    except Exception:
        return False
    return len(raw) == 32 and b64url_encode(raw) == s


def _private_key(secret: str) -> Ed25519PrivateKey:
    seed = b64url_decode(secret)
    if len(seed) != 32:
        raise ValueError("secret must be a base64url 32-byte ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_from_secret(secret: str) -> str:
    pub = _private_key(secret).public_key()
    return b64url_encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))


def sign_bytes(secret: str, data: bytes) -> str:
    return b64url_encode(_private_key(secret).sign(data))


def sign_context(secret: str, context: str, canonical: str) -> str:
    """Domain-separated signing: sign over ``utf8(context + "\\n" + canonical)``."""
    return sign_bytes(secret, utf8(f"{context}\n{canonical}"))


def verify_bytes(public: str, data: bytes, signature: str) -> bool:
    """Verify a base64url signature over raw bytes. Never raises on bad input."""
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(public)).verify(
            b64url_decode(signature), data
        )
        return True
    except Exception:
        return False


def verify_context(public: str, context: str, canonical: str, signature: str) -> bool:
    return verify_bytes(public, utf8(f"{context}\n{canonical}"), signature)
