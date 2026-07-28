# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
counter-sign — Python client for the agent-to-human authorization protocol.

A vectors-conformant port of the protocol core: canonical JSON, ed25519
domain-separated signing, Intent + Countersignature build/verify, quorum
resolution, and the hash-chained receipt log. Verified byte-for-byte against
``vectors/countersign-vectors.json`` from the reference implementation.

WebAuthn / passkey receipt verification is a planned follow-up; passkey receipts
fail closed here. The raw-ed25519 keyed/vouched paths are complete.
"""
from .canonical import canonicalize
from .constants import (
    COUNTERSIGN_VERSION,
    COUNTERSIGNATURE_CONTEXT,
    INTENT_CONTEXT,
    LINK_CONTEXT,
)
from .countersignature import (
    normalize_actor,
    sign_decision,
    verify_countersignature,
)
from .errors import CountersignError, InvalidCountersignatureError
from .intent import assert_intent_invariants, quorum_of, verify_intent
from .keys import (
    b64url_decode,
    b64url_encode,
    is_canonical_public_key,
    public_key_from_secret,
    sign_context,
    utf8,
    verify_context,
)
from .receipt_log import CHAIN_GENESIS, ReceiptLog
from .resolution import deadline, verify_resolution

__version__ = "0.2.0"

__all__ = [
    "canonicalize",
    "COUNTERSIGN_VERSION",
    "INTENT_CONTEXT",
    "COUNTERSIGNATURE_CONTEXT",
    "LINK_CONTEXT",
    "public_key_from_secret",
    "sign_context",
    "verify_context",
    "b64url_encode",
    "b64url_decode",
    "is_canonical_public_key",
    "utf8",
    "verify_intent",
    "assert_intent_invariants",
    "quorum_of",
    "sign_decision",
    "verify_countersignature",
    "normalize_actor",
    "verify_resolution",
    "deadline",
    "ReceiptLog",
    "CHAIN_GENESIS",
    "CountersignError",
    "InvalidCountersignatureError",
]
