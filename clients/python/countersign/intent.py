# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Intent verification + structural invariants — matches src/core/intent.ts.

``verify_intent`` proves the agent authored the bytes; ``assert_intent_invariants``
re-validates a received Intent's structure (quorum/timeout/approver rules) before
acting on it, since a valid signature does not prove the fields are well-formed.
"""
from .canonical import canonicalize
from .constants import (
    APPROVER_MODES,
    DECISIONS,
    DEFAULT_TIMEOUT_ACTOR,
    INTENT_CONTEXT,
    MAX_TIMEOUT_SECONDS,
    RISK_TIERS,
)
from .countersignature import (
    credential_key_material,
    is_valid_credential_descriptor,
    normalize_actor,
)
from .errors import CountersignError
from .keys import is_canonical_public_key, verify_context
from .timeutil import parse_iso_ms


def _is_int(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool)


def validate_approvers(approvers, quorum) -> None:
    keys = set()
    actors = set()
    for a in approvers:
        if not isinstance(a, dict) or not isinstance(a.get("actor"), str) or len(a["actor"]) == 0:
            raise CountersignError("each approver must have a non-empty string actor")
        if a.get("mode") not in APPROVER_MODES:
            raise CountersignError(f"approver {a['actor']} has invalid mode {a.get('mode')!r}")
        na = normalize_actor(a["actor"])
        if na == DEFAULT_TIMEOUT_ACTOR:
            raise CountersignError(f"approver actor {a['actor']!r} is reserved")
        if na in actors:
            raise CountersignError(f"approver actor {a['actor']!r} is listed more than once")
        actors.add(na)
        if a["mode"] == "keyed":
            pk = a.get("public_key")
            if not isinstance(pk, str) or len(pk) == 0:
                raise CountersignError(f"keyed approver {a['actor']} must carry a public_key")
            if not is_canonical_public_key(pk) and not is_valid_credential_descriptor(pk):
                raise CountersignError(
                    f"keyed approver {a['actor']} has a non-canonical or malformed public_key"
                )
            material = credential_key_material(pk)
            if material in keys:
                raise CountersignError(
                    f"approver public_key {pk} shares key material with another approver"
                )
            keys.add(material)
        elif a.get("public_key") is not None:
            raise CountersignError(f"vouched approver {a['actor']} must not carry a public_key")
    if quorum > 1 and any(a.get("mode") != "keyed" for a in approvers):
        raise CountersignError(
            "Intent.quorum > 1 requires every approver to be keyed "
            "(a vouched slot in a quorum is server-forgeable)"
        )
    if quorum > len(approvers):
        raise CountersignError(
            f"Intent.quorum ({quorum}) exceeds the number of approvers ({len(approvers)}) "
            "— it can never be reached"
        )


def quorum_of(intent) -> int:
    q = intent.get("quorum")
    if q is None:
        return 1
    if not _is_int(q) or q < 1:
        raise CountersignError(f"Intent.quorum must be an integer >= 1 (got {q!r})")
    return q


def assert_intent_invariants(intent) -> None:
    if not isinstance(intent, dict):
        raise CountersignError("intent must be an object")
    if not isinstance(intent.get("intent_id"), str) or len(intent["intent_id"]) == 0:
        raise CountersignError("Intent.intent_id must be a non-empty string")
    agent = intent.get("agent")
    if not isinstance(agent, dict) or not isinstance(agent.get("id"), str) or len(agent["id"]) == 0:
        raise CountersignError("Intent.agent must carry a non-empty id")
    if not is_canonical_public_key(agent.get("public_key")):
        raise CountersignError("Intent.agent.public_key must be a canonical ed25519 key")
    if not isinstance(intent.get("action"), str) or len(intent["action"]) == 0:
        raise CountersignError("Intent.action is required")
    if not isinstance(intent.get("summary"), str) or len(intent["summary"]) == 0:
        raise CountersignError("Intent.summary is required")
    if intent.get("risk_tier") not in RISK_TIERS:
        raise CountersignError(f"invalid risk_tier: {intent.get('risk_tier')}")
    approvers = intent.get("approvers")
    if not isinstance(approvers, list) or len(approvers) == 0:
        raise CountersignError("Intent.approvers must be a non-empty array")
    quorum = intent.get("quorum", 1)
    if not _is_int(quorum) or quorum < 1:
        raise CountersignError("Intent.quorum must be an integer >= 1")
    if quorum > 1 and intent.get("default") == "approve":
        raise CountersignError("Intent.quorum > 1 must not be combined with default: approve")
    validate_approvers(approvers, quorum)
    timeout = intent.get("timeout")
    if not _is_int(timeout) or timeout < 1 or timeout > MAX_TIMEOUT_SECONDS:
        raise CountersignError(
            f"Intent.timeout must be an integer number of seconds in [1, {MAX_TIMEOUT_SECONDS}]"
        )
    if intent.get("default") not in DECISIONS:
        raise CountersignError(f"invalid default: {intent.get('default')}")
    if parse_iso_ms(intent.get("created_at")) is None:
        raise CountersignError("Intent.created_at must be a valid ISO 8601 timestamp")


def verify_intent(intent) -> bool:
    """Verify the agent's signature over the canonical envelope. Never raises."""
    try:
        if not isinstance(intent, dict):
            return False
        signature = intent.get("signature")
        agent = intent.get("agent")
        if not isinstance(signature, str) or not isinstance(agent, dict):
            return False
        if not isinstance(agent.get("public_key"), str):
            return False
        unsigned = {k: v for k, v in intent.items() if k != "signature"}
        return verify_context(agent["public_key"], INTENT_CONTEXT, canonicalize(unsigned), signature)
    except Exception:
        return False
