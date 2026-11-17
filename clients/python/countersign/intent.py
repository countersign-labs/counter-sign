# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Intent verification + structural invariants — matches src/core/intent.ts.

``verify_intent`` proves the agent authored the bytes; ``assert_intent_invariants``
re-validates a received Intent's structure (quorum/timeout/approver rules) before
acting on it, since a valid signature does not prove the fields are well-formed.
``create_intent`` builds and signs one, with every authorship rule of the
reference's ``createIntent``.
"""
import math
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone

from .canonical import canonicalize
from .constants import (
    APPROVER_MODES,
    COUNTERSIGN_VERSION,
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
from .keys import is_canonical_public_key, public_key_from_secret, sign_context, verify_context
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


_LOWERCASE_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ISO_MS_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


def _as_js_integer(n):
    """
    ``n`` as an int if JavaScript's ``Number.isInteger`` would accept it, else None.
    JSON (and JavaScript) has one number type, so ``2.0`` is the integer 2 there;
    a bool is not a number at all.
    """
    if _is_int(n):
        return n
    if isinstance(n, float) and math.isfinite(n) and n.is_integer():
        return int(n)
    return None


def _iso_ms_z(dt: datetime) -> str:
    """JavaScript's ``Date.prototype.toISOString`` for an aware datetime."""
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _created_at(value) -> str:
    if value is None:
        return _iso_ms_z(datetime.now(timezone.utc))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CountersignError("created_at must be a timezone-aware datetime")
        return _iso_ms_z(value)
    if not isinstance(value, str) or not _ISO_MS_Z.fullmatch(value):
        raise CountersignError(
            "created_at must be an ISO 8601 UTC time with milliseconds, e.g. 2026-01-01T00:00:00.000Z "
            "(the form JavaScript's toISOString gives)"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise CountersignError(f"created_at {value!r} is not a real date and time") from None
    return value


def _intent_id(value) -> str:
    if value is None:
        return str(uuid.uuid4())
    if not isinstance(value, str) or not _LOWERCASE_UUID.fullmatch(value):
        raise CountersignError(
            "intent_id must be a lowercase UUID (8-4-4-4-12 hex digits); chat button payloads accept only that form"
        )
    return value


def _normalize_approver(entry):
    """A bare string is shorthand for a ``vouched`` approver; an object passes through
    as ``{actor, mode}`` plus ``public_key`` when present (other keys are dropped)."""
    if isinstance(entry, str):
        return {"actor": entry, "mode": "vouched"}
    if not isinstance(entry, Mapping):
        raise CountersignError("each approver must be a string or an object")
    out = {"actor": entry.get("actor"), "mode": entry.get("mode")}
    if "public_key" in entry:
        out["public_key"] = entry["public_key"]
    return out


def create_intent(fields, agent_secret_key, *, agent_id, intent_id=None, created_at=None):
    """
    Build and sign an Intent, exactly as the reference's ``createIntent`` does.

    ``fields`` is a mapping with ``action``, ``summary``, ``risk_tier``,
    ``approvers`` (bare strings are ``vouched`` approvers), ``timeout``, ``default``
    and optionally ``quorum`` (default 1) and ``callback`` (default None). Other
    keys are ignored, as in the reference: nothing outside the protocol's fields is
    signed. ``agent_secret_key`` is the agent's base64url ed25519 seed; the Intent
    carries its public key. ``agent_id`` names the agent.

    ``intent_id`` defaults to a fresh random UUID (v4). Pass one only when you
    must know it before signing, and never reuse one: a fresh id per Intent is the
    replay defence. It must be a lowercase UUID. ``created_at`` defaults to now; it
    may be an aware ``datetime`` or a ``YYYY-MM-DDTHH:MM:SS.mmmZ`` string.

    Raises CountersignError on anything the reference would refuse.
    """
    if not isinstance(agent_id, str) or len(agent_id) == 0:
        raise CountersignError("agent_id must be a non-empty string")
    try:
        if not isinstance(agent_secret_key, str):
            raise TypeError
        agent_public_key = public_key_from_secret(agent_secret_key)
    except Exception:
        raise CountersignError("agent_secret_key is not a valid ed25519 secret key") from None
    if not isinstance(fields, Mapping):
        raise CountersignError("fields must be a mapping of Intent fields")

    action = fields.get("action")
    if not action:
        raise CountersignError("Intent.action is required")
    if not isinstance(action, str):
        raise CountersignError("Intent.action must be a string")
    summary = fields.get("summary")
    if not summary:
        raise CountersignError("Intent.summary is required")
    if not isinstance(summary, str):
        raise CountersignError("Intent.summary must be a string")
    risk_tier = fields.get("risk_tier")
    if not isinstance(risk_tier, str) or risk_tier not in RISK_TIERS:
        raise CountersignError(f"invalid risk_tier: {risk_tier}")
    raw_approvers = fields.get("approvers")
    if not isinstance(raw_approvers, (list, tuple)) or len(raw_approvers) == 0:
        raise CountersignError("Intent.approvers must be a non-empty array")
    approvers = [_normalize_approver(a) for a in raw_approvers]
    raw_quorum = fields.get("quorum")
    quorum = 1 if raw_quorum is None else _as_js_integer(raw_quorum)
    if quorum is None or quorum < 1:
        raise CountersignError("Intent.quorum must be an integer >= 1")
    # validate_approvers treats a None public_key as absent; the reference treats a
    # present-but-null key on a vouched approver as present. Refuse it here so a
    # vouched approver never signs as {"public_key": null}.
    for a in approvers:
        if a.get("mode") == "vouched" and "public_key" in a and isinstance(a.get("actor"), str) and a["actor"]:
            raise CountersignError(f"vouched approver {a['actor']} must not carry a public_key")
    validate_approvers(approvers, quorum)
    default = fields.get("default")
    if quorum > 1 and default == "approve":
        raise CountersignError(
            "Intent.quorum > 1 must not be combined with default: approve "
            "(a timeout would bypass the required approvers)"
        )
    timeout = _as_js_integer(fields.get("timeout"))
    if timeout is None or timeout < 1 or timeout > MAX_TIMEOUT_SECONDS:
        raise CountersignError(
            f"Intent.timeout must be an integer number of seconds in [1, {MAX_TIMEOUT_SECONDS}]"
        )
    if not isinstance(default, str) or default not in DECISIONS:
        raise CountersignError(f"invalid default: {default}")
    callback = fields.get("callback")
    if callback is not None and not isinstance(callback, str):
        raise CountersignError("Intent.callback must be a string or None")

    unsigned = {
        "countersign": COUNTERSIGN_VERSION,
        "intent_id": _intent_id(intent_id),
        "agent": {"id": agent_id, "public_key": agent_public_key},
        "action": action,
        "summary": summary,
        "risk_tier": risk_tier,
        "approvers": approvers,
        "quorum": quorum,
        "timeout": timeout,
        "default": default,
        "callback": callback,
        "created_at": _created_at(created_at),
    }
    canonical = canonicalize(unsigned)
    try:
        canonical.encode("utf-8")
    except UnicodeEncodeError as e:
        # A lone UTF-16 surrogate (U+D800..U+DFFF on its own) has no UTF-8 form, so
        # the envelope cannot be signed. Name the field rather than leak the codec error.
        raise CountersignError(
            f"Intent contains a lone surrogate ({_surrogate_field(unsigned)}, U+{ord(e.object[e.start]):04X}); "
            "every string must be valid Unicode text"
        ) from None
    signature = sign_context(agent_secret_key, INTENT_CONTEXT, canonical)
    return {**unsigned, "signature": signature}


def _surrogate_field(unsigned) -> str:
    """The first field of an unsigned Intent that holds a lone surrogate, for the error message."""
    def bad(value) -> bool:
        if isinstance(value, str):
            return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
        if isinstance(value, dict):
            return any(bad(k) or bad(v) for k, v in value.items())
        if isinstance(value, list):
            return any(bad(v) for v in value)
        return False

    for key, value in unsigned.items():
        if bad(value):
            return key
    return "a field"


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
