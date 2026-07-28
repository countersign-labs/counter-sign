# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
verify_resolution — the end-to-end authorize/deny check, matching
src/core/defaults.ts. A resolution is justified in exactly two ways: a quorum of
distinct keyed/vouched approver receipts (``policy == "approver"``), or the signed
timeout Default (``policy == "default"``). Raises InvalidCountersignatureError on any
violation (fail closed). The negatives — under-quorum, forged quorum, wrong-authority
key — MUST be rejected.
"""
from .constants import DEFAULT_TIMEOUT_ACTOR
from .countersignature import (
    credential_key_material,
    normalize_actor,
    verify_countersignature,
)
from .errors import InvalidCountersignatureError
from .intent import assert_intent_invariants, quorum_of, verify_intent
from .keys import is_canonical_public_key
from .timeutil import parse_iso_ms


def deadline(intent) -> int:
    """Epoch milliseconds at which the Intent's Default fires."""
    created = parse_iso_ms(intent.get("created_at"))
    if created is None:
        raise InvalidCountersignatureError("Intent.created_at is not a valid timestamp")
    return created + intent["timeout"] * 1000


def verify_resolution(intent, resolution, expected_authority_public_key, webauthn=None) -> None:
    assert_intent_invariants(intent)
    if not verify_intent(intent):
        raise InvalidCountersignatureError(
            f"intent {intent.get('intent_id')} does not carry a valid agent signature"
        )
    if not is_canonical_public_key(expected_authority_public_key):
        raise InvalidCountersignatureError("expected authority public key is not a canonical ed25519 key")
    if intent.get("agent", {}).get("public_key") == expected_authority_public_key:
        raise InvalidCountersignatureError(
            f"intent {intent['intent_id']} was authored by the authority key "
            "— the agent and authority keys must be distinct"
        )

    receipts = resolution.get("countersignatures") if isinstance(resolution, dict) else None
    if not isinstance(receipts, list) or len(receipts) == 0:
        raise InvalidCountersignatureError(f"resolution for {intent['intent_id']} carries no receipts")
    decision = resolution.get("decision")
    if decision not in ("approve", "reject"):
        raise InvalidCountersignatureError(
            f"resolution for {intent['intent_id']} has invalid decision {decision!r}"
        )
    for cs in receipts:
        if cs.get("intent_id") != intent["intent_id"]:
            raise InvalidCountersignatureError(
                f"receipt intent_id {cs.get('intent_id')} does not match intent {intent['intent_id']}"
            )
        if cs.get("decision") != decision:
            raise InvalidCountersignatureError(
                f"a receipt for {intent['intent_id']} says {cs.get('decision')} "
                f"but the resolution claims {decision}"
            )

    policy = resolution.get("policy")
    if policy == "approver":
        by_actor = {}
        for a in intent["approvers"]:
            na = normalize_actor(a["actor"])
            if na != DEFAULT_TIMEOUT_ACTOR:
                by_actor[na] = a
        distinct = set()
        for cs in receipts:
            if cs.get("policy") != "approver":
                raise InvalidCountersignatureError(
                    f"{decision} resolution for {intent['intent_id']} has a receipt whose signed "
                    f'policy is {cs.get("policy")!r}, not "approver"'
                )
            actor = normalize_actor(cs.get("actor"))
            if actor == DEFAULT_TIMEOUT_ACTOR:
                raise InvalidCountersignatureError(
                    f"{decision} resolution for {intent['intent_id']} uses reserved actor "
                    "default:timeout as an approver"
                )
            approver = by_actor.get(actor)
            if approver is None:
                raise InvalidCountersignatureError(
                    f"{decision} resolution for {intent['intent_id']} has a receipt from "
                    f"{cs.get('actor')}, who is not in the Intent's approvers"
                )
            if approver["mode"] == "keyed":
                if not approver.get("public_key"):
                    raise InvalidCountersignatureError(
                        f"keyed approver {cs.get('actor')} for {intent['intent_id']} has no bound key"
                    )
                if credential_key_material(approver["public_key"]) == expected_authority_public_key:
                    raise InvalidCountersignatureError(
                        f"keyed approver {cs.get('actor')} for {intent['intent_id']} is bound to the "
                        "authority key — a keyed slot must be the approver's own key"
                    )
                trusted_key = approver["public_key"]
            else:
                trusted_key = expected_authority_public_key
            if not verify_countersignature(cs, trusted_keys=trusted_key, webauthn=webauthn):
                raise InvalidCountersignatureError(
                    f"a {approver['mode']} receipt from {cs.get('actor')} for {intent['intent_id']} "
                    f"was not signed by the expected key (got {cs.get('public_key')})"
                )
            distinct.add(actor)
        if decision == "approve":
            need = quorum_of(intent)
            if len(distinct) < need:
                raise InvalidCountersignatureError(
                    f"approve resolution for {intent['intent_id']} has {len(distinct)} distinct "
                    f"approver(s), needs {need}"
                )
    elif policy == "default":
        expected = "reject" if quorum_of(intent) > 1 else intent.get("default")
        if decision != expected:
            raise InvalidCountersignatureError(
                f"a default:{decision} resolution for {intent['intent_id']} contradicts the "
                f"Intent's Default ({expected})"
            )
        if (
            len(receipts) != 1
            or receipts[0].get("policy") != "default"
            or normalize_actor(receipts[0].get("actor")) != DEFAULT_TIMEOUT_ACTOR
        ):
            raise InvalidCountersignatureError(
                f"a default resolution for {intent['intent_id']} must be exactly one "
                "default:timeout receipt"
            )
        if not verify_countersignature(receipts[0], trusted_keys=expected_authority_public_key):
            raise InvalidCountersignatureError(
                f"the timeout Default for {intent['intent_id']} was not signed by the expected "
                f"authority (got {receipts[0].get('public_key')})"
            )
        ts = parse_iso_ms(receipts[0].get("timestamp"))
        if ts is None or not (ts >= deadline(intent)):
            raise InvalidCountersignatureError(
                f"a default resolution for {intent['intent_id']} is timestamped before the Intent's "
                "deadline — the Default cannot fire early"
            )
    else:
        raise InvalidCountersignatureError(
            f"resolution for {intent['intent_id']} has an unrecognized policy {policy!r}"
        )
