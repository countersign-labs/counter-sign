# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
create_intent: the Python client builds and signs an Intent exactly as the
TypeScript reference's createIntent does (src/core/intent.ts).

Two kinds of proof:
  1. Byte for byte against the committed vectors: given a vector's fields, agent
     key, intent_id and created_at, the output IS the vector's Intent.
  2. Against the reference itself, through tsx: every case the reference accepts,
     Python accepts and signs to the same bytes; every case it refuses, Python
     refuses too.
"""
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from conftest import load_vectors, vector_key

from countersign import (
    CountersignError,
    assert_intent_invariants,
    canonicalize,
    create_intent,
    public_key_from_secret,
    verify_intent,
)
from countersign.constants import MAX_TIMEOUT_SECONDS

V = load_vectors()
AGENT = vector_key("agent")
CEO = vector_key("ceo")
CTO = vector_key("cto")
AUTHORITY = vector_key("authority")

FIELD_NAMES = ("action", "summary", "risk_tier", "approvers", "quorum", "timeout", "default", "callback")

UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ISO_MS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def fields(**over):
    base = {
        "action": "billing.refund",
        "summary": "Refund $42.00 to customer 8675309",
        "risk_tier": "high",
        "approvers": ["tg:alice"],
        "timeout": 300,
        "default": "reject",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not _DROP}


_DROP = object()


def make(f=None, **kw):
    kw.setdefault("agent_id", "agent:test")
    return create_intent(fields() if f is None else f, AGENT["secret"], **kw)


# --- 1. the committed vectors, byte for byte ---------------------------------

VALID_INTENT_VECTORS = [c for c in V["intents"] if c["valid"]]


@pytest.mark.parametrize("case", VALID_INTENT_VECTORS, ids=[c["name"] for c in VALID_INTENT_VECTORS])
def test_reproduces_vector_intent_byte_for_byte(case):
    want = case["intent"]
    assert want["agent"]["public_key"] == AGENT["public"]  # the vectors sign with the "agent" key
    got = create_intent(
        {k: want[k] for k in FIELD_NAMES},
        AGENT["secret"],
        agent_id=want["agent"]["id"],
        intent_id=want["intent_id"],
        created_at=want["created_at"],
    )
    assert got == want
    assert canonicalize({k: v for k, v in got.items() if k != "signature"}) == case["canonical_unsigned"]
    assert canonicalize(got) == canonicalize(want)


def test_vector_fields_with_bare_string_approver_give_the_same_intent():
    # Shorthand: a bare string is a vouched approver — same bytes as the object form.
    want = VALID_INTENT_VECTORS[0]["intent"]
    assert want["approvers"] == [{"actor": "tg:alice", "mode": "vouched"}]
    f = {k: want[k] for k in FIELD_NAMES}
    f["approvers"] = ["tg:alice"]
    del f["quorum"]  # absent quorum means 1
    del f["callback"]  # absent callback means null
    got = create_intent(f, AGENT["secret"], agent_id=want["agent"]["id"],
                        intent_id=want["intent_id"], created_at=want["created_at"])
    assert got == want


# --- 2. defaults -------------------------------------------------------------

def test_default_id_is_a_fresh_lowercase_uuid4_and_time_is_iso_ms_z():
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    a, b = make(), make()
    after = datetime.now(timezone.utc) + timedelta(seconds=1)
    for i in (a, b):
        assert UUID_V4.match(i["intent_id"])
        assert ISO_MS_Z.match(i["created_at"])
        t = datetime.strptime(i["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        assert before <= t <= after
        assert verify_intent(i) is True
        assert_intent_invariants(i)
    assert a["intent_id"] != b["intent_id"]


def test_envelope_shape_and_derived_fields():
    i = make(fields(approvers=["tg:alice", {"actor": "m:ceo", "mode": "keyed", "public_key": CEO["public"]}]))
    assert list(i.keys()) == [
        "countersign", "intent_id", "agent", "action", "summary", "risk_tier", "approvers",
        "quorum", "timeout", "default", "callback", "created_at", "signature",
    ]
    assert i["countersign"] == "0.2"
    assert i["agent"] == {"id": "agent:test", "public_key": AGENT["public"]}
    assert i["approvers"] == [
        {"actor": "tg:alice", "mode": "vouched"},
        {"actor": "m:ceo", "mode": "keyed", "public_key": CEO["public"]},
    ]
    assert i["quorum"] == 1 and i["callback"] is None


def test_unknown_fields_and_extra_approver_keys_are_dropped_as_in_the_reference():
    f = fields(approvers=[{"actor": "tg:alice", "mode": "vouched", "note": "x"}])
    f["payload"] = {"not": "signed"}
    i = make(f)
    assert "payload" not in i
    assert i["approvers"] == [{"actor": "tg:alice", "mode": "vouched"}]


def test_does_not_alias_the_callers_approver_objects():
    approver = {"actor": "tg:alice", "mode": "vouched"}
    i = make(fields(approvers=[approver]))
    approver["actor"] = "tg:mallory"
    assert i["approvers"][0]["actor"] == "tg:alice"
    assert verify_intent(i) is True


def test_accepts_an_aware_datetime_for_created_at():
    when = datetime(2026, 1, 1, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    i = make(intent_id="11111111-1111-4111-8111-111111111111", created_at=when)
    assert i["created_at"] == "2026-01-01T00:00:00.000Z"


# --- 3. every authorship rule ------------------------------------------------

KEYED_CEO = {"actor": "m:ceo", "mode": "keyed", "public_key": CEO["public"]}
KEYED_CTO = {"actor": "m:cto", "mode": "keyed", "public_key": CTO["public"]}
NON_CANONICAL_CEO = CEO["public"][:-1] + chr(ord(CEO["public"][-1]) + 1)  # same bytes, other spelling
P256_POINT = "BA" + "A" * 85  # 65 bytes, starts 0x04 — well formed (curve not checked, as in TS)

# (name, fields overrides) the reference ACCEPTS
ACCEPT = [
    ("bare-string", {}),
    ("object-vouched", {"approvers": [{"actor": "tg:alice", "mode": "vouched"}]}),
    ("mixed", {"approvers": ["tg:alice", KEYED_CEO]}),
    ("keyed-quorum-2", {"approvers": [KEYED_CEO, KEYED_CTO], "quorum": 2, "risk_tier": "critical"}),
    ("passkey-ed25519", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "webauthn-ed25519:" + CEO["public"]}]}),
    ("passkey-p256", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "webauthn-p256:" + P256_POINT}]}),
    ("callback", {"callback": "https://example.com/cs"}),
    ("default-approve-q1", {"default": "approve"}),
    ("quorum-null", {"quorum": None}),
    ("timeout-1", {"timeout": 1}),
    ("timeout-max", {"timeout": MAX_TIMEOUT_SECONDS}),
    ("risk-low", {"risk_tier": "low"}),
    ("risk-medium", {"risk_tier": "medium"}),
    ("unicode", {"summary": "Pay ₹4,200 to Ünïcode café", "approvers": ["tg:Ålice"]}),
    ("integral-float-quorum", {"quorum": 1.0}),
    ("integral-float-timeout", {"timeout": 300.0}),
]

# (name, fields overrides, agent_id, agent_secret) the reference REFUSES
REFUSE = [
    ("empty-agent-id", {}, "", None),
    ("short-secret", {}, None, "abc"),
    ("no-action", {"action": _DROP}, None, None),
    ("empty-action", {"action": ""}, None, None),
    ("no-summary", {"summary": _DROP}, None, None),
    ("empty-summary", {"summary": ""}, None, None),
    ("bad-risk", {"risk_tier": "extreme"}, None, None),
    ("no-risk", {"risk_tier": _DROP}, None, None),
    ("no-approvers", {"approvers": _DROP}, None, None),
    ("empty-approvers", {"approvers": []}, None, None),
    ("approvers-not-list", {"approvers": "tg:alice"}, None, None),
    ("approver-null", {"approvers": [None]}, None, None),
    ("approver-number", {"approvers": [7]}, None, None),
    ("empty-actor", {"approvers": [""]}, None, None),
    ("bad-mode", {"approvers": [{"actor": "tg:a", "mode": "trusted"}]}, None, None),
    ("no-mode", {"approvers": [{"actor": "tg:a"}]}, None, None),
    ("reserved-actor", {"approvers": ["default:timeout"]}, None, None),
    ("reserved-actor-variant", {"approvers": [" Default:Timeout "]}, None, None),
    ("duplicate-actor", {"approvers": ["tg:alice", "tg:alice"]}, None, None),
    ("duplicate-normalized", {"approvers": ["tg:alice", " TG:Alice"]}, None, None),
    ("keyed-no-key", {"approvers": [{"actor": "m:ceo", "mode": "keyed"}]}, None, None),
    ("keyed-empty-key", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": ""}]}, None, None),
    ("keyed-non-canonical", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": NON_CANONICAL_CEO}]}, None, None),
    ("keyed-garbage", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "not-a-key"}]}, None, None),
    ("vouched-with-key", {"approvers": [{"actor": "tg:a", "mode": "vouched", "public_key": CEO["public"]}]}, None, None),
    ("vouched-with-null-key", {"approvers": [{"actor": "tg:a", "mode": "vouched", "public_key": None}]}, None, None),
    ("shared-key", {"approvers": [KEYED_CEO, {"actor": "m:cto", "mode": "keyed", "public_key": CEO["public"]}], "quorum": 2}, None, None),
    ("shared-key-through-passkey", {"approvers": [KEYED_CEO, {"actor": "m:cto", "mode": "keyed", "public_key": "webauthn-ed25519:" + CEO["public"]}]}, None, None),
    ("p256-short", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "webauthn-p256:" + "A" * 86}]}, None, None),
    ("p256-not-uncompressed", {"approvers": [{"actor": "m:ceo", "mode": "keyed", "public_key": "webauthn-p256:" + "Aw" + "A" * 85}]}, None, None),
    ("quorum-0", {"quorum": 0}, None, None),
    ("quorum-negative", {"quorum": -1}, None, None),
    ("quorum-fraction", {"quorum": 1.5}, None, None),
    ("quorum-string", {"quorum": "2"}, None, None),
    ("quorum-true", {"quorum": True}, None, None),
    ("timeout-true", {"timeout": True}, None, None),
    ("vouched-quorum-2", {"approvers": ["tg:a", "tg:b"], "quorum": 2}, None, None),
    ("mixed-quorum-2", {"approvers": ["tg:a", KEYED_CEO], "quorum": 2}, None, None),
    ("quorum-over-approvers", {"approvers": [KEYED_CEO], "quorum": 2}, None, None),
    ("quorum-2-default-approve", {"approvers": [KEYED_CEO, KEYED_CTO], "quorum": 2, "default": "approve"}, None, None),
    ("timeout-0", {"timeout": 0}, None, None),
    ("timeout-over-max", {"timeout": MAX_TIMEOUT_SECONDS + 1}, None, None),
    ("timeout-fraction", {"timeout": 1.5}, None, None),
    ("timeout-string", {"timeout": "300"}, None, None),
    ("no-timeout", {"timeout": _DROP}, None, None),
    ("bad-default", {"default": "maybe"}, None, None),
    ("no-default", {"default": _DROP}, None, None),
]


def _case(over, agent_id=None, agent_secret=None):
    return {
        "fields": fields(**over),
        "agent_id": "agent:test" if agent_id is None else agent_id,
        "agent_secret": AGENT["secret"] if agent_secret is None else agent_secret,
    }


@pytest.mark.parametrize("name,over", ACCEPT, ids=[c[0] for c in ACCEPT])
def test_accepts(name, over):
    c = _case(over)
    i = create_intent(c["fields"], c["agent_secret"], agent_id=c["agent_id"])
    assert verify_intent(i) is True
    assert_intent_invariants(i)


@pytest.mark.parametrize("name,over,agent_id,secret", REFUSE, ids=[c[0] for c in REFUSE])
def test_refuses_with_countersign_error(name, over, agent_id, secret):
    c = _case(over, agent_id, secret)
    with pytest.raises(CountersignError):
        create_intent(c["fields"], c["agent_secret"], agent_id=c["agent_id"])


def test_integral_floats_are_stored_as_ints():
    i = make(fields(quorum=1.0, timeout=300.0))
    assert type(i["quorum"]) is int and type(i["timeout"]) is int


# Python-side guards the reference does not need (its type system covers them).
@pytest.mark.parametrize("over", [
    {"action": 7}, {"summary": ["x"]}, {"risk_tier": ["high"]}, {"default": {"x": 1}},
    {"callback": 7}, {"approvers": {"tg:a": "vouched"}},
])
def test_refuses_wrong_python_types(over):
    with pytest.raises(CountersignError):
        make(fields(**over))


def test_fields_must_be_a_mapping():
    with pytest.raises(CountersignError):
        create_intent([("action", "x")], AGENT["secret"], agent_id="agent:test")


@pytest.mark.parametrize("secret", ["", "AQEB", None, 42, AGENT["public"] + "AA"])
def test_refuses_a_malformed_agent_secret(secret):
    with pytest.raises(CountersignError, match="secret"):
        create_intent(fields(), secret, agent_id="agent:test")


@pytest.mark.parametrize("bad", [
    "11111111-1111-4111-8111-11111111111A",   # uppercase hex
    "11111111-1111-4111-8111-1111111111111",  # too long
    "111111111111411181111111111111111111",   # no dashes
    "not-a-uuid",
    "",
    7,
])
def test_refuses_a_caller_supplied_intent_id_that_is_not_a_lowercase_uuid(bad):
    with pytest.raises(CountersignError, match="intent_id"):
        make(intent_id=bad)


def test_uppercase_uuid_is_refused_because_button_payloads_are_lowercase_only():
    upper = str(uuid.uuid4()).upper()
    with pytest.raises(CountersignError):
        make(intent_id=upper)
    assert make(intent_id=upper.lower())["intent_id"] == upper.lower()


@pytest.mark.parametrize("bad", [
    "2026-01-01T00:00:00Z",          # no milliseconds
    "2026-01-01T00:00:00.000+00:00",  # offset, not Z
    "2026-01-01 00:00:00.000Z",
    "2026-02-30T00:00:00.000Z",       # not a real date
    "yesterday",
    datetime(2026, 1, 1),             # naive datetime
    1767225600,
])
def test_refuses_a_created_at_that_is_not_iso_ms_z(bad):
    with pytest.raises(CountersignError, match="created_at"):
        make(created_at=bad)


def test_agent_id_is_required():
    with pytest.raises(TypeError):
        create_intent(fields(), AGENT["secret"])  # noqa  (keyword-only, required)
    with pytest.raises(CountersignError, match="agent"):
        create_intent(fields(), AGENT["secret"], agent_id=7)


def test_tuple_approvers_are_accepted_and_stored_as_a_list():
    i = make(fields(approvers=("tg:alice",)))
    assert i["approvers"] == [{"actor": "tg:alice", "mode": "vouched"}]


def test_create_intent_does_not_know_the_authority_key():
    # createIntent does not know the authority key; verify_resolution enforces the
    # separation. Signing with the authority key still produces a valid Intent.
    i = create_intent(fields(), AUTHORITY["secret"], agent_id="agent:test")
    assert i["agent"]["public_key"] == public_key_from_secret(AUTHORITY["secret"])


# --- 4. parity with the TypeScript reference, through tsx --------------------

def test_matches_the_typescript_reference_case_for_case(ts):
    accept = [_case(over) for _, over in ACCEPT if not any(isinstance(v, float) for v in over.values())]
    refuse = [_case(over, a, s) for _, over, a, s in REFUSE if not any(isinstance(v, float) for v in over.values())]
    results = ts("create-intents", {"cases": accept + refuse})
    assert len(results) == len(accept) + len(refuse)
    for c, r in zip(accept, results[: len(accept)]):
        assert r["ok"], f"the reference refused {c['fields']}: {r.get('error')}"
        want = r["intent"]
        got = create_intent(c["fields"], c["agent_secret"], agent_id=c["agent_id"],
                            intent_id=want["intent_id"], created_at=want["created_at"])
        assert got == want, c["fields"]
    for c, r in zip(refuse, results[len(accept):]):
        assert not r["ok"], f"the reference accepted {c['fields']} but Python refuses it"
        with pytest.raises(CountersignError):
            create_intent(c["fields"], c["agent_secret"], agent_id=c["agent_id"])


def test_float_cases_match_the_reference(ts):
    # JSON cannot tell 1.0 from 1 and JavaScript has one number type, so the
    # reference sees 1.0 as the integer 1 and 1.5 as a fraction; so does Python.
    results = ts("create-intents", {"cases": [
        _case({"quorum": 1.0}), _case({"timeout": 300.0}), _case({"quorum": 1.5}), _case({"timeout": 1.5}),
    ]})
    assert [r["ok"] for r in results] == [True, True, False, False]
    for over, r in zip(({"quorum": 1.0}, {"timeout": 300.0}), results):
        want = r["intent"]
        got = create_intent(fields(**over), AGENT["secret"], agent_id="agent:test",
                            intent_id=want["intent_id"], created_at=want["created_at"])
        assert got == want


def test_reference_verifies_a_python_made_intent(ts, tmp_path):
    # The other direction: a Python-made Intent decides receipts in the reference's audit.
    from countersign import FileReceiptLog, sign_decision

    i = make(fields(approvers=["tg:alice"]))
    log = FileReceiptLog(tmp_path / "r.jsonl")
    log.append(sign_decision(i, "approve", "tg:alice", AUTHORITY["secret"]))
    out = ts("verify-log", {"intents": [i], "authority_key": AUTHORITY["public"],
                            "trusted_agent_keys": [AGENT["public"]]}, tmp_path / "r.jsonl")
    assert out["report"]["ok"] is True, out["report"]


# A lone UTF-16 surrogate cannot be encoded as UTF-8, so it cannot be signed. Every
# other bad input raises CountersignError; so must this (it used to escape as a raw
# UnicodeEncodeError). The reference accepts it: see docs/proposals/0005.
@pytest.mark.parametrize("over, kw", [
    ({"summary": "lone \ud800 surrogate"}, {}),
    ({"summary": "low \udc00 first"}, {}),
    ({"action": "billing.\udfff"}, {}),
    ({"callback": "https://example.test/\ud83d"}, {}),
    ({"approvers": ["tg:\ud800"]}, {}),
    ({"approvers": [{"actor": "tg:alice", "mode": "keyed", "public_key": CEO["public"]}], "quorum": 1}, {"agent_id": "agent:\udbff"}),
])
def test_a_lone_surrogate_raises_countersign_error(over, kw):
    with pytest.raises(CountersignError, match="surrogate"):
        make(fields(**over), **kw)


def test_a_surrogate_pair_written_as_one_character_is_fine():
    assert make(fields(summary="ok \U0001F600"))["summary"] == "ok \U0001F600"
