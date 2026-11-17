# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
FileReceiptLog: the TypeScript reference's file-backed ReceiptLog
(src/receipt-log.ts), in Python. Same file (one canonical-JSON ChainEntry per
line), same hash chain, same head, same audit; proven both ways against the
reference through tsx.
"""
import json
import os
import threading
from datetime import datetime, timedelta, timezone

import pytest

from conftest import load_vectors, vector_key

from countersign import (
    CHAIN_GENESIS,
    CountersignError,
    FileReceiptLog,
    ReceiptLog,
    canonicalize,
    create_intent,
    sign_decision,
)
from countersign.receipt_log import entry_hash

V = load_vectors()
AGENT = vector_key("agent")
AUTH = vector_key("authority")
CEO = vector_key("ceo")
CTO = vector_key("cto")
ROGUE = vector_key("rogue")


def _iso(ms_from_now=0):
    t = datetime.now(timezone.utc) + timedelta(milliseconds=ms_from_now)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _intent(**over):
    f = {"action": "billing.refund", "summary": "Refund 42.00", "risk_tier": "high",
         "approvers": ["tg:alice"], "timeout": 300, "default": "reject"}
    f.update(over)
    return create_intent(f, AGENT["secret"], agent_id="agent:test")


def _keyed_intent():
    return _intent(approvers=[{"actor": "m:ceo", "mode": "keyed", "public_key": CEO["public"]},
                              {"actor": "m:cto", "mode": "keyed", "public_key": CTO["public"]}],
                   quorum=2, risk_tier="critical")


def _default_receipt(intent):
    created = datetime.strptime(intent["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    t = created + timedelta(seconds=intent["timeout"])
    stamp = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    return sign_decision(intent, "reject", "default:timeout", AUTH["secret"], policy="default", timestamp=stamp)


def honest_log(path):
    """Four decisions: vouched approve, keyed 2-of-2 approve, a veto, a timeout Default."""
    log = FileReceiptLog(path)
    vouched, keyed = _intent(), _keyed_intent()
    veto = _intent(action="mail.send", approvers=["slack:U0BOB"], risk_tier="medium")
    silent = _intent(action="post.publish", approvers=["tg:carol"], timeout=1, risk_tier="low")
    log.record({"decision": "approve", "policy": "approver",
                "countersignatures": [sign_decision(vouched, "approve", "tg:alice", AUTH["secret"])]})
    log.record({"decision": "approve", "policy": "approver", "countersignatures": [
        sign_decision(keyed, "approve", "m:ceo", CEO["secret"]),
        sign_decision(keyed, "approve", "m:cto", CTO["secret"]),
    ]})
    log.append(sign_decision(veto, "reject", "slack:U0BOB", AUTH["secret"]))
    log.append(_default_receipt(silent))
    return log, [vouched, keyed, veto, silent]


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path, lines):
    path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")


# --- file format and chain ---------------------------------------------------

def test_a_missing_file_is_an_empty_log(tmp_path):
    log = FileReceiptLog(tmp_path / "none.jsonl")
    assert log.head() == {"length": 0, "hash": CHAIN_GENESIS}
    assert log.read() == []
    assert log.history() == {}
    assert log.verify_chain() == {"intact": True, "length": 0}


def test_vectors_chain_head_and_lines(tmp_path):
    path = tmp_path / "sub" / "dir" / "r.jsonl"  # parent folders are created
    log = FileReceiptLog(path)
    for r in V["chain"]["receipts"]:
        log.append(r)
    assert log.head() == V["chain"]["expected_head"]
    lines = _lines(path)
    prev = CHAIN_GENESIS
    for i, (line, r) in enumerate(zip(lines, V["chain"]["receipts"])):
        entry = {"seq": i, "prev": prev, "receipt": r}
        assert line == canonicalize(entry)  # one canonical ChainEntry per line
        prev = entry_hash(entry)
    assert path.read_text(encoding="utf-8").endswith("\n")


def test_matches_the_in_memory_log(tmp_path):
    mem, f = ReceiptLog(), FileReceiptLog(tmp_path / "r.jsonl")
    for r in V["chain"]["receipts"]:
        mem.append(r)
        f.append(r)
    assert f.head() == mem.head()
    assert [json.loads(l) for l in _lines(tmp_path / "r.jsonl")] == mem.entries()


def test_appends_continue_the_chain_across_instances(tmp_path):
    path = tmp_path / "r.jsonl"
    receipts = V["chain"]["receipts"]
    FileReceiptLog(path).append(receipts[0])
    second = FileReceiptLog(path)  # a restart: head recovered from the file
    for r in receipts[1:]:
        second.append(r)
    assert second.head() == V["chain"]["expected_head"]
    assert second.verify_chain()["intact"] is True


def test_record_writes_every_receipt_in_order_and_an_empty_one_writes_nothing(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    assert log.head()["length"] == 5
    log.record({"decision": "approve", "policy": "approver", "countersignatures": []})
    assert log.head()["length"] == 5
    actors = [r["actor"] for r in log.read()]
    assert actors == ["tg:alice", "m:ceo", "m:cto", "slack:U0BOB", "default:timeout"]


def test_history_groups_by_intent_in_write_order(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    h = log.history()
    assert list(h.keys()) == [i["intent_id"] for i in intents]
    assert [r["actor"] for r in h[intents[1]["intent_id"]]] == ["m:ceo", "m:cto"]


def test_every_append_is_flushed_to_disk(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    log = FileReceiptLog(tmp_path / "r.jsonl")
    log.append(V["chain"]["receipts"][0])
    assert len(calls) >= 1
    n = len(calls)
    log.record({"countersignatures": V["chain"]["receipts"][1:]})
    assert len(calls) > n  # one flush per write, the whole resolution in one write


def test_a_resolution_is_written_in_one_write(tmp_path, monkeypatch):
    # The receipts of one resolution go to disk together, never one by one.
    writes = []
    real_write = os.write
    monkeypatch.setattr(os, "write", lambda fd, b: (writes.append(bytes(b)), real_write(fd, b))[1])
    log = FileReceiptLog(tmp_path / "r.jsonl")
    log.record({"countersignatures": V["chain"]["receipts"]})
    assert len(writes) == 1 and writes[0].count(b"\n") == len(V["chain"]["receipts"])


def test_concurrent_appends_in_one_process_never_interleave(tmp_path):
    log = FileReceiptLog(tmp_path / "r.jsonl")
    intent = _intent()
    receipts = [sign_decision(intent, "approve", "tg:alice", AUTH["secret"]) for _ in range(40)]
    threads = [threading.Thread(target=log.append, args=(r,)) for r in receipts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert log.head()["length"] == 40
    assert log.verify_chain() == {"intact": True, "length": 40}


def test_a_corrupt_line_is_loud(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    for op in (log.read, log.head, log.verify_chain, log.history):
        with pytest.raises(CountersignError, match="corrupt at line 2"):
            op()
    with pytest.raises(CountersignError, match="corrupt"):
        FileReceiptLog(path).append(V["chain"]["receipts"][1])


def test_nan_and_infinity_are_corrupt_as_in_javascript(tmp_path):
    path = tmp_path / "r.jsonl"
    path.write_text('{"seq":NaN}\n', encoding="utf-8")
    with pytest.raises(CountersignError, match="corrupt"):
        FileReceiptLog(path).read()


def test_blank_lines_and_crlf_are_ignored_as_in_the_reference(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    for r in V["chain"]["receipts"]:
        log.append(r)
    text = path.read_text(encoding="utf-8").replace("\n", "\r\n\n")
    path.write_text(text, encoding="utf-8")
    assert FileReceiptLog(path).head() == V["chain"]["expected_head"]


# --- verify_chain -------------------------------------------------------------

@pytest.fixture
def chained(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    for r in V["chain"]["receipts"]:
        log.append(r)
    return path, log


def test_chain_intact(chained):
    path, log = chained
    n = len(V["chain"]["receipts"])
    assert log.verify_chain() == {"intact": True, "length": n}
    assert log.verify_chain(V["chain"]["expected_head"]) == {"intact": True, "length": n}


def test_chain_edit_is_a_broken_link(chained):
    path, log = chained
    lines = _lines(path)
    e = json.loads(lines[0])
    e["receipt"]["actor"] = "tg:mallory"
    lines[0] = canonicalize(e)
    _write_lines(path, lines)
    assert log.verify_chain() == {"intact": False, "length": len(lines), "brokenAt": 1, "reason": "broken-link"}


def test_chain_reorder_is_bad_seq(chained):
    path, log = chained
    lines = _lines(path)
    lines[0], lines[1] = lines[1], lines[0]
    _write_lines(path, lines)
    assert log.verify_chain() == {"intact": False, "length": len(lines), "brokenAt": 0, "reason": "bad-seq"}


def test_chain_bad_genesis(chained):
    path, log = chained
    lines = _lines(path)
    e = json.loads(lines[0])
    e["prev"] = "x"
    lines[0] = canonicalize(e)
    _write_lines(path, lines)
    assert log.verify_chain()["reason"] == "bad-genesis"


def test_chain_truncation_and_divergence_need_the_anchor(chained):
    path, log = chained
    head = log.head()
    lines = _lines(path)
    _write_lines(path, lines[:-1])
    assert log.verify_chain()["intact"] is True  # what remains is self-consistent
    assert log.verify_chain(head) == {"intact": False, "length": len(lines) - 1,
                                      "brokenAt": len(lines) - 1, "reason": "truncated"}
    _write_lines(path, lines)
    other = dict(head, hash="A" * 43)
    assert log.verify_chain(other) == {"intact": False, "length": len(lines),
                                       "brokenAt": head["length"] - 1, "reason": "diverged"}
    assert log.verify_chain({"length": 0, "hash": CHAIN_GENESIS})["intact"] is True


def test_a_legacy_bare_receipt_line_reads_but_is_unchained(tmp_path):
    path = tmp_path / "r.jsonl"
    r = V["chain"]["receipts"][0]
    path.write_text(canonicalize(r) + "\n", encoding="utf-8")
    log = FileReceiptLog(path)
    assert log.read() == [r]
    assert log.verify_chain() == {"intact": False, "length": 1, "brokenAt": 0, "reason": "unchained-entry"}


def test_a_malformed_expected_head_is_refused(chained):
    _, log = chained
    for bad in ({"length": "2", "hash": "x"}, {"hash": "x"}, {"length": 1}, "head", {"length": True, "hash": "x"}):
        with pytest.raises(CountersignError):
            log.verify_chain(bad)


# --- verify_all ---------------------------------------------------------------

def test_verify_all_honest_log(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    report = log.verify_all(intents=intents, authority_key=AUTH["public"], trusted_agent_keys=[AGENT["public"]],
                            expected_head=log.head())
    assert report == {"total": 5, "valid": 5, "faults": [], "chain": {"intact": True, "length": 5}, "ok": True}


def test_verify_all_positional_trusted_keys_and_expected_head(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    # With no Intents, trusted_keys is a plain allowlist of signing keys.
    report = log.verify_all([AUTH["public"], CEO["public"], CTO["public"]], log.head())
    assert report["ok"] is True
    report = log.verify_all([AUTH["public"]], log.head())
    assert [f["actor"] for f in report["faults"]] == ["m:ceo", "m:cto"]
    assert {f["reason"] for f in report["faults"]} == {"untrusted-key"}


def test_verify_all_integrity_only_without_options(tmp_path):
    log, _ = honest_log(tmp_path / "r.jsonl")
    assert log.verify_all()["ok"] is True


def test_vouched_and_default_receipts_need_the_authority_key(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    report = log.verify_all(intents=intents)
    assert [(f["index"], f["reason"]) for f in report["faults"]] == [
        (0, "missing-authority-key"), (1, "missing-authority-key"), (2, "missing-authority-key"),
        (3, "missing-authority-key"), (4, "missing-authority-key"),
    ]
    assert report["ok"] is False


def test_a_tampered_receipt_is_an_invalid_signature(tmp_path):
    path = tmp_path / "r.jsonl"
    log, intents = honest_log(path)
    lines = _lines(path)
    e = json.loads(lines[3])
    e["receipt"]["decision"] = "approve"
    lines[3] = canonicalize(e)
    _write_lines(path, lines)
    report = log.verify_all(intents=intents, authority_key=AUTH["public"])
    assert report["faults"] == [{"index": 3, "intent_id": intents[2]["intent_id"], "actor": "slack:U0BOB",
                                 "reason": "invalid-signature"}]
    assert report["chain"]["reason"] == "broken-link"


def test_unknown_and_unverified_intents(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    tampered = dict(intents[1], summary="Deploy something else")
    report = log.verify_all(intents=[intents[0], tampered, intents[3]], authority_key=AUTH["public"])
    reasons = [(f["index"], f["reason"]) for f in report["faults"]]
    assert reasons == [(1, "unverified-intent"), (2, "unverified-intent"), (3, "unknown-intent")]


def test_agent_pin_drops_intents_from_other_agents(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    report = log.verify_all(intents=intents, authority_key=AUTH["public"], trusted_agent_keys=[ROGUE["public"]])
    assert {f["reason"] for f in report["faults"]} == {"unverified-intent"}


def test_an_intent_authored_by_the_authority_is_not_trusted(tmp_path):
    path = tmp_path / "r.jsonl"
    i = create_intent({"action": "a", "summary": "s", "risk_tier": "low", "approvers": ["tg:a"],
                       "timeout": 60, "default": "reject"}, AUTH["secret"], agent_id="agent:x")
    log = FileReceiptLog(path)
    log.append(sign_decision(i, "approve", "tg:a", AUTH["secret"]))
    assert log.verify_all(intents=[i], authority_key=AUTH["public"])["faults"][0]["reason"] == "unverified-intent"


def test_keyed_receipt_signed_by_someone_else_is_untrusted(tmp_path):
    path = tmp_path / "r.jsonl"
    keyed = _keyed_intent()
    log = FileReceiptLog(path)
    log.append(sign_decision(keyed, "approve", "m:ceo", ROGUE["secret"]))  # not the CEO's key
    log.append(sign_decision(keyed, "approve", "m:cto", AUTH["secret"]))   # the authority, on a keyed slot
    log.append(sign_decision(keyed, "approve", "m:nobody", AUTH["secret"]))  # not an approver
    log.append(sign_decision(keyed, "approve", "m:ceo", CEO["secret"], policy="default"))  # default label on a person
    report = log.verify_all(intents=[keyed], authority_key=AUTH["public"])
    assert [(f["index"], f["reason"]) for f in report["faults"]] == [
        (0, "untrusted-key"), (1, "untrusted-key"), (2, "untrusted-key"), (3, "untrusted-key"),
    ]


def test_keyed_slot_bound_to_the_authority_key_is_refused(tmp_path):
    path = tmp_path / "r.jsonl"
    i = _intent(approvers=[{"actor": "m:ceo", "mode": "keyed", "public_key": AUTH["public"]}])
    log = FileReceiptLog(path)
    log.append(sign_decision(i, "approve", "m:ceo", AUTH["secret"]))
    report = log.verify_all(intents=[i], authority_key=AUTH["public"])
    assert report["faults"][0]["reason"] == "untrusted-key"


def test_keyed_trusted_keys_is_an_extra_filter(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    report = log.verify_all([CEO["public"]], intents=intents, authority_key=AUTH["public"])
    assert [(f["actor"], f["reason"]) for f in report["faults"]] == [("m:cto", "untrusted-key")]
    # raw key and its passkey wrapper are one identity
    report = log.verify_all(["webauthn-ed25519:" + CEO["public"], CTO["public"]], intents=intents,
                            authority_key=AUTH["public"])
    assert report["ok"] is True


def test_an_early_or_wrong_default_is_untrusted(tmp_path):
    path = tmp_path / "r.jsonl"
    i = _intent(timeout=3600)
    log = FileReceiptLog(path)
    log.append(sign_decision(i, "reject", "default:timeout", AUTH["secret"], policy="default", timestamp=_iso()))
    late = _default_receipt(i)
    log.append(dict(late))
    approve = sign_decision(i, "approve", "default:timeout", AUTH["secret"], policy="default",
                            timestamp=late["timestamp"])
    log.append(approve)
    report = log.verify_all(intents=[i], authority_key=AUTH["public"])
    assert [(f["index"], f["reason"]) for f in report["faults"]] == [(0, "untrusted-key"), (2, "untrusted-key")]


def test_authority_key_rotation_accepts_any_listed_key(tmp_path):
    log, intents = honest_log(tmp_path / "r.jsonl")
    report = log.verify_all(intents=intents, authority_key=[ROGUE["public"], AUTH["public"]])
    assert report["ok"] is True


def test_a_malformed_line_is_a_fault_not_an_exception(tmp_path):
    path = tmp_path / "r.jsonl"
    log, intents = honest_log(path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"hello":"world"}\n')
    report = log.verify_all(intents=intents, authority_key=AUTH["public"])
    assert report["faults"] == [{"index": 5, "intent_id": "", "actor": "", "reason": "malformed"}]


def test_passkey_receipts_fail_closed(tmp_path):
    path = tmp_path / "r.jsonl"
    case = next(c for c in V["webauthn"]["receipts"] if c.get("receipt"))
    receipt = case["receipt"]
    log = FileReceiptLog(path)
    log.append(receipt)
    broken = dict(receipt)
    broken.pop("webauthn", None)
    log.append(broken)
    report = log.verify_all()
    assert [(f["index"], f["reason"]) for f in report["faults"]] == [
        (0, "missing-webauthn-policy"), (1, "invalid-signature"),
    ]
    assert report["ok"] is False


def test_a_receipt_carrying_a_null_webauthn_block_does_not_verify(tmp_path):
    # The reference rejects ANY `webauthn` key on an ed25519 receipt, null included.
    path = tmp_path / "r.jsonl"
    i = _intent()
    r = sign_decision(i, "approve", "tg:alice", AUTH["secret"])
    log = FileReceiptLog(path)
    log.append(dict(r, webauthn=None))
    assert log.verify_all()["faults"][0]["reason"] == "invalid-signature"


@pytest.mark.parametrize("kwargs,match", [
    ({"intents": []}, "intents must not be an empty"),
    ({"intents": "x"}, "intents must be"),
    ({"authority_key": AUTH["public"]}, "authorityKey has no effect without"),
    ({"authority_key": [], "intents": [None]}, "must not be an empty array"),
    ({"authority_key": "nope", "intents": [None]}, "non-canonical"),
    ({"authority_key": 7}, "authorityKey must be"),
    ({"trusted_agent_keys": []}, "trustedAgentKeys must not be an empty"),
    ({"trusted_agent_keys": ""}, "trustedAgentKeys must be an array"),
    ({"trusted_agent_keys": [AGENT["public"]]}, "trustedAgentKeys has no effect without"),
    ({"trusted_keys": []}, "trustedKeys must not be empty"),
    ({"trusted_keys": ""}, "trustedKeys must not be empty"),
    ({"trusted_keys": [None, ""]}, "trustedKeys must not be empty"),
    ({"trusted_keys": 7}, "trustedKeys must be"),
])
def test_verify_all_refuses_misconfigured_options(tmp_path, kwargs, match):
    log, _ = honest_log(tmp_path / "r.jsonl")
    with pytest.raises(CountersignError, match=match):
        log.verify_all(**kwargs)


# --- interop with the TypeScript reference, both ways --------------------------

def _keyed_actors():
    return [{"actor": "m:ceo", "secret": CEO["secret"]}, {"actor": "m:cto", "secret": CTO["secret"]}]


def test_a_log_written_by_the_reference_verifies_in_python(ts, tmp_path):
    path = tmp_path / "ts.jsonl"
    out = ts("write-log", {"agent_id": "agent:ts", "agent_secret": AGENT["secret"],
                           "authority_secret": AUTH["secret"], "keyed": _keyed_actors()}, path)
    log = FileReceiptLog(path)
    assert log.head() == out["head"]
    assert log.history() == out["history"]
    report = log.verify_all(intents=out["intents"], authority_key=AUTH["public"],
                            trusted_agent_keys=[AGENT["public"]], expected_head=out["head"])
    assert report["ok"] is True, report
    assert report["total"] == out["head"]["length"] == 5
    # Python keeps appending to the reference's file; the reference still verifies it.
    log.append(sign_decision(out["intents"][0], "approve", "tg:alice", AUTH["secret"]))
    back = ts("verify-log", {"intents": out["intents"], "authority_key": AUTH["public"],
                             "expected_head": log.head()}, path)
    assert back["report"]["ok"] is True and back["head"] == log.head()


def test_a_log_written_by_python_verifies_in_the_reference(ts, tmp_path):
    path = tmp_path / "py.jsonl"
    log, intents = honest_log(path)
    opts = {"intents": intents, "authority_key": AUTH["public"], "trusted_agent_keys": [AGENT["public"]],
            "expected_head": log.head()}
    out = ts("verify-log", opts, path)
    assert out["head"] == log.head()
    assert out["history"] == log.history()
    assert out["report"]["ok"] is True, out["report"]
    assert out["report"] == log.verify_all(**opts)


def test_python_and_the_reference_agree_on_a_damaged_log(ts, tmp_path):
    path = tmp_path / "py.jsonl"
    log, intents = honest_log(path)
    head = log.head()
    lines = _lines(path)
    e = json.loads(lines[1])
    e["receipt"]["actor"] = "m:cto"  # a keyed receipt relabelled
    lines[1] = canonicalize(e)
    lines.append(canonicalize({"hello": "world"}))
    _write_lines(path, lines)
    for opts in (
        {"intents": intents, "authority_key": AUTH["public"], "expected_head": head},
        {"intents": [intents[0], dict(intents[1], summary="x")], "authority_key": AUTH["public"]},
        {"intents": intents},
        {"trusted_keys": [AUTH["public"]]},
        {"expected_head": dict(head, hash="A" * 43)},
        {},
    ):
        theirs = ts("verify-log", opts, path)["report"]
        assert log.verify_all(**opts) == theirs, opts


# --- a torn last line (the reference's rule, src/durable-file.ts) ----------------
#
# A crash in mid-append can leave a last line with no newline. As in the
# reference, nothing changes unless the log opts in: by default a torn last line
# raises, exactly as before. With repair_torn_tail=True, reads skip it and
# verify_all reports it in `tornTails` (ok false) WITHOUT changing the file: a
# reader never writes. Only the instance that appends repairs, before its next
# append: it moves the bytes into `<file>.quarantine.jsonl` and cuts the log back
# to its last whole line. A bad line anywhere else stays a hard fault.

import base64
import hashlib

from countersign.keys import b64url_encode


def _torn(path):
    """A log of one chained vector receipt, plus a torn half of the next entry."""
    n = 1
    log = FileReceiptLog(path)
    for r in V["chain"]["receipts"][:n]:
        log.append(r)
    whole = path.read_bytes()
    nxt = canonicalize({"seq": n, "prev": "x", "receipt": V["chain"]["receipts"][n]}).encode("utf-8")
    torn = nxt[: len(nxt) // 2]
    with open(path, "ab") as fh:
        fh.write(torn)
    return whole, torn


def _snapshot(path):
    q = path.parent / (path.name + ".quarantine.jsonl")
    return path.read_bytes(), os.stat(path).st_mtime_ns, q.exists()


def test_by_default_a_torn_last_line_raises_and_nothing_is_written(tmp_path):
    path = tmp_path / "r.jsonl"
    whole, torn = _torn(path)
    before = _snapshot(path)
    log = FileReceiptLog(path)
    for call in (log.read, log.history, log.head, log.verify_chain, log.verify_all):
        with pytest.raises(CountersignError, match="corrupt at line 2"):
            call()
    with pytest.raises(CountersignError, match="corrupt at line 2"):
        log.append(V["chain"]["receipts"][1])
    assert _snapshot(path) == before
    assert path.read_bytes() == whole + torn


def test_a_clean_report_has_exactly_the_reference_keys_by_default(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    assert sorted(log.verify_all()) == ["chain", "faults", "ok", "total", "valid"]


def test_a_reader_never_writes_it_reports_the_torn_tail(tmp_path):
    path = tmp_path / "r.jsonl"
    whole, torn = _torn(path)
    before = _snapshot(path)
    reader = FileReceiptLog(path, repair_torn_tail=True)
    assert len(reader.read()) == 1
    assert reader.head()["length"] == 1
    assert reader.verify_chain() == {"intact": True, "length": 1}
    report = reader.verify_all()
    assert _snapshot(path) == before
    assert report["faults"] == [] and report["total"] == 1 and report["valid"] == 1
    assert report["ok"] is False
    assert report["tornTails"] == [
        {"index": 1, "intent_id": report["tornTails"][0]["intent_id"], "offset": len(whole), "length": len(torn), "quarantined": False}
    ]


def test_an_auditor_during_an_append_in_flight_changes_nothing(tmp_path):
    # The writer's append is half on disk when the auditor looks; then it completes.
    path = tmp_path / "r.jsonl"
    writer = FileReceiptLog(path, repair_torn_tail=True)
    writer.append(V["chain"]["receipts"][0])
    line = canonicalize({"seq": 1, "prev": writer.head()["hash"], "receipt": V["chain"]["receipts"][1]}) + "\n"
    with open(path, "ab") as fh:
        fh.write(line[:40].encode())
    before = _snapshot(path)
    report = FileReceiptLog(path, repair_torn_tail=True).verify_all()
    assert _snapshot(path) == before
    assert report["ok"] is False and report["tornTails"][0]["quarantined"] is False
    with open(path, "ab") as fh:
        fh.write(line[40:].encode())
    after = FileReceiptLog(path, repair_torn_tail=True)
    assert len(after.read()) == 2
    assert after.head() == V["chain"]["expected_head"]
    assert after.verify_all()["ok"] is True and after.verify_all()["tornTails"] == []


def test_the_writer_repairs_before_its_next_append(tmp_path):
    path = tmp_path / "r.jsonl"
    whole, torn = _torn(path)
    log = FileReceiptLog(path, repair_torn_tail=True)
    assert len(log.read()) == 1
    assert path.read_bytes() == whole + torn  # the read moved nothing
    log.append(V["chain"]["receipts"][1])
    q = [json.loads(l) for l in (tmp_path / "r.jsonl.quarantine.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(q) == 1
    rec = q[0]
    assert base64.b64decode(rec["bytes_b64"]) == torn
    assert rec["sha256"] == b64url_encode(hashlib.sha256(torn).digest())
    assert (rec["line"], rec["offset"], rec["length"]) == (1, len(whole), len(torn))
    assert log.quarantine_path == str(tmp_path / "r.jsonl.quarantine.jsonl")
    assert log.verify_chain() == {"intact": True, "length": 2}
    assert log.head() == V["chain"]["expected_head"]
    # A fresh instance (a restart) still reports it, as quarantined.
    report = FileReceiptLog(path, repair_torn_tail=True).verify_all()
    assert report["chain"]["intact"] is True
    assert report["total"] == 2 and report["valid"] == 2 and report["faults"] == []
    assert [(t["index"], t["quarantined"]) for t in report["tornTails"]] == [(1, True)]
    assert report["ok"] is False
    # A default reader sees the quarantine too (it never existed for a user who opted into nothing).
    assert [t["quarantined"] for t in FileReceiptLog(path).verify_all()["tornTails"]] == [True]


def test_a_tail_torn_after_the_instance_opened_is_reported_then_repaired(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path, repair_torn_tail=True)
    log.append(V["chain"]["receipts"][0])
    log.append(V["chain"]["receipts"][1])
    path.write_bytes(path.read_bytes()[:-30])
    before = _snapshot(path)
    report = log.verify_all()
    assert _snapshot(path) == before
    assert report["ok"] is False and report["total"] == 1
    assert [t["quarantined"] for t in report["tornTails"]] == [False]
    log.append(V["chain"]["receipts"][1])
    assert log.verify_chain() == {"intact": True, "length": 2}
    assert [t["quarantined"] for t in log.verify_all()["tornTails"]] == [True]


def test_repair_can_be_called_and_is_then_a_no_op(tmp_path):
    path = tmp_path / "r.jsonl"
    whole, torn = _torn(path)
    log = FileReceiptLog(path)  # explicit: repairs even without the option
    first = log.repair()
    assert first["line"] == 1 and first["offset"] == len(whole) and first["length"] == len(torn)
    assert log.repair() is None
    assert path.read_bytes() == whole


def test_a_whole_last_entry_missing_only_its_newline_is_kept(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    log2 = FileReceiptLog(path, repair_torn_tail=True)
    assert len(log2.read()) == 1
    log2.append(V["chain"]["receipts"][1])
    assert path.read_bytes().count(b"\n") == 2
    assert not (tmp_path / "r.jsonl.quarantine.jsonl").exists()
    assert log2.verify_all()["ok"] is True


def test_a_corrupt_middle_line_is_still_a_hard_fault_and_nothing_is_quarantined(tmp_path):
    path = tmp_path / "r.jsonl"
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(canonicalize({"seq": 2, "prev": "x", "receipt": V["chain"]["receipts"][1]}) + "\n")
    for log2 in (FileReceiptLog(path), FileReceiptLog(path, repair_torn_tail=True)):
        with pytest.raises(CountersignError, match="corrupt at line 2"):
            log2.read()
        with pytest.raises(CountersignError, match="corrupt at line 2"):
            log2.append(V["chain"]["receipts"][1])
    assert not (tmp_path / "r.jsonl.quarantine.jsonl").exists()


def test_a_quarantine_record_written_twice_is_reported_once(tmp_path):
    path = tmp_path / "r.jsonl"
    _torn(path)
    FileReceiptLog(path).repair()
    q = tmp_path / "r.jsonl.quarantine.jsonl"
    q.write_bytes(q.read_bytes() * 2)  # a repair interrupted between its two steps, then re-run
    report = FileReceiptLog(path, repair_torn_tail=True).verify_all()
    assert report["faults"] == []
    assert len(report["tornTails"]) == 1


def test_python_and_the_reference_agree_on_a_torn_tail(ts, tmp_path):
    # Still in the file: both read it, neither changes it, both report the same.
    path = tmp_path / "py.jsonl"
    log, intents = honest_log(path)
    with open(path, "ab") as fh:
        fh.write(b'{"seq":5,"prev":"abc","receipt":{"intent_id":"' + intents[0]["intent_id"].encode() + b'","de')
    before = path.read_bytes()
    opts = {"intents": intents, "authority_key": AUTH["public"]}
    mine = FileReceiptLog(path, repair_torn_tail=True).verify_all(**opts)
    assert mine["tornTails"][0]["intent_id"] == intents[0]["intent_id"]
    assert mine["tornTails"][0]["quarantined"] is False
    assert ts("verify-log", dict(opts, repair_torn_tail=True), path)["report"] == mine
    assert path.read_bytes() == before
    # Python's writer repairs; the reference reports the same, quarantined.
    FileReceiptLog(path, repair_torn_tail=True).repair()
    mine = FileReceiptLog(path, repair_torn_tail=True).verify_all(**opts)
    assert mine["tornTails"][0]["quarantined"] is True
    assert ts("verify-log", dict(opts, repair_torn_tail=True), path)["report"] == mine
    # The reference reads a torn log written by itself the same way Python does.
    path2 = tmp_path / "ts.jsonl"
    _, intents2 = honest_log(path2)
    with open(path2, "ab") as fh:
        fh.write(b'{"seq":5,"pr')
    opts2 = {"intents": intents2, "authority_key": AUTH["public"]}
    theirs = ts("verify-log", dict(opts2, repair_torn_tail=True), path2)
    assert theirs["report"]["tornTails"][-1]["quarantined"] is False
    assert FileReceiptLog(path2, repair_torn_tail=True).verify_all(**opts2) == theirs["report"]
    assert FileReceiptLog(path2, repair_torn_tail=True).head() == theirs["head"]


# --- N6: a whole last entry that only lost its newline (default instance) ----------
# 0.2.0 (and the reference before this fix) glued the next entry onto it, and the log
# then read as corrupt. The append path now writes the missing newline first; nothing
# is cut or moved, a reader never writes, and a segment that does not parse is left
# exactly as before.


def _without_final_newline(path):
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    data = path.read_bytes()
    path.write_bytes(data[:-1])
    return data[:-1]


def test_default_append_restores_a_lost_newline_before_appending(tmp_path):
    path = tmp_path / "r.jsonl"
    cut = _without_final_newline(path)
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][1])
    after = path.read_bytes()
    assert after.startswith(cut + b"\n") and after.endswith(b"\n")
    assert len(FileReceiptLog(path).read()) == 2
    assert FileReceiptLog(path).verify_chain() == {"intact": True, "length": 2}
    assert not (tmp_path / "r.jsonl.quarantine.jsonl").exists()


def test_a_reader_never_restores_the_newline(tmp_path):
    path = tmp_path / "r.jsonl"
    cut = _without_final_newline(path)
    reader = FileReceiptLog(path)
    reader.read(); reader.history(); reader.head(); reader.verify_chain(); reader.verify_all()
    assert path.read_bytes() == cut


def test_default_append_leaves_an_unparseable_tail_exactly_as_before(tmp_path):
    path = tmp_path / "r.jsonl"
    whole, torn = _torn(path)
    with pytest.raises(CountersignError, match="corrupt at line 2"):
        FileReceiptLog(path).append(V["chain"]["receipts"][1])
    assert path.read_bytes() == whole + torn


# --- NF1: the lost newline only after the head reads cleanly, and only after this
# log's own last chain entry. A failing append writes nothing, as in 0.2.0.


def _two_lines(path):
    log = FileReceiptLog(path)
    log.append(V["chain"]["receipts"][0])
    log.append(V["chain"]["receipts"][1])
    l1, l2 = path.read_bytes().split(b"\n")[:2]
    return l1, l2


def test_failing_append_on_a_corrupt_line_elsewhere_leaves_the_file_byte_for_byte(tmp_path):
    path = tmp_path / "r.jsonl"
    l1, l2 = _two_lines(path)
    damaged = l1 + b"\ngarbage\n" + l2
    path.write_bytes(damaged)
    with pytest.raises(CountersignError, match="corrupt at line 2"):
        FileReceiptLog(path).append(V["chain"]["receipts"][0])
    assert path.read_bytes() == damaged


def test_a_whole_object_that_is_not_a_chain_entry_gets_no_newline(tmp_path):
    path = tmp_path / "r.jsonl"
    FileReceiptLog(path).append(V["chain"]["receipts"][0])
    before = path.read_bytes() + b'{"x":1}'
    path.write_bytes(before)
    FileReceiptLog(path).append(V["chain"]["receipts"][1])
    after = path.read_bytes()
    assert after.startswith(before) and after[len(before):len(before) + 1] == b"{"


def test_a_chain_entry_that_is_not_the_head_gets_no_newline(tmp_path):
    path = tmp_path / "r.jsonl"
    l1, l2 = _two_lines(path)
    wrong = l1 + b"\n" + l1 + b"\n" + l2  # l2 claims seq 1 but sits at index 2
    path.write_bytes(wrong)
    FileReceiptLog(path).append(V["chain"]["receipts"][0])
    after = path.read_bytes()
    assert after.startswith(wrong) and after[len(wrong):len(wrong) + 1] == b"{"
