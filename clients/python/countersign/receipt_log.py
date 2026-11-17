# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Hash-chained receipt log — matches src/receipt-log.ts.

Each entry is ``{seq, prev, receipt}`` (0-based ``seq``; ``prev`` is the previous
entry's hash, the genesis anchor for ``seq`` 0). An entry's hash is
``base64url(sha256(utf8(canonical(entry))))``. ``head()`` is the last entry's hash
(or the genesis anchor for an empty log) plus the length, for external anchoring.

``ReceiptLog`` keeps the chain in memory. ``FileReceiptLog`` keeps it in a file in
the reference's format (one canonical-JSON entry per line), with the reference's
``read``/``history``/``head``/``verify_chain``/``verify_all``.
"""
import base64
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone

from .canonical import canonicalize
from .constants import CHAIN_GENESIS_LABEL, DEFAULT_TIMEOUT_ACTOR
from .countersignature import (
    credential_key_material,
    is_valid_credential_descriptor,
    is_webauthn_credential,
    normalize_actor,
    verify_countersignature,
)
from .errors import CountersignError
from .intent import assert_intent_invariants, quorum_of, verify_intent
from .keys import b64url_encode, is_canonical_public_key, utf8
from .resolution import deadline
from .timeutil import parse_iso_ms


def _sha256_b64url(s: str) -> str:
    return b64url_encode(hashlib.sha256(utf8(s)).digest())


#: The chain's genesis ``prev``: a fixed, version-domain-separated anchor.
CHAIN_GENESIS = _sha256_b64url(CHAIN_GENESIS_LABEL)


def entry_hash(entry) -> str:
    """The link hash of one entry: base64url SHA-256 over its canonical JSON."""
    return _sha256_b64url(canonicalize(entry))


class ReceiptLog:
    """An in-memory append-only chained log. Mirrors the reference's chain semantics.
    For a durable log in the reference's file format, use ``FileReceiptLog``."""

    def __init__(self):
        self._entries = []  # list of (entry_dict, hash)

    def append(self, receipt):
        seq = len(self._entries)
        prev = self._entries[-1][1] if self._entries else CHAIN_GENESIS
        entry = {"seq": seq, "prev": prev, "receipt": receipt}
        self._entries.append((entry, entry_hash(entry)))
        return entry

    def head(self):
        """The checkpointable head: ``{"length", "hash"}`` (genesis hash for an empty log)."""
        return {
            "length": len(self._entries),
            "hash": self._entries[-1][1] if self._entries else CHAIN_GENESIS,
        }

    def entries(self):
        return [entry for entry, _ in self._entries]


# --- the file-backed log ------------------------------------------------------
#
# FileReceiptLog is the reference's ReceiptLog (src/receipt-log.ts), line for
# line: the same file, the same chain, the same head, the same audit report.
# A file either side writes, the other reads and verifies.


def _is_number(n) -> bool:
    return isinstance(n, (int, float)) and not isinstance(n, bool)


def _is_bare_receipt(o) -> bool:
    return (
        isinstance(o, dict)
        and isinstance(o.get("decision"), str)
        and isinstance(o.get("signature"), str)
        and isinstance(o.get("intent_id"), str)
    )


def _is_chain_entry(o) -> bool:
    return (
        isinstance(o, dict)
        and _is_number(o.get("seq"))
        and isinstance(o.get("prev"), str)
        and _is_bare_receipt(o.get("receipt"))
    )


def _extract_receipt(o):
    """The portable receipt on a log line (a chained entry, or a legacy bare receipt)."""
    if _is_chain_entry(o):
        return o["receipt"]
    if _is_bare_receipt(o):
        return o
    raise CountersignError("receipt log line is neither a chained entry nor a receipt")


def _reject_constant(name):
    # JavaScript's JSON.parse has no NaN or Infinity; such a line is corrupt there too.
    raise ValueError(f"{name} is not JSON")


def _check_head(expected_head):
    if expected_head is None:
        return None
    if (
        not isinstance(expected_head, dict)
        or not _is_int(expected_head.get("length"))
        or expected_head["length"] < 0
        or not isinstance(expected_head.get("hash"), str)
    ):
        raise CountersignError('expected_head must be {"length": <int >= 0>, "hash": <str>}, as head() returns')
    return expected_head


def _is_int(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool)


def _walk_chain(lines, expected_head=None):
    """Walk the chain; report the first break, or intact. Same report as the reference."""
    prev = CHAIN_GENESIS
    n = len(lines)
    for i, (obj, h) in enumerate(lines):
        if not _is_chain_entry(obj):
            return {"intact": False, "length": n, "brokenAt": i, "reason": "unchained-entry"}
        if obj["seq"] != i:
            return {"intact": False, "length": n, "brokenAt": i, "reason": "bad-seq"}
        if obj["prev"] != prev:
            return {"intact": False, "length": n, "brokenAt": i, "reason": "bad-genesis" if i == 0 else "broken-link"}
        prev = h
    if expected_head is not None:
        want = expected_head["length"]
        if n < want:
            return {"intact": False, "length": n, "brokenAt": n, "reason": "truncated"}
        head_hash = lines[want - 1][1] if want >= 1 else CHAIN_GENESIS
        if head_hash != expected_head["hash"]:
            return {"intact": False, "length": n, "brokenAt": want - 1, "reason": "diverged"}
    return {"intact": True, "length": n}


class FileReceiptLog:
    """
    An append-only, hash-chained log of receipts in a file — the same format as the
    reference's ``ReceiptLog``: one canonical-JSON ``{seq, prev, receipt}`` per line.

    Like the reference it gives two different guarantees. Every receipt's signature
    is checked by ``verify_all`` (authenticity, keyed). The chain only shows the
    sequence is complete relative to a ``head()`` you anchored somewhere the writer
    cannot reach (it is keyless: a writer can rewrite it end to end).

    **Single writer.** Writes from threads of one process are serialised and each
    links onto the last, but nothing coordinates two processes: point separate
    processes at separate files, exactly as with the reference. The head is
    recovered from the file on the first write, so appends continue across
    restarts. Every write is flushed and fsync'd before it returns, and the
    receipts of one resolution go to disk in one write.

    **A torn last line** (a crash in mid-append, or an append still being
    written) is handled as the reference handles it. By default it raises, like
    any corrupt line. With ``repair_torn_tail=True``, reads skip it and
    ``verify_all`` reports it in ``tornTails`` (``ok`` false) WITHOUT changing the
    file: a reader never writes. Only this instance's own appends repair: before
    each append, a torn end is moved into ``<file>.quarantine.jsonl`` and the log
    is cut back to its last whole line (see ``repair()``), so set it on the single
    writer, and on any auditor that should report rather than raise. A whole last
    entry that only lost its newline is kept, and this instance's next append
    writes the newline first (by default too, once the rest of the file reads
    cleanly and that entry is the log's own last chain entry). A corrupt line anywhere else still
    raises.

    The log stores receipts only, never Intents: keep the signed Intents yourself
    and pass them to ``verify_all(intents=...)`` to audit.
    """

    def __init__(self, file_path, *, repair_torn_tail=False):
        self.file_path = os.fspath(file_path)
        #: where torn tails are moved: ``<file>.quarantine.jsonl`` (the reference's name)
        self.quarantine_path = self.file_path + ".quarantine.jsonl"
        self._repairs = bool(repair_torn_tail)
        self._lock = threading.Lock()
        self._head_state = None  # (count, last_hash), recovered lazily

    def repair(self):
        """
        Repair the log now: if its last line is torn (a crash in mid-append), move
        those bytes into ``quarantine_path`` and cut the log back to its last whole
        line. Returns what was moved (``{"line", "offset", "length", "intent_id"}``)
        or None. This WRITES to the log: call it only from the log's single writer,
        never from an auditor (a torn end may be the writer's append still in
        flight). With ``repair_torn_tail=True`` the writer also does this on its own
        before each append. It never touches a bad line in the middle of the file.
        """
        with self._lock:
            torn = _repair_torn_tail(self.file_path, self.quarantine_path)
            self._head_state = None
            return torn

    # -- writing --

    def append(self, receipt) -> None:
        """Append one receipt as one chained entry."""
        self._write([receipt])

    def record(self, resolution) -> None:
        """
        Append every receipt that produced a resolution, contiguously and in order:
        the N approvals of a quorum, the single veto, or the timeout Default.
        Rejections are recorded too.
        """
        receipts = resolution.get("countersignatures") if isinstance(resolution, dict) else None
        if not isinstance(receipts, list):
            raise CountersignError("record() needs a resolution with a countersignatures list")
        if receipts:
            self._write(receipts)

    # -- reading --

    def read(self):
        """Every stored receipt, in write order ([] if the file does not exist yet).
        Raises CountersignError on a corrupt line: audit corruption is never silent."""
        return [_extract_receipt(obj) for obj, _ in self._parse_lines()]

    def history(self):
        """Stored receipts grouped by the Intent they decide, in write order."""
        by_intent = {}
        for cs in self.read():
            by_intent.setdefault(cs["intent_id"], []).append(cs)
        return by_intent

    def head(self):
        """The current chain head ``{"length", "hash"}`` — anchor it outside the box."""
        lines = self._parse_lines()
        return {"length": len(lines), "hash": lines[-1][1] if lines else CHAIN_GENESIS}

    def verify_chain(self, expected_head=None):
        """Walk the ``prev`` links; with ``expected_head`` also catch tail truncation.
        Returns ``{"intact", "length"}`` plus ``"brokenAt"`` and ``"reason"`` on a break."""
        expected_head = _check_head(expected_head)
        return _walk_chain(self._parse_lines(), expected_head)

    def verify_all(
        self,
        trusted_keys=None,
        expected_head=None,
        *,
        intents=None,
        trusted_agent_keys=None,
        authority_key=None,
    ):
        """
        Re-verify the whole log, authenticity and completeness in one pass, exactly as
        the reference's ``verifyAll`` does, and return the same report:
        ``{"total", "valid", "faults": [{"index", "intent_id", "actor", "reason"}],
        "chain", "ok"}``. ``ok`` is true only when no receipt faulted and the chain is
        intact.

        - ``intents``: the signed Intents these receipts decide. Each receipt must
          decide one of them, and is checked against that Intent's approvers. An
          Intent that does not verify is not used (its receipts fault
          ``unverified-intent``).
        - ``authority_key``: the authority public key (or a list, across a rotation).
          Needed to verify vouched approvals and the timeout Default; without it they
          fault ``missing-authority-key``. Only meaningful with ``intents``.
        - ``trusted_agent_keys``: only Intents signed by one of these agent keys count.
        - ``trusted_keys``: with ``intents``, an extra allowlist for keyed approvers'
          keys; without, an allowlist for every receipt's signing key.
        - ``expected_head``: a ``head()`` anchored earlier; catches truncation and
          rewrites at or below it.

        Passkey (WebAuthn) receipts cannot be verified by this client and always
        fault: ``missing-webauthn-policy`` when well formed, ``invalid-signature``
        when not. ``ok`` is then false (fail closed).
        """
        if authority_key is not None and not isinstance(authority_key, (str, list, tuple)):
            raise CountersignError("verifyAll: authorityKey must be a string or an array of strings")
        if trusted_keys is not None and not isinstance(trusted_keys, (str, list, tuple)):
            raise CountersignError("verifyAll: trustedKeys must be a string or an array of strings")
        if trusted_agent_keys is not None and not isinstance(trusted_agent_keys, (list, tuple)):
            raise CountersignError(
                "verifyAll: trustedAgentKeys must be an array of agent public keys "
                "(an empty string does NOT disable the pin)"
            )
        if intents is not None and not isinstance(intents, (list, tuple)):
            raise CountersignError("verifyAll: intents must be an array of Intents")
        if intents is not None and len(intents) == 0:
            raise CountersignError(
                "verifyAll: intents must not be an empty array — omit it to audit without Intent binding, "
                "or supply at least one Intent"
            )
        authority_keys = None
        if authority_key is not None:
            authority_keys = [authority_key] if isinstance(authority_key, str) else list(authority_key)
            if len(authority_keys) == 0:
                raise CountersignError(
                    "verifyAll: authorityKey must not be an empty array — omit it, or supply at least one key"
                )
            if not all(is_canonical_public_key(k) for k in authority_keys):
                raise CountersignError("verifyAll: authorityKey contains a non-canonical ed25519 key")
            if intents is None:
                raise CountersignError(
                    "verifyAll: authorityKey has no effect without `intents` (the authority checks are "
                    "per-Intent) — omit it or supply intents"
                )
        if trusted_agent_keys is not None and len(trusted_agent_keys) == 0:
            raise CountersignError(
                "verifyAll: trustedAgentKeys must not be an empty array — omit it, or supply at least one agent key"
            )
        if trusted_agent_keys is not None and intents is None:
            raise CountersignError(
                "verifyAll: trustedAgentKeys has no effect without `intents` (the agent pin is per-Intent) "
                "— omit it or supply intents"
            )
        trusted_materials = None
        if trusted_keys is not None:
            tk = [trusted_keys] if isinstance(trusted_keys, str) else list(trusted_keys)
            usable = [k for k in tk if isinstance(k, str) and k != ""]
            if not usable:
                raise CountersignError(
                    "verifyAll: trustedKeys must not be empty — omit it, or supply at least one (non-empty) key"
                )
            trusted_materials = {credential_key_material(k) for k in usable}
        expected_head = _check_head(expected_head)

        # Only Intents whose invariants hold, whose agent signature verifies, that the
        # authority did not author, and (if pinned) whose agent is trusted, bind receipts.
        intents_by_id = None
        approvers_by_intent = {}
        unverified_ids = set()
        if intents is not None:
            intents_by_id = {}
            for i in intents:
                try:
                    assert_intent_invariants(i)
                    agent_key = i.get("agent", {}).get("public_key")
                    authentic = (
                        verify_intent(i)
                        and (authority_keys is None or agent_key not in authority_keys)
                        and (trusted_agent_keys is None or agent_key in trusted_agent_keys)
                    )
                except Exception:
                    authentic = False
                if authentic:
                    intents_by_id[i["intent_id"]] = i
                    by_actor = {}
                    for a in i["approvers"]:
                        na = normalize_actor(a["actor"])
                        if na != DEFAULT_TIMEOUT_ACTOR:
                            by_actor[na] = a
                    approvers_by_intent[i["intent_id"]] = by_actor
                elif isinstance(i, dict) and isinstance(i.get("intent_id"), str):
                    unverified_ids.add(i["intent_id"])

        lines, torn_now = self._parse_file()
        chain = _walk_chain(lines, expected_head)
        faults = []
        # Torn tails (read only): the quarantined ones, once each (a repair cut short by a
        # crash may record the same bytes twice), then one still at the end of the file.
        quarantined = _read_quarantine(self.quarantine_path)
        torn = None
        if self._repairs or quarantined or torn_now:
            torn = []
            seen_torn = set()
            for q in quarantined:
                key = (q.get("offset"), q.get("sha256"))
                if key in seen_torn:
                    continue
                seen_torn.add(key)
                intent_id = q.get("intent_id")
                torn.append({"index": q.get("line"), "intent_id": intent_id if isinstance(intent_id, str) else "",
                             "offset": q.get("offset"), "length": q.get("length"), "quarantined": True})
            if torn_now:
                torn.append(dict(index=torn_now["line"], intent_id=torn_now["intent_id"], offset=torn_now["offset"],
                                 length=torn_now["length"], quarantined=False))
        for index, (obj, _) in enumerate(lines):
            try:
                cs = _extract_receipt(obj)
            except CountersignError:
                faults.append({"index": index, "intent_id": "", "actor": "", "reason": "malformed"})
                continue
            reason = self._receipt_fault(
                cs, intents_by_id, approvers_by_intent, unverified_ids, authority_keys, trusted_materials
            )
            if reason:
                fault = {"index": index, "intent_id": cs["intent_id"], "actor": cs.get("actor"), "reason": reason}
                if "actor" not in cs:
                    del fault["actor"]  # the reference's JSON report has no actor key then
                faults.append(fault)
        report = {
            "total": len(lines),
            "valid": len(lines) - len(faults),
            "faults": faults,
            "chain": chain,
            "ok": len(faults) == 0 and chain["intact"],
        }
        # A torn tail is not one of the stored lines: it does not reduce `valid`, but it fails
        # `ok`. The key is there only when the log opted in or something torn exists, as in the
        # reference, so a default report has exactly the reference's 0.2.0 keys.
        if torn is not None:
            report["tornTails"] = torn
            if torn:
                report["ok"] = False
        return report

    # -- internals --

    @staticmethod
    def _receipt_fault(cs, intents_by_id, approvers_by_intent, unverified_ids, authority_keys, trusted_materials):
        public_key = cs.get("public_key")
        # (1) Integrity. This client cannot verify a passkey assertion, so a passkey
        # receipt faults: as the reference reports one checked without an RP policy.
        if is_webauthn_credential(public_key):
            wa = cs.get("webauthn")
            has_block = (
                isinstance(wa, dict)
                and bool(wa)
                and isinstance(wa.get("authenticator_data"), str)
                and isinstance(wa.get("client_data_json"), str)
            )
            if not is_valid_credential_descriptor(public_key) or not has_block:
                return "invalid-signature"
            return "missing-webauthn-policy"
        if not verify_countersignature(cs):
            return "invalid-signature"

        intent = intents_by_id.get(cs["intent_id"]) if intents_by_id is not None else None
        if intents_by_id is not None and intent is None:
            return "unverified-intent" if cs["intent_id"] in unverified_ids else "unknown-intent"
        if intent is not None:
            # (2) Bind the receipt to the Intent's approver.
            cs_actor = normalize_actor(cs.get("actor"))
            approver = approvers_by_intent[intent["intent_id"]].get(cs_actor)
            is_timeout_default = cs.get("policy") == "default" and cs_actor == DEFAULT_TIMEOUT_ACTOR
            reason = None
            if approver is not None and cs.get("policy") != "approver":
                reason = "untrusted-key"  # the Default's label on a person's slot
            elif approver is not None and approver.get("mode") == "keyed":
                if authority_keys is None:
                    reason = "missing-authority-key"
                elif approver.get("public_key") and credential_key_material(approver["public_key"]) in authority_keys:
                    reason = "untrusted-key"  # a keyed slot must be the approver's own key
                elif not verify_countersignature(cs, trusted_keys=approver.get("public_key")):
                    reason = "untrusted-key"
            elif is_timeout_default:
                expected = "reject" if quorum_of(intent) > 1 else intent.get("default")
                ts = parse_iso_ms(cs.get("timestamp"))
                if cs.get("decision") != expected:
                    reason = "untrusted-key"
                elif ts is None or not ts >= deadline(intent):
                    reason = "untrusted-key"  # a Default cannot fire early
                elif authority_keys is None:
                    reason = "missing-authority-key"
                elif not verify_countersignature(cs, trusted_keys=authority_keys):
                    reason = "untrusted-key"
            elif approver is not None:
                if authority_keys is None:
                    reason = "missing-authority-key"
                elif not verify_countersignature(cs, trusted_keys=authority_keys):
                    reason = "untrusted-key"
            else:
                reason = "untrusted-key"  # not an approver of this Intent
            if (
                reason is None
                and approver is not None
                and approver.get("mode") == "keyed"
                and trusted_materials is not None
                and credential_key_material(public_key) not in trusted_materials
            ):
                reason = "untrusted-key"
            return reason
        if trusted_materials is not None and credential_key_material(public_key) not in trusted_materials:
            return "untrusted-key"
        return None

    def _parse_lines(self):
        """Every line as ``(obj, link_hash)``; raises loud on a corrupt line. Never writes."""
        return self._parse_file()[0]

    def _parse_file(self):
        """
        Read and parse the file (READ ONLY): ``(lines, torn)``. Strict unless the log
        opted into ``repair_torn_tail``: then a torn last segment (no newline, does not
        parse) comes back separately as ``torn``, for ``verify_all`` to report.
        """
        try:
            with open(self.file_path, "rb") as fh:
                buf = fh.read()
        except FileNotFoundError:
            return [], None
        torn = None
        if self._repairs:
            raw_lines, torn = _split_torn_tail(buf)
        else:
            raw_lines = buf.decode("utf-8").split("\n")
        out = []
        for i, raw in enumerate(raw_lines):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line, parse_constant=_reject_constant)
                h = entry_hash(obj)
            except (ValueError, TypeError, RecursionError):
                raise CountersignError(f"receipt log {self.file_path} is corrupt at line {i + 1}") from None
            out.append((obj, h))
        return out, torn

    def _ensure_head(self):
        if self._head_state is None:
            lines = self._parse_lines()
            self._head_state = (len(lines), lines[-1][1]) if lines else (0, CHAIN_GENESIS)
        return self._head_state

    def _write(self, receipts) -> None:
        with self._lock:
            parent = os.path.dirname(self.file_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            # Only the writer repairs, and only here, under its lock: if the file does not end
            # on a whole line, move the torn end aside and recover the head before linking on.
            if self._repairs and not _ends_clean(self.file_path):
                _repair_torn_tail(self.file_path, self.quarantine_path)
                self._head_state = None
            count, last_hash = self._ensure_head()
            if not self._repairs:
                # By default too, a last entry that only lost its newline gets it back before
                # the append, so the new entry is not glued onto it. Only after the head was
                # read (an append that fails on damage elsewhere writes nothing, as in 0.2.0),
                # and only when the last segment is this log's own head entry. Nothing is cut
                # or moved; any other last segment is left exactly as it is.
                _complete_last_line(
                    self.file_path,
                    lambda last, before: _is_head_entry(last, before, count, last_hash),
                )
            out = []
            for receipt in receipts:
                line = canonicalize({"seq": count, "prev": last_hash, "receipt": receipt})
                out.append(line + "\n")
                last_hash = _sha256_b64url(line)
                count += 1
            data = "".join(out).encode("utf-8")
            try:
                _durable_append(self.file_path, data)
            except BaseException:
                # The write may have left a partial line. With the repair opted in, forget the
                # head; the next append's check moves torn bytes aside and links onto the rest.
                if self._repairs:
                    self._head_state = None
                raise
            self._head_state = (count, last_hash)


def _durable_append(path, data: bytes) -> None:
    """Append ``data`` in one write on an O_APPEND fd and fsync it; fsync a new file's directory."""
    created = not os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        _fsync_dir(os.path.dirname(path) or ".")


# --- a torn last line: the reference's rule (src/durable-file.ts) ----------------

_INTENT_ID_IN = re.compile(r'"intent_id"\s*:\s*"([0-9a-fA-F-]{36})"')


def _is_whole_object(text: str) -> bool:
    try:
        v = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return False
    return isinstance(v, dict)


def _split_torn_tail(buf: bytes):
    """
    The reference's ``splitTornTail`` (READ ONLY): the file's lines, and separately a
    torn last segment (no newline, not a whole JSON object) described as
    ``_repair_torn_tail`` would describe it, or None.
    """
    cut = buf.rfind(b"\n") + 1  # 0 when there is no newline at all
    tail = buf[cut:].decode("utf-8", errors="replace")
    head = buf[:cut].decode("utf-8")
    if tail.strip() == "" or _is_whole_object(tail):
        return (head + tail).split("\n"), None
    lines = head.split("\n")
    m = _INTENT_ID_IN.search(tail)
    torn = {"line": len([l for l in lines if l.strip() != ""]), "offset": cut, "length": len(buf) - cut,
            "intent_id": m.group(1) if m else ""}
    return lines, torn


def _ends_clean(path) -> bool:
    """True when the file is missing, empty, or ends with a newline (one small read)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                return True
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) == b"\n"
    except FileNotFoundError:
        return True


def _complete_last_line(path, accept) -> bool:
    """
    The reference's ``completeLastLine``: if the file does not end with a newline,
    its last segment parses as a whole JSON object, and ``accept(last, before)``
    says it is the entry the caller expects there (``before`` is the parsed line
    before it, or None), append the newline (fsync'd) and return True. Otherwise
    the file is left exactly as it is (False). Never truncates. For the writer's
    append path only, never a read.
    """
    if _ends_clean(path):
        return False
    with open(path, "rb") as fh:
        buf = fh.read()
    cut = buf.rfind(b"\n")
    tail = buf[cut + 1:].decode("utf-8", errors="replace")
    if tail.strip() == "" or not _is_whole_object(tail):
        return False
    before = None
    if cut >= 0:
        lines = [l for l in buf[:cut].decode("utf-8", errors="replace").split("\n") if l.strip()]
        if lines:
            try:
                before = json.loads(lines[-1], parse_constant=_reject_constant)
            except (ValueError, TypeError, RecursionError):
                return False
    try:
        last = json.loads(tail, parse_constant=_reject_constant)
        if not accept(last, before):
            return False
    except (ValueError, TypeError, RecursionError):
        return False
    _durable_append(path, b"\n")
    return True


def _is_head_entry(last, before, count, last_hash) -> bool:
    """True when ``last`` is the entry the head was taken from: its seq, its hash, its link to ``before``."""
    if count < 1 or not _is_chain_entry(last):
        return False
    if last["seq"] != count - 1 or entry_hash(last) != last_hash:
        return False
    prev = CHAIN_GENESIS if before is None else entry_hash(before)
    return last["prev"] == prev


def _iso_now() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _repair_torn_tail(path, quarantine_path):
    """
    The reference's ``repairTornTail``: a whole last entry that only lost its
    newline gets it back; any other last line with no newline is written, byte for
    byte, to the quarantine file (flushed) and only then cut from the log, so a
    crash between the two leaves the bytes in both places, never in neither.
    Returns what was moved, or None.
    """
    try:
        with open(path, "rb") as fh:
            buf = fh.read()
    except FileNotFoundError:
        return None
    cut = buf.rfind(b"\n") + 1  # 0 when there is no newline at all
    tail = buf[cut:]
    text = tail.decode("utf-8", errors="replace")
    if text.strip() == "":
        return None
    if _is_whole_object(text):
        _durable_append(path, b"\n")
        return None
    head = buf[:cut].decode("utf-8", errors="replace")
    m = _INTENT_ID_IN.search(text)
    torn = {
        "line": len([l for l in head.split("\n") if l.strip() != ""]),
        "offset": cut,
        "length": len(tail),
        "intent_id": m.group(1) if m else "",
    }
    record = dict(
        torn,
        repaired_at=_iso_now(),
        sha256=b64url_encode(hashlib.sha256(tail).digest()),
        bytes_b64=base64.b64encode(tail).decode("ascii"),
    )
    _durable_append(quarantine_path, (canonicalize(record) + "\n").encode("utf-8"))
    fd = os.open(path, os.O_WRONLY)
    try:
        os.ftruncate(fd, cut)
        os.fsync(fd)
    finally:
        os.close(fd)
    return torn


def _read_quarantine(quarantine_path):
    """Every record in a quarantine file ([] if none). Unreadable lines are skipped, as in the reference."""
    try:
        with open(quarantine_path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            text = fh.read()
    except FileNotFoundError:
        return []
    out = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _fsync_dir(path) -> None:
    """Make a new file's directory entry durable too (POSIX; a no-op where unsupported)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
