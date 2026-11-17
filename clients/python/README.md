# counter-sign — Python client

A Python port of the [counter-sign](https://countersignlabs.com) protocol core:
canonical JSON, ed25519 domain-separated signing, **Intent** and
**Countersignature** build/verify, quorum **resolution**, and the hash-chained
**receipt log**.

It is verified **byte-for-byte** against the reference implementation's committed,
language-neutral conformance vectors (`../../vectors/countersign-vectors.json`) —
so a receipt this client produces verifies in the TypeScript reference, and vice
versa. This is a second, independent implementation of the protocol; passing the
vectors is what proves interoperability.

> **Status.** The raw-ed25519 **keyed** and **vouched** paths are complete:
> create and verify Intents, sign and verify decisions, verify resolutions, and
> keep a file-backed receipt log the TypeScript reference can read. Passkey /
> **WebAuthn** receipt verification is a planned follow-up and currently fails
> closed (returns `False`), matching the reference verifier's behavior with no RP
> policy. See [What this client does not do](#what-this-client-does-not-do).

## Install

```sh
pip install cryptography   # the only runtime dependency
# then vendor this package, or (once published) `pip install countersign`
```

## Create an Intent

```python
from countersign import create_intent, CountersignError

intent = create_intent(
    {
        "action": "billing.refund",
        "summary": "Refund $42.00 to customer 8675309",
        "risk_tier": "high",                 # low | medium | high | critical
        "approvers": ["tg:8675309"],         # a bare string is a vouched approver
        "timeout": 300,                      # seconds until the Default fires
        "default": "reject",                 # what silence means
    },
    AGENT_SECRET_KEY,                        # base64url ed25519 seed; never the authority key
    agent_id="agent:billing",
)
# -> a signed Intent dict, ready to send to a Route as JSON
```

It applies every rule the reference's `createIntent` applies, and refuses with
`CountersignError` where the reference would: a keyed approver needs its own
canonical key (or a well-formed passkey descriptor) and no two keyed approvers
may share one; `quorum` greater than 1 needs every approver keyed and
`default: "reject"`, and can never exceed the number of approvers;
`default:timeout` is reserved; the same actor may not be listed twice (after
case and Unicode folding); `timeout` is a whole number of seconds from 1 to
2147483. Keys other than the Intent's fields are ignored, as in the reference;
only the protocol's fields are signed.

`intent_id` defaults to a fresh random UUID and `created_at` to now. You may pass
either (`intent_id="..."`, `created_at="2026-01-01T00:00:00.000Z"` or an aware
`datetime`), for example to store the id before you send the Intent. A supplied
id must be a lowercase UUID (chat button payloads accept only that form) and
must never be reused: a fresh id per Intent is the replay defence. With the same
id and time, the output is byte-identical to the reference's.

## Verify a decision before acting

```python
from countersign import verify_resolution, InvalidCountersignatureError

# `intent`, `resolution`, and the authority key you trust for this Route
# (all plain dicts / strings, e.g. loaded from JSON your service received).
try:
    verify_resolution(intent, resolution, expected_authority_public_key=AUTH_PUBLIC_KEY)
    run_the_action()          # authorized: quorum met (or the signed Default fired)
except InvalidCountersignatureError as e:
    refuse(e)                 # fail closed — never act on an unverified resolution
```

`verify_resolution` raises on *any* violation: a bad agent signature, a receipt
not signed by the key its approver's mode requires, fewer than `quorum` distinct
approvers, an authority-authored Intent, or a timeout Default that fires early. A
single approver's `reject` is a complete veto.

## Keep a receipt log

`FileReceiptLog` is the reference's `ReceiptLog` in Python: the same file (one
canonical-JSON `{seq, prev, receipt}` per line), the same hash chain and the same
head, so either side can write a log the other verifies.

```python
from countersign import FileReceiptLog

log = FileReceiptLog("/var/lib/myapp/receipts.jsonl")
log.record(resolution)              # every receipt of the resolution, in order, in one write
log.append(receipt)                 # or one receipt

anchor = log.head()                 # {"length": N, "hash": ...}: copy it somewhere the writer can't reach
log.history()                       # {intent_id: [receipts...]}, in write order

report = log.verify_all(
    intents=stored_intents,         # the signed Intents, which you keep: the log holds receipts only
    authority_key=AUTH_PUBLIC_KEY,  # or a list, across a key rotation
    trusted_agent_keys=[AGENT_PUBLIC_KEY],
    expected_head=anchor,           # catches truncation and rewrites at or below the anchor
)
report["ok"]                        # True only if every receipt verified and the chain is intact
report["faults"]                    # [{"index", "intent_id", "actor", "reason"}], as in the reference
```

Every write is fsync'd before it returns. A corrupt line makes `read`, `head`,
`history` and further appends raise `CountersignError`; audit damage is never
silent. `verify_all` reports a malformed line as a fault instead of raising.

The one exception is the last line, which a crash in mid-append can leave cut
short. As in the reference, nothing changes unless you opt in: by default a torn
last line raises like any corrupt line. With
`FileReceiptLog(path, repair_torn_tail=True)`, reads skip it and `verify_all`
lists it in the report's `tornTails` (and `ok` is false) without changing the
file, so an auditor can read while the writer appends. Only the instance that
appends repairs: before its next append it moves those bytes into
`<file>.quarantine.jsonl` (`log.quarantine_path`) and cuts the log back to its
last whole line. Each `tornTails` entry says whether it is `quarantined`; it
stays listed until you review and archive the quarantine file. A whole last
entry that only lost its newline is kept, and the next append writes the
newline first (by default too, so the new entry is never glued onto it; by
default only when the rest of the file reads cleanly and that entry is the
log's own last chain entry, so a failing append writes nothing).
`log.repair()` does the same on demand; call it only from the writer.

The chain is keyless: on its own it catches accidents and careless edits, not a
writer who rewrites the whole file. Tamper evidence comes from checking against a
`head()` you anchored elsewhere.

**One writer per file.** Threads in one process are serialised, but nothing
coordinates two processes (the same rule as the reference). Point separate
processes at separate files.

The in-memory `ReceiptLog` is still there for tests and for checking entries you
received.

## Lower-level pieces

```python
from countersign import (
    canonicalize, public_key_from_secret, sign_context, verify_context,
    verify_intent, verify_countersignature, sign_decision, ReceiptLog,
)

verify_intent(intent)                                   # agent authored the bytes?
verify_countersignature(receipt, trusted_keys=[KEY])    # signed by a key you trust?

log = ReceiptLog()
for receipt in receipts:
    log.append(receipt)
log.head()                     # {"length": N, "hash": ...} — anchor this externally
```

## What this client does not do

- **Passkey (WebAuthn) receipts are not verified.** `verify_countersignature` and
  `verify_resolution` return `False` / raise on them, and `verify_all` faults them
  (`missing-webauthn-policy`, or `invalid-signature` when malformed). A deployment
  that uses passkey approvers must verify those receipts with the reference.
- **No timeout Default.** There is no `default_resolution` or
  `await_with_default`: this client cannot mint the signed Default when an Intent
  times out. It verifies one minted by the reference.
- **No adapters and no Route.** Delivering an Intent to Slack, Telegram, WhatsApp,
  email or a signing link, and collecting the decision, is the reference's job.
- **No approver registry or policy log.** `ApproverRegistry` and `PolicyLog` are not
  ported.
- **No cross-process locking on the receipt log.** One writer per file, as above.

## Run the tests

```sh
pip install cryptography pytest
pytest -q          # from this directory
```

Every deterministic vector section (keys, canonical JSON, signing,
Intent/Countersignature, resolution accept + reject, receipt-log chain) must pass;
the WebAuthn section is skipped pending passkey support.

The interop tests also run the TypeScript reference (through `tsx`, from the
repository's `node_modules`) and check that both sides make the same Intents and
read and verify each other's receipt logs. They are skipped, with the reason,
when Node or `npm install` is missing.

## License

Apache-2.0 · © 2026 Haridarman Kumaresan
