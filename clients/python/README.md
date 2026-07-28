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

> **Status.** The raw-ed25519 **keyed** and **vouched** paths are complete.
> Passkey / **WebAuthn** receipt verification is a planned follow-up and currently
> fails closed (returns `False`), matching the reference verifier's behavior with
> no RP policy.

## Install

```sh
pip install cryptography   # the only runtime dependency
# then vendor this package, or (once published) `pip install countersign`
```

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

## Run the conformance test

```sh
pip install cryptography pytest
pytest -q          # from this directory
```

Every deterministic vector section (keys, canonical JSON, signing,
Intent/Countersignature, resolution accept + reject, receipt-log chain) must pass;
the WebAuthn section is skipped pending passkey support.

## License

Apache-2.0 · © 2026 Haridarman Kumaresan
