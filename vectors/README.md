# counter-sign conformance test vectors

`countersign-vectors.json` is a **language-neutral, deterministic** fixture set that any
independent counter-sign implementation can check itself against. If your implementation
reproduces these bytes and reaches these verdicts, its signatures interoperate with the
reference implementation — a receipt it produces verifies here, and vice versa.

The reference implementation is re-checked against this exact file by
[`tests/conformance.test.ts`](../tests/conformance.test.ts) on every `npm test`.

> ⚠️ **Test keys only.** The keys below are derived from low-entropy, public seeds and are
> labelled as such. Never use them for anything real.

## Regenerating (they are frozen, not incidental)

```sh
npm run gen:vectors      # rewrites countersign-vectors.json from the reference impl
```

The generator ([`scripts/gen-vectors.ts`](../scripts/gen-vectors.ts)) is fully deterministic —
fixed seeds, fixed ids, fixed timestamps, and ed25519 is deterministic (RFC 8032), so re-running
produces byte-identical output. Because the vectors are committed and the conformance suite reads
the committed file, a change to canonicalization or signing surfaces as a failing test **plus** a
reviewable diff to this file, instead of a silent wire-format drift.

## The algorithm (what an implementation must reproduce)

Everything counter-sign signs is built the same way. The `algorithm` block in the JSON restates
this for machines; here it is for humans.

| Concern | Rule |
| --- | --- |
| **Keys** | ed25519. Encoded as **base64url of the raw 32-byte value** — a 32-byte seed for a secret, the 32-byte public key for a public key. No padding. |
| **Canonical JSON** | Object keys **sorted lexicographically at every depth** (by UTF-16 code unit); no insignificant whitespace; UTF-8 bytes; `undefined` members omitted; non-finite numbers rejected. Both sides MUST produce byte-identical output for the same value. |
| **Signed bytes** | `utf8( context + "\n" + canonical )` — a domain-separation **context** label, a single `0x0A`, then the canonical JSON of the *unsigned* object. The ed25519 signature is over exactly these bytes; the `signature` field itself is excluded from `canonical`. |
| **Contexts** | Intent → `countersign-intent-v0.2`; Countersignature → `countersign-countersignature-v0.2`; link/token → `countersign-link-v0.2`. |
| **Receipt chain** | Genesis `prev` = `base64url(sha256(utf8("countersign-receipt-chain-v0.1")))`. Each entry is `{ seq, prev, receipt }` (0-based `seq`; `prev` is the previous entry's hash, genesis for `seq` 0). Entry hash = `base64url(sha256(utf8(canonical(entry))))`. Head hash = the last entry's hash (or genesis for an empty log). |

## Sections

| Section | What it fixes | How to check |
| --- | --- | --- |
| `keys` | `{ name, secret, public }` | `public == derive_public(secret)` |
| `canonical` | `{ name, value, canonical }` | `canonical_json(value) == canonical` (the interop-critical one) |
| `signing` | `{ secret_key, public_key, context, canonical, message_base64url, signature }` | reproduce `message_base64url`, then the `signature`, then verify it |
| `intents` | a signed `Intent`, its `canonical_unsigned`, and whether it should verify | `canonical_json(intent − signature) == canonical_unsigned`; `verify_intent(intent) == valid` |
| `countersignatures` | a `receipt`, its `signer_public_key`, and `valid` | `verify_countersignature(receipt, trustedKeys=[signer_public_key]) == valid` (the `forged-wrong-key` case must be **rejected**) |
| `resolutions` | `{ intent, resolution, expected_authority_public_key, expect }` | `verify_resolution(...)` succeeds iff `expect == "valid"` (covers under-quorum, forged quorum, and wrong-authority-key negatives) |
| `chain` | receipts to append in order + `expected_head` | append to a fresh chained log; `head() == expected_head` |

## Writing a runner in another language

1. Load `countersign-vectors.json`.
2. Implement the four primitives from the table above: `derive_public`, `canonical_json`,
   `sign(secret, context, canonical)`, `verify(public, context, canonical, signature)`.
3. Walk each section and assert as in the table. Start with `canonical` — it is where
   independent implementations most often diverge (key ordering, Unicode, number formatting).
4. The **negatives matter most**: a conforming verifier MUST reject `intents.tampered-summary`,
   `countersignatures.forged-wrong-key`, and every `resolutions` case marked `"invalid"`.

## Scope

v0.2 vectors cover the deterministic, interop-critical surface: canonical JSON, ed25519 key
derivation and signing, Intent/Countersignature signing + verification, `verifyResolution`
accept/reject, and the receipt-log hash chain. **Passkey / WebAuthn receipts are not yet vectored**
— P-256 WebAuthn assertions are non-deterministic, so they need captured verify-only fixtures; that
is planned. The raw-ed25519 keyed path here **is** the base signer the passkey path is layered on.
