# Countersign — an open protocol for agent-to-human authorization

**Version:** 0.1 (draft)
**Author:** Haridarman K (Agents Stack)
**License:** This specification text is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Reference code is licensed separately under Apache-2.0.

## Abstract

An agent signs its intent; a human countersigns it into authority.

MCP connects agents to tools. A2A connects agents to each other. Neither says
what happens when an agent needs a human's yes. Countersign fills that leg
with exactly four nouns: an **Intent** (what the agent wants to do), a
**Route** (how the question reaches a human), a **Countersignature** (the
signed, portable receipt of the decision), and a **Default** (what silence
means). Nothing else is specified on purpose.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in RFC 2119.

## 1. Intent

An Intent is a signed JSON envelope stating what an agent wants to do, who
may authorize it, and what happens if nobody answers.

| Field        | Type            | Meaning |
| ------------ | --------------- | ------- |
| `countersign`| string          | Protocol version. MUST be `"0.1"`. |
| `intent_id`  | string (UUID)   | Unique id of this intent. MUST NOT be reused. |
| `agent`      | object          | `{ id, public_key }` — identity string and base64url raw ed25519 public key of the requesting agent. |
| `action`     | string          | Machine-oriented action name (e.g. `billing.refund`). |
| `summary`    | string          | Human-oriented one-liner. This is what the approver decides on; it MUST be truthful about `action`. |
| `risk_tier`  | enum            | `low` \| `medium` \| `high` \| `critical`. |
| `approvers`  | string[]        | Who may countersign, as `channel:address` strings (e.g. `telegram:8675309`, `email:ops@example.com`). MUST be non-empty. |
| `timeout`    | integer         | Seconds after `created_at` at which the Default fires. MUST be ≥ 1. |
| `default`    | enum            | `approve` \| `reject` — the decision that fires at the deadline. |
| `callback`   | string \| null  | Optional URL the Countersignature is POSTed to. |
| `created_at` | string          | ISO 8601 timestamp. |
| `signature`  | string          | base64url ed25519 signature by `agent.public_key`. |

**Signing.** The signature is computed over the bytes
`context || 0x0A || canonical`, where `canonical` is the canonical JSON of the
envelope with the `signature` field absent and `context` is a
domain-separation label unique to the artifact type
(`countersign-intent-v0.1` for an Intent). Canonical JSON means: object keys
sorted lexicographically at every depth, no insignificant whitespace, UTF-8
encoding. Domain separation MUST be used so a signature minted for one
artifact type (Intent, Countersignature, or an email decision link) can never
be replayed as another. Producers and verifiers MUST use this
canonicalization; verifiers MUST reject an Intent whose signature does not
verify, and SHOULD reject before signing/verifying any envelope nested beyond
a small fixed depth.

An Intent asks; it never authorizes. Holding a signed Intent grants no
authority to act.

## 2. Route

A Route delivers an Intent to where its approvers actually live — Telegram,
Discord, Slack, WhatsApp, email — and carries the decision back. Routes are
implemented by **adapters**, which are intentionally dumb: deliver the
envelope, report the decision. Policy, timeout handling, and enforcement
stay with the requesting runtime.

- Adapters MUST be pluggable behind one interface: `deliver(intent)` plus a
  decision callback that yields a Countersignature.
- Delivery SHOULD be push (webhook) where the channel supports it; an
  adapter MAY fall back to polling where it does not (e.g. long-polling a
  bot API). Push and poll are equivalent transports for the same Route.
- An adapter MUST NOT alter, summarize, or re-sign the Intent. What the
  approver sees is derived from the signed envelope.

Adapters use one of two interaction patterns, and MUST use one of these two:

1. **Button-webhook** (chat platforms). The Intent is rendered as a message
   with Approve/Reject buttons; the platform delivers the button press to
   the adapter's webhook (or polling loop), which signs the
   Countersignature.
2. **Signed link-callback** (email and similar). The Intent is rendered with
   Approve/Reject hyperlinks. Each link token MUST be signed, MUST be
   single-use, and MUST expire exactly when the Intent's timeout fires.
   Following a link MUST NOT decide anything: the GET serves a confirmation
   page, and the decision executes only on an explicit confirmation (a POST
   from that page). This keeps mail-scanner prefetch from approving
   anything.

A Countersignature MUST be identical in shape and equally verifiable
regardless of which interaction pattern produced it. Consumers of receipts
MUST NOT be able to tell — and MUST NOT need to know — whether an approval
came from a chat button or an email link.

## 3. Countersignature

A Countersignature is the signed receipt of a decision. It is the only
artifact in the protocol that conveys authority.

| Field        | Type          | Meaning |
| ------------ | ------------- | ------- |
| `countersign`| string        | MUST be `"0.1"`. |
| `intent_id`  | string (UUID) | The Intent being decided. |
| `decision`   | enum          | `approve` \| `reject`. |
| `actor`      | string        | Who decided, as `channel:address` (e.g. `slack:U024BE7LH`); `default:timeout` when the Default fired. |
| `policy`     | enum          | `approver` for an explicit human decision; `default` when the Default fired. |
| `timestamp`  | string        | ISO 8601 time of decision. |
| `public_key` | string        | base64url raw ed25519 public key of the signing authority. |
| `signature`  | string        | base64url ed25519 signature over the canonical receipt (without this field). |

Signing and canonicalization are as in §1 (the Countersignature context is
`countersign-countersignature-v0.1`). A Countersignature MUST be
**portable**: any party holding only the receipt (and, to bind it, the
Intent with the matching `intent_id`) can verify it offline. Verifiers MUST
check: (1) the signature verifies against the embedded `public_key`, (2) the
`intent_id` matches the Intent in question, and (3) the `public_key` is an
authority they trust for that Route. Trust distribution for authority keys
is deployment policy and out of scope for this version.

**Integrity is not authority.** Check (1) alone only proves the receipt is
self-consistent — anyone can mint a receipt that passes (1) with their own
key. A party MUST NOT act on a receipt on the strength of (1) without also
performing check (3) against a trusted-key set. In particular, the runtime
enforcing an Intent MUST verify that the decision it receives was signed by
the authority key it trusts for the Route, not merely that the receipt
verifies against its own embedded key.

A runtime MUST NOT execute the guarded action unless it holds a verifying
Countersignature with `decision: "approve"` for that exact `intent_id`. One
Intent yields at most one Countersignature; later decisions on the same
`intent_id` MUST be ignored.

## 4. Default

Silence is never ambiguous. Every Intent declares its `default` and
`timeout`; together they define the deadline `created_at + timeout` at which
the Default fires.

- If no Countersignature has been produced by the deadline, the enforcing
  runtime MUST resolve the Intent to its declared `default`, and SHOULD
  record that resolution as a Countersignature with
  `actor: "default:timeout"` and `policy: "default"`, signed by its own
  authority key. Timeout receipts verify exactly like human ones.
- A human decision arriving before the deadline wins; one arriving after
  the deadline MUST be ignored (the Default already decided).
- `default: "approve"` is legitimate for low-risk actions but SHOULD be
  paired with a short timeout; `risk_tier: "critical"` Intents SHOULD
  declare `default: "reject"`.

## 5. Security considerations

- **Verify before acting.** The Countersignature signature check is not
  optional; an unverifiable receipt is not a decision (§3). And integrity is
  not authority: the acting party MUST also bind the receipt to a trusted
  authority key (§3), never act on self-consistency alone.
- **Domain separation.** Every signature commits to an artifact-type context
  (§1), so a signature is only ever valid for the artifact it was minted for.
- **Replay.** `intent_id` uniqueness plus single-decision semantics (§3)
  make receipts non-replayable across intents. Verifiers SHOULD also check
  `timestamp` falls within the Intent's validity window.
- **Link safety.** The link-callback pattern's single-use, signed-expiry,
  GET-never-decides rules (§2) are load-bearing; implementations MUST NOT
  relax them.
- **Transport auth.** Adapters SHOULD verify their platform's webhook
  authentication (e.g. Slack request signatures, Discord interaction
  signatures, Meta hub signatures) before trusting any callback.
- **Key custody.** Agent keys and authority keys are distinct roles and
  SHOULD be distinct keys; compromise of an agent key forges requests,
  compromise of an authority key forges authority.

## 6. Versioning

This is version 0.1, a draft for implementation feedback. The `countersign`
field pins the version in every envelope and receipt. Breaking changes bump
the minor version until 1.0. Anything not specified here — approver
directories, multi-approver quorums, delegation chains, revocation — is
deliberately left to implementations for now.

---

*Countersign is spec plus reference implementation, not a framework. If you
can render a message and receive a button press, you can implement a Route.*
