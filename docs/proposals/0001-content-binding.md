# 0001 · Binding content to an Intent

**Status:** proposal, not applied · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

An Intent says what the agent wants to do with two free strings, `action` and
`summary` (spec §1). Nothing else is signed: the schema sets
`additionalProperties: false` and `createIntent` copies only the named fields,
so an extra key passed in is silently dropped.

Kaviyam asks a person to approve a social post: these exact words and this exact
picture, on LinkedIn. The receipt must cover those bytes, or "approved" means
"approved something about this topic". The picture cannot travel in an Intent at
all. So Kaviyam does this today:

- `action` = `kaviyam.post.linkedin:sha256=<64 hex>`, where the digest covers the
  canonical JSON of the words, the picture's sha256, the place and the mode;
- `summary` = a heading, the check verdict, a picture line, then the **exact
  words**, so the approver reads what is bound;
- at post time it rebuilds the digest from the stored bytes and refuses on any
  mismatch.

The chain of proof is receipt → `intent_id` → agent-signed Intent → digest inside
`action` → stored bytes. It works, but every verifier must know Kaviyam's private
convention to find the digest, and nothing tells a generic tool that the action
string is carrying one.

## Options

1. **Document the convention, change nothing.** Add non-normative guidance: when
   an approval is about specific content, put `<name>:sha256=<hex>` at the end of
   `action`, define what the digest covers in your own documentation, and show the
   content (or the part a person decides on) in `summary`.
2. **An optional signed digest field.** For example
   `content: { alg: "sha256", digest: "<base64url>", media_type?: string }` or a
   list of them, signed with the rest of the envelope. Verifiers that understand it
   can check stored content; verifiers that do not still verify the signature.
3. **Inline payload.** Carry the content itself. Rejected: Intents travel through
   chat and email, pictures do not fit, and the approver still decides on
   `summary`.

## Recommendation

Do option 1 now as a short note in the spec's guidance and the README, because it
needs no version bump and is what deployments already do. Plan option 2 for the
next minor version, as an **optional** field, with the rule that `summary` stays
the human-readable truth: a digest binds bytes, it does not tell a person what
they approved.

## Wire and vectors

- Option 1: no wire change, no vector change.
- Option 2: a new optional field in `schemas/intent.schema.json`, a new
  `countersign` minor (`"0.3"`), because a v0.2 verifier with
  `additionalProperties: false` must reject an Intent that carries it. New vectors:
  an Intent with `content`, the same Intent with a tampered digest (must fail
  `verifyIntent`), and a canonical-JSON case for the field.

## What integrators can do today

Use the `action` convention above, keep the hashed bytes next to the stored
Intent, and re-hash before acting. Keep `summary` truthful and readable on the
surface where the person presses Approve (see proposal 0007 for message limits).
