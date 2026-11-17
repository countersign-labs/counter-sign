# 0004 · A signed, self-anchoring receipt chain

**Status:** proposal, not applied (already on the roadmap, spec §6) · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

`ReceiptLog` is an append-only JSONL file of `{seq, prev, receipt}` entries, where
`prev` is a plain SHA-256 of the previous entry's canonical line and the genesis is
`sha256("countersign-receipt-chain-v0.1")`. The chain is keyless: anyone who can
rewrite the file can recompute every hash, so tamper evidence comes only from a
`head()` copied somewhere the writer cannot reach and checked with
`verifyAll({ expectedHead })`.

Kaviyam runs one approvals router per workspace. To make the log mean anything it
has to build an anchoring job: a root-owned timer that verifies the log hourly,
appends `{at, length, hash}` to an append-only file, and once a week sends the head
to the owner's chat so a copy lives off the box. Every deployment will need a
version of that, and between anchors a rewrite is still undetectable.

## What the head signature should cover, and who signs

- **Signer: a dedicated log key**, distinct from the agent key and the org-root
  key. It may be the authority key in a single-process deployment, but should not
  have to be: the authority key mints vouched receipts and Defaults, and the log
  key's job is only to say "this was my log at this length". Keeping them distinct
  means a leaked log key cannot mint a decision.
- **Signed bytes:** under a new context `countersign-receipt-head-v0.3`, the
  canonical JSON of `{ log_id, length, hash, prev_head_signature_hash?, at }`, where
  `hash` is today's entry hash of the last entry and `log_id` names the log so a
  head cannot be replayed onto another log.
- **When:** one signed head per append (or per batch written in one call), written
  as its own line type or a sidecar file. The entry format is unchanged, so today's
  `verifyChain` still works.
- **What it gives:** a verifier with the log public key can detect any rewrite of
  history it has a signed head for, without trusting the file's writer. It does
  **not** stop truncation back to an older signed head, or a log-key holder from
  re-signing a rewritten log; for those an external anchor is still needed, but much
  less often (a rare copy of the latest signed head, not a constant watch).

## Options

1. Signed head per append (above).
2. Signed head per checkpoint (every N entries or T seconds): cheaper, weaker
   between checkpoints.
3. Keep keyless, and document anchoring recipes only.

## Recommendation

Option 1 with option 2 as a setting, using the dedicated log key. Ship it as an
opt-in `ReceiptLog` mode so existing logs keep verifying.

## Wire and vectors

The receipt itself does not change. The log format gains a head record and a new
signing context, so the `chain` vectors gain cases: a signed head over the existing
three-entry chain, a head signed by the wrong key (must fail), and a head whose
`length` does not match (must fail). The existing `chain` vector stays as it is.

## What integrators can do today

Anchor `head()` off-box on a schedule, and run `verifyAll({ intents, authorityKey,
expectedHead })` against the last anchor. Store the Intents too, since vouched
receipts cannot be audited without them.
