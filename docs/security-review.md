# counter-sign security review — v0.1

Adversarial review of the protocol and reference implementation, with fixes
applied in the same pass. Scope: the crypto core, the shim, all five
adapters, and the email link-callback flow. Method: manual code audit plus
regression tests (`tests/security.test.ts`) that encode each finding.

Severity: **High** = authority/authorization bypass; **Medium** = spoofing /
notification abuse gated by a secret; **Low** = defense-in-depth / DoS
hardening.

## Findings and fixes

### CS-01 · Integrity was treated as authority (High) — FIXED
`verifyCountersignature(cs)` verified a receipt against its *own embedded*
public key, so an attacker could mint a self-signed `approve` that returned
`true`. `awaitWithDefault` — the runtime choke point — used exactly that
check, so a rogue or misconfigured adapter's self-signed decision would be
accepted as authority.

**Fix.** `verifyCountersignature(cs, { trustedKeys })` now optionally requires
the signer to be in a trusted set. `awaitWithDefault` binds every decision to
the public key derived from the authority secret it was given, and throws
`InvalidCountersignatureError` otherwise. The spec (§3, §5) now states
"integrity is not authority" normatively; the README shows the trusted-key
pattern. Consequence: the decision adapter and the runtime MUST share one
authority key (`COUNTERSIGN_AUTHORITY_KEY`); the email example was updated to
thread a single key to both.
Tests: `authority binding — integrity is not authority`.

### CS-02 · No signature domain separation (Low, defense-in-depth) — FIXED
Intent, Countersignature, and email-link signatures were all raw
`ed25519(canonical)`. Distinct field shapes made cross-type reuse
non-exploitable in practice, but nothing *prevented* it.

**Fix.** All signatures now commit to an artifact-type context
(`countersign-intent-v0.1`, `countersign-countersignature-v0.1`,
`countersign-link-v0.1`) via `signContext`/`verifyContext`, signing
`context || 0x0A || canonical`. Spec §1 updated.
Tests: `signature domain separation`.

### CS-03 · Discord mention injection (Medium) — FIXED
`deliver()` posted the intent summary as message `content` with no
`allowed_mentions`, so a crafted `summary`/`action` containing `@everyone`,
`@here`, or `<@&role>` would ping the server (notification abuse / phishing
amplification).

**Fix.** `allowed_mentions: { parse: [] }` on every Discord message.
Test: `Discord disables all mentions`.

### CS-04 · Slack mrkdwn / broadcast injection (Medium) — FIXED
The summary was wrapped in a ``` fence inside an `mrkdwn` block, and echoed
raw into the fallback `text`. A `summary` containing ``` broke out of the
fence, and `<!channel>`/`<!here>` in the fallback text broadcast to the
channel.

**Fix.** The section renders the summary as `plain_text` (which never parses
mrkdwn or broadcast mentions), and the fallback `text` is escaped
(`&`,`<`,`>`). Test: `Slack renders the summary as plain_text and escapes`.

### CS-05 · Unauthenticated webhooks accepted silently (Medium) — MITIGATED
Telegram (webhook mode) and WhatsApp accept callbacks without verifying the
platform secret when none is configured. Forgery still requires knowing the
target `intent_id` (an unguessable v4 UUID), which is the second factor — but
IDs travel in cleartext messages, so this is a real weakness if the operator
skips the secret.

**Fix.** Both adapters now emit a one-time `warnOnce` security warning when a
webhook runs without verification configured, naming the env var to set
(`TELEGRAM_WEBHOOK_SECRET` / `WHATSAPP_APP_SECRET`). Slack and Discord already
*require* their secrets and verify every request (confirmed by the
`webhook authentication is enforced` conformance tests). Telegram's default
mode is long-poll, which needs no inbound auth at all.

### CS-06 · Verifier DoS via deep nesting (Low) — FIXED
`canonicalize` recursed without bound; a hostile deeply-nested object handed
to a verifier could blow the stack. Verifiers also threw on malformed input
instead of returning a clean `false`.

**Fix.** `canonicalize` caps depth at 64 (`RangeError` beyond). `verifyIntent`
and `verifyCountersignature` are now total functions — any thrown error
becomes `false`. Tests: `verifiers are total`.

### CS-07 · Oversized timeout could fire the Default early (Low) — FIXED
`timeout` had no upper bound. A value whose millisecond form exceeds Node's
`setTimeout` 32-bit range is clamped and fires *immediately* — a silent
early-approve if `default: "approve"`.

**Fix.** `createIntent` bounds `timeout` to `[1, 2147483]` seconds (the
largest value whose ms form the timer won't clamp); the JSON Schema carries
the same `maximum`. Tests: `timeout is bounded`.

## Verified already-safe (no change needed)

- **Slack request signatures** — HMAC-SHA256 over `v0:ts:body`, `timingSafeEqual`,
  length check first, ±300s timestamp tolerance. Correct.
- **Discord interaction signatures** — ed25519 over `timestamp || body`,
  rejected when absent/invalid. Correct.
- **WhatsApp `X-Hub-Signature-256`** — HMAC-SHA256, `timingSafeEqual`. Correct
  when `WHATSAPP_APP_SECRET` is set (see CS-05).
- **Email link-callback** — tokens are ed25519-signed, single-use, expire at
  exactly the Intent deadline, and a GET only renders a confirm page (decision
  runs only on the POST) — mail-scanner prefetch cannot approve. Bound to the
  adapter's own authority public key. Extensively tested in
  `tests/email-links.test.ts`.
- **`intent_id` as a capability** — v4 UUID from `crypto.randomUUID` (122 bits);
  callbacks are ignored unless the id matches a pending intent.
- **Prototype pollution** — `additionalProperties: false` schemas reject stray
  keys; object spread copies own `__proto__` as a data property (no pollution);
  canonicalization does not walk the prototype chain.
- **Fail-closed** — an adapter error, an unverifiable receipt, or an
  authority-mismatch all propagate as a throw; the guarded action never runs.

## Residual limitations (documented, not code-fixable in 0.1)

- **Authority-key trust distribution** is still deployment policy: the library
  checks a receipt against keys *you* supply, but does not distribute or pin
  them. This is the item most in need of a 0.2 spec section.
- **`approvers` is declarative**, not enforced against the actor who pressed
  the button; enforcement is left to the runtime at verify time.
- **Bearer-link semantics** for email: possession of a signed link token is
  authority. A CSRF nonce on the confirm page would harden the (narrow) case
  of an enterprise scanner that auto-submits forms; possession is still required.
- **In-memory single-decision / pending state** does not survive a restart and
  is not shared across instances; a distributed deployment needs shared state.

---

# v0.1.2 — pre-public adversarial stress test

Before making the repository public, the protocol and reference implementation
were put through a five-front adversarial red-team (crypto core, authorization
logic, adapters/transport, ReceiptLog integrity, DoS/fail-open), and every
serious finding was reproduced with a runnable proof-of-concept before being
accepted. All confirmed findings below are fixed, each with a regression test in
`tests/security-hardening.test.ts` (or `tests/quorum.test.ts`) that encodes the
exploit. The cryptographic primitives (ed25519, domain separation, canonical
signing, fail-closed verifiers, no prototype pollution / ReDoS) were probed hard
and held.

## Fixed

### CS-08 · `verifyResolution` quorum bypass via `resolution.policy` (BLOCKER) — FIXED
The quorum re-derivation was gated on `resolution.policy === "approver"`, an
attacker-controlled field. A resolution `{decision:"approve", policy:"default"}`
carrying a single authority-signed receipt — including the public timeout-reject
receipt — was accepted for any `quorum: N` Intent, executing the guarded action
with zero human approvals (confirmed end-to-end: a 3-of-3 prod deploy ran).
**Fix.** Quorum enforcement no longer branches on `policy` to decide *whether* to
run — only *which* proof is required. Every `approve` requires either `quorum`
distinct approvers (`policy:"approver"`) or the narrow single timeout Default
(quorum-1 + `default:"approve"`, exactly one `default:timeout` receipt); any
other policy is rejected, and every receipt's own `decision` must match the
resolution's.

### CS-09 · Enforcement path trusted unvalidated Intents (High) — FIXED
`awaitWithDefault`/`verifyResolution` never re-validated a received Intent, and
`quorumOf` silently downgraded a malformed quorum (`"3"`, `2.5`, `0`) to `1`; a
`NaN`/huge `created_at`/`timeout` collapsed the veto window (`setTimeout(NaN)`
fires immediately → instant Default). **Fix.** `assertIntentInvariants` +
`verifyIntent` run at the enforcement boundary (fail closed); `quorumOf` throws
on a malformed quorum instead of downgrading.

### CS-10 · WhatsApp / Telegram webhooks fail-open (High) — FIXED
Both skipped signature/secret verification when the (documented-as-optional)
secret was unset, so a network attacker who learned an `intent_id` forged an
approval. **Fix.** `WHATSAPP_APP_SECRET` is required; `TelegramAdapter.webhookHandler()`
refuses to run without `TELEGRAM_WEBHOOK_SECRET` and compares it constant-time.

### CS-11 · Actor identity spoofing / mutable id (High) — FIXED
Distinct-approver dedup was raw-string (`alice`/`Alice`/`alice ` counted as
three), and Telegram keyed on the mutable `@username`. **Fix.** `normalizeActor`
(NFC + trim + casefold) for all dedup; Telegram keys on the stable numeric id.

### CS-12 · DoS: unbounded `readBody` and leaking `PendingDecisions` (High) — FIXED
`readBody` buffered without limit before auth; timed-out Intents leaked their
`PendingEntry` forever. **Fix.** `readBody` caps at 1 MiB (throws before
parse/auth); `PendingDecisions` reaps each entry at its deadline.

### CS-13 · Robustness (Medium) — FIXED
Ephemeral authority/agent keys are now warned loudly (silent-key footgun);
`ReceiptLog.verifyAll` reports a malformed line as a fault instead of throwing;
`isChainEntry` rejects a non-receipt (e.g. array) payload.

## Documented, not "fixed" — accurate claims + planned crypto

Two features were **overclaimed** in earlier docs. The claims are corrected;
the stronger *cryptographic* versions are planned for v0.2. These are design
properties, not bugs — the reference behaviour is unchanged, the wording is.

- **ReceiptLog is not standalone tamper-evident.** The chain is keyless SHA-256:
  a writer who tampers can recompute every downstream `prev` and pass
  `verifyChain`. Real tamper-evidence requires an externally-anchored `head()`
  (`expectedHead`). Docs/comments/site now say so; **v0.2** adds a keyed,
  self-anchoring chain (a signed head per append).
- **Quorum four-eyes is authority-enforced, not cryptographic separation of
  duty.** Distinctness is over `actor` strings the single authority key vouches
  for, so a holder of that key can mint N distinct receipts. Spec §1 "Trust
  model" and the README/`awaitWithDefault` docs now state this; **v0.2** adds
  per-approver keys (one verifying receipt per distinct trusted key).

## Interop note (Medium)
"Canonical JSON" is under-specified for *third-party* verifiers (number
formatting, key-sort by UTF-16 code unit, duplicate keys, NFC). Same-impl this
is safe (fixed ASCII keys, bounded integers, re-canonicalizing verifiers). To be
pinned normatively (RFC 8785 / JCS) before other-language implementations are
relied upon.
