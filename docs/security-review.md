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

## Second-engine (Codex) adversarial review — FIXED

After the five-front review above, the v0.1.2→v0.1.3 diff was re-reviewed by a
different engine (OpenAI Codex, adversarial mode) as an independent check on the
fixes. It confirmed the policy bypass was closed and found three further issues,
all now fixed with regression tests in `tests/security-hardening.test.ts`:

- **CS-14 · Named `approvers` were not enforced (High) — FIXED.** `verifyResolution`
  counted any distinct signed actor without checking membership in the Intent's
  signed `approvers`, so in a shared channel any authenticated member's click
  could satisfy quorum. Now both `PendingDecisions.settle` (ignores an unlisted
  actor's approve *and* veto) and `verifyResolution` (rejects a receipt from a
  non-approver) enforce the allowlist under normalized identity.
- **CS-15 · Timeout reaper could reject the arbitration promise (Medium) — FIXED.**
  The deadline reaper rejected the same promise `awaitWithDefault` races against
  its default timer; at an equal deadline the reaper (registered first) could make
  the race reject instead of resolving to the signed Default. The reaper now evicts
  the entry without rejecting.
- **CS-16 · Telegram webhook lacked an outer error handler (Medium) — FIXED.** The
  new `readBody` cap threw into a `void`-launched handler with no `.catch`, risking
  an unhandled rejection on an oversized body. Added the outer catch the other
  adapters already had.

A re-review after those fixes found one more:

- **CS-17 · A decision processed after the deadline could beat the Default (High)
  — FIXED.** `PendingDecisions.settle` did not check the deadline; if the event
  loop stalled past expiry (process suspend, GC pause, sleep), a late approval
  processed before the overdue reaper fired could win the `awaitWithDefault` race
  and authorize after the review window closed — contra spec §4 ("any decision
  arriving after the deadline MUST be ignored"). `settle` now evicts and ignores
  any decision observed at/after `deadline(intent)`, so the signed Default wins.
- **CS-18 · The core timeout race lacked the deadline gate for non-PendingDecisions
  adapters (High) — FIXED.** The CS-17 gate lived in `PendingDecisions.settle`, so
  a *custom* `Adapter` (not using that helper) could still resolve a late approval
  that beat the Default in `awaitWithDefault`'s race. The gate now lives in
  `awaitWithDefault` itself: the adapter resolution is wrapped so any decision
  observed at/after the deadline is replaced by the Default, enforcing the rule for
  every Adapter implementation (settle keeps its gate as defense-in-depth).
- **CS-19 · LocalAdapter overclaimed a distinct-human quorum (High) — FIXED.** For
  `quorum > 1` the local adapter read approver names from stdin, so one terminal
  operator could type `alice` then `bob` and mint a "two-person" quorum that
  `verifyResolution` accepted. A single terminal cannot authenticate distinct
  humans, so LocalAdapter now refuses `quorum > 1` at `deliver` (matching
  EmailAdapter's single-bearer-link stance). `demo:quorum` was reworked to
  illustrate the accumulation/veto mechanism with clearly-simulated approvers.

A subsequent standard (non-adversarial) Codex review found one more:

- **CS-20 · A far-future `created_at` collapsed the review window (P1) — FIXED.**
  `assertIntentInvariants` bounded `timeout` but only required `created_at` to be
  *finite*, so a parseable but absurd timestamp (e.g. `+275760-09-13T…`) made
  `deadline − now` exceed Node's ~24.8-day `setTimeout` ceiling; Node clamps that
  to ~1 ms and fires the Default immediately — an auto-approve for
  `default:"approve"`. `awaitWithDefault` now refuses a `remaining` beyond the
  timer ceiling (fail closed).

An adversarial re-review of the five hardening commits above found one more:

- **CS-21 · Reject resolutions bypassed the signed approver allowlist (High) —
  FIXED.** `verifyResolution`'s allowlist/policy proof ran only for
  `decision: "approve"`, so a custom or version-skewed adapter could return an
  authority-signed `reject` receipt from an actor absent from the Intent's
  `approvers` — or under an arbitrary `policy` — and `awaitWithDefault` would
  accept it: an unauthorized channel participant could permanently veto an
  operation and mint a misleading audit receipt (denial of service).
  `PendingDecisions.settle` already blocked this, but `verifyResolution` is the
  documented trust-boundary choke point for ANY adapter. The policy proof now
  runs for both decisions: a `policy:"approver"` resolution requires every
  receipt's actor to be in the signed allowlist (approve additionally needs the
  quorum); a `policy:"default"` resolution must be exactly the canonical
  `default:timeout` receipt whose decision matches what `defaultResolution`
  would produce; any other policy is rejected.

The adversarial review of the CS-21 fix found one more:

- **CS-22 · Default receipts were accepted before the timeout fired (Critical) —
  FIXED.** Nothing checked a `policy:"default"` receipt against the deadline:
  an adapter could return `defaultResolution(intent, key)` immediately and
  `awaitWithDefault` accepted it ~the full window early. For `default:"reject"`
  that forges a "nobody responded" audit record (and bypasses CS-21's allowlist
  via the `default:timeout` actor); for `default:"approve"` it made `wrapAction`
  execute without waiting for human review — the review window collapsed to
  zero. Three layers now enforce "the Default fires AT the deadline, never
  before": `defaultResolution` refuses to mint while `now < deadline`;
  `verifyResolution` rejects a default receipt whose signed `timestamp`
  precedes the deadline (offline-verifiable — the timestamp is
  signature-protected); and `awaitWithDefault` discards any adapter-supplied
  `policy:"default"` resolution observed before the deadline (even one with a
  forged future timestamp, signable by an authority-key holder), letting the
  runtime's own timer mint the genuine Default on time. Spec §4 now states the
  rule. +6 tests, including a `wrapAction`-level regression proving the action
  cannot execute before the window closes.

An adversarial multi-agent re-review of the CS-22 fix (4 attack lenses → verify)
confirmed one regression it had introduced and refuted three other candidates:

- **CS-23 · The CS-22 mint guard could crash/hang the honest timeout path under a
  backward wall-clock step (Medium, availability) — FIXED.** `awaitWithDefault`
  computes `remaining` from the wall clock but schedules `setTimeout` on the
  monotonic clock, then the timer callback called `defaultResolution`, whose
  CS-22 layer-1 guard re-reads the wall clock and throws when `Date.now() <
  deadline`. If the wall clock stepped backward relative to the monotonic timer
  after scheduling (NTP step-back, VM snapshot/resume, macOS `adjtime`), the
  guard threw *inside the timer macrotask* — uncaught: process crash, or a
  permanent hang if an `uncaughtException` handler was installed. It failed
  *closed* (no early authorization, no forged record — the throw prevented any
  mint), so it was availability-only, not a deadline bypass. Fix: split the
  actual minting into an internal `mintDefault` that performs no wall-clock check
  (the runtime timer firing is the authoritative "deadline reached" signal) and
  stamps the receipt at `max(now, deadline)` so a genuine Default is never
  stamped before the window it represents; the timer/expiry paths in
  `awaitWithDefault` mint through it, while the public `defaultResolution` keeps
  the guard for external callers. This also fixes a second facet: a Default
  stamped at a backward wall clock would have been rejected by CS-22's own
  `verifyResolution` timestamp gate at the end of the race. +2 tests.
  Three refuted candidates (all verified to fail closed / out of scope): an
  offline verifier accepting a future-timestamped forged default (grants the
  authority-key holder nothing beyond the already-permitted key-compromise model,
  since the approver branch has no time check either); the same backward-clock
  divergence in the synchronous branches (settles as a *handled* fail-closed
  rejection, no crash); and a "routine NTP slew" trigger (Linux disciplines
  `CLOCK_MONOTONIC` and `CLOCK_REALTIME` from the same timekeeper, so only an
  abnormal backward *step* — not slew — diverges them).

A standard Codex review of the CS-22/CS-23 commit found one more security gap plus
a tooling regression:

- **CS-24 · An early Default could be relabelled past the approver branch (High)
  — FIXED.** `verifyResolution`'s `policy:"approver"` branch trusted the *unsigned*
  `Resolution.policy` and never checked each receipt's *signed* `policy`, and
  `default:timeout` was an allowed approver actor. So an Intent that lists
  `default:timeout` in its (agent-signed) `approvers`, plus a hostile adapter that
  wraps an early authority-signed `policy:"default"` / `actor:"default:timeout"`
  receipt inside a Resolution *labelled* `policy:"approver"`, dodged both
  `awaitWithDefault`'s CS-22 layer-3 discard (which keyed off the unsigned wrapper
  policy) and the approver allowlist — authorizing a `default:"approve"` action
  before the deadline. Fix (same principle as CS-21 — bind to *signed* content,
  never the attacker-controlled wrapper): the approver branch now requires every
  receipt's own signed `policy` to be `"approver"`; `default:timeout` (normalized)
  is filtered from the approver allowlist *and* rejected as a receipt actor; and
  the layer-3 early-discard keys off the signed receipt policy
  (`countersignatures.some(cs => cs.policy === "default")`) instead of the unsigned
  `Resolution.policy`. `PendingDecisions.settle` excludes `default:timeout` from
  its `approverSet` too, keeping settle-level gating in parity (defense in depth;
  every shipped adapter already channel-prefixes actors, so this is unreachable in
  practice but removes the asymmetry). An adversarial multi-agent re-review of this
  fix returned clean — no residual bypass and no CS-17..CS-23 regression. +4 tests.
- **CS-25 · The CS-22 mint guard broke the conformance-vector generator (tooling)
  — FIXED.** `scripts/gen-payloads.ts` builds a fresh 300s Intent and calls
  `defaultResolution` immediately, so the CS-22 pre-deadline guard made
  `npm run gen:payloads` deterministically throw, and the checked-in
  `default-timeout` vector was stamped ~5 min before its Intent's deadline
  (inconsistent with the new rule). The generator now advances `Date.now` to the
  deadline while minting the timeout vector (restored in `finally`), and the
  refreshed fixture is an on-time Resolution that round-trips through
  `verifyResolution` (asserted in `signing.test.ts`).

The layer-3 discard described under CS-22 above was subsequently rebound (CS-24) to
key off each receipt's *signed* policy rather than the unsigned `Resolution.policy`.
