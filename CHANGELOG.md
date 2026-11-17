# Changelog

All notable changes to counter-sign are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
1.0. Until then, `0.x` minor bumps may include breaking changes.

## [Unreleased]

### Changed
- **Human passkey / WebAuthn signing promoted to stable** (was `@experimental` in 0.2.0).
  The `SigningServer` HTTP surface (GET/POST `/sign`, the signed single-use link token, the
  two-phase challenge→record protocol) and the `SigningLinkAdapter` delivery/collection
  contract are now frozen. No wire or API change — the promotion removes the experimental
  caveat, adds conformance vectors for the passkey path, and documents the surface
  (README *Passkey approvals*). Re-validated end to end by the browser + WebAuthn
  human-simulation harness (approve / veto / timeout-Default / wrong-key).
- README quorum docs updated to v0.2 reality: per-approver-key quorum is cryptographic
  separation of duty (the stale "binding each approver to a distinct key is on the
  roadmap" note predated 0.2.0), the adapter table now includes the signing-link
  channel, and per-channel delivery constraints (email/local `quorum: 1`, vouched-only
  chat channels, all-passkey signing-link delivery) are stated explicitly.
- The passkey receipt/challenge recipe (`unsignedReceipt` / `challengeFor`) now has a
  single definition in `core/countersignature.ts`, consumed by the signing page, the
  verifier, and the vector generator alike — signer/verifier/vectors can no longer
  drift by copy-paste. Internal refactor; no public-API or wire change.
- **Chat adapters refuse, before sending anything, a request the platform would reject
  anyway**: Telegram text over 4096 characters, a Slack section over 3000 characters
  (both counted in code points, so the refusal covers only text the platform rejects
  however it counts), and a WhatsApp template variable with a newline or tab. 0.2.0 sent
  these and then failed on the platform's error (`telegram sendMessage failed`, `slack
  chat.postMessage failed: invalid_blocks`, `whatsapp template send failed`); now
  `deliver` throws a `CountersignError` naming the problem and makes no API call.
  Anything 0.2.0 delivered is still delivered; the stricter checks are opt-in
  (`enforceLimits`, under Added).
- Telegram poll mode: a 409 Conflict from `getUpdates` (another process polling the same
  bot, or a webhook set) stops polling and fails waiting requests with one clear
  `TelegramPollingConflictError` instead of retrying every 2 seconds forever.
- After a decision, Telegram, Slack and Discord messages say "Decision recorded:
  <DECISION> by <who> at <receipt timestamp>" (Discord said "Resolved: <DECISION> (last:
  <who>)"); Slack keeps the original request visible instead of replacing it with a
  one-liner, unless it is too long to repeat in a section. While a quorum is open:
  "Approval n/q recorded: <who> at <time>. Awaiting more approvers." The reason: the
  message now shows who decided and when, taken from the signed receipt, so the chat
  record matches the audit record. Code that parses the old Discord "Resolved: …" text
  must be updated.
- `resolveRule` called without `deps.registry` in keyed mode now throws a clear
  `CountersignError` instead of a `TypeError`.
- **`ReceiptLog` flushes every append to disk by default** (`fdatasync`, plus the
  directory of a new file), so `record()` and `append()` resolve only once the receipt is on stable storage. Results, files and errors are
  unchanged; each append now waits for the disk, which adds latency (most on slow or
  network disks). Why: the guarded action must never run on an approval a power cut
  could take back. Opt out with `new ReceiptLog(path, { fsync: false })` (see Added).

### Added
- **Conformance vectors for passkey / WebAuthn receipts** (`webauthn` section,
  [`vectors/`](vectors/)): deterministic `webauthn-ed25519` accept cases, a frozen
  verify-only `webauthn-p256` fixture (ECDSA signing is randomized; the generator
  re-verifies the fixture on every run), and the negatives — wrong origin, cross-origin
  frame, missing User-Present, UV-required-but-absent, forged authenticator key,
  cross-intent replay, and the no-RP-policy fail-closed rule — plus resolution-level
  accept/reject including a 2-of-2 passkey quorum, a forged slot, and under-quorum.
- **`ReceiptLog` is durable before anyone acts.** Every append is flushed (`fdatasync`)
  before `record()` resolves, and a new file's directory is flushed too. Opt out with
  `new ReceiptLog(path, { fsync: false })`. This is a new default; see Changed.
- **`ReceiptLog` torn-tail handling, opt-in** (`{ repairTornTail: true }`; default off,
  so a torn last line still throws exactly as in 0.2.0). Reads skip a partial last line
  and `verifyAll` lists it in a new optional report field, `tornTails` (type
  `TornTailReport`: `index`, `intent_id`, `offset`, `length`, `quarantined`), with `ok`
  false. Reading never changes the file. Only the instance that appends repairs: before
  each append it moves a torn end, byte for byte, to `<file>.quarantine.jsonl` and cuts
  the log back to its last whole line; `repair()` does the same on demand. A whole last
  entry that only lost its newline is kept. A corrupt line anywhere else is still a hard
  error. The `ReceiptFault` reason union is unchanged, and `tornTails` is absent from a
  report unless the log opted in or has a quarantine file.
- **`ReceiptLog` can keep each Intent beside its receipts** (`{ intents: true }`, sidecar
  `<file>.intents.jsonl`, or any `IntentStore`; `FileIntentStore` is the default), so
  `verifyAll` audits vouched receipts and timeout Defaults without being handed the
  Intents. `ReceiptSink.record` receives the Intent as an optional second argument. The
  receipts file format is unchanged.
- **Resumable decisions.** `DurableDecisions` issues an Intent now and resolves it later,
  across a restart: `restore()` re-arms unfinished Intents with their remaining time,
  lapses expired ones to the signed Default, finishes decisions taken but not logged, and
  never decides an Intent twice. It lapses by the Intent's own deadline, and a record it
  cannot restore is listed in `RestoreReport.failed` while the others are still restored.
  A stored Intent that no longer carries its agent's signature (an edited store file) is
  listed in `failed` and never re-armed or delivered again. A delivery that reached some
  approvers but not others (`DeliveryPartialError`) keeps the Intent pending, marked
  delivered, so the reached approvers' presses count; the missed approvers are stored and
  returned in the new `PendingRecord.unreached` (`PendingStore.markDelivered` takes them
  as an optional second argument). A delivery that reached nobody abandons the Intent
  and rethrows. A re-delivery in `restore()` that fails outright abandons the Intent only
  if no earlier delivery reached anyone; if one did, those approvers still hold live
  buttons, so it stays pending and re-armed and the failure is listed in the new
  `RestoreReport.redeliveryFailed`.
  Backed by the `PendingStore` interface and `FilePendingStore` (flushed JSONL events, a
  lock file enforcing one writer per store; run one process per store). The lock records
  pid, host, process start time and a random token and is kept fresh by a heartbeat
  (`lockLeaseMs`, default 10 s). On the same host it is taken over when its process is
  gone or its heartbeat is older than the lease. A lock naming this process's own pid is
  taken over only when its last heartbeat predates this process and is older than two
  heartbeat intervals: a crash-restart in a container opens at once (or after waiting out
  those two intervals), while a live twin container sharing the hostname and pid is
  refused. Takeover is atomic (rename aside, check, exclusive create, re-read), so two
  processes starting together never both hold it, and an opener that loses a round backs
  off and retries a bounded number of times instead of failing at once. Every write
  checks, before and after its append, that the lock is still the handle's and that the
  file holds only the handle's own bytes; otherwise the write rejects, this handle does
  not act on it, and the handle stops writing. If the event landed, the store's next
  holder (or the next open) replays it, so a rejected issue may still be delivered and a
  rejected decision may still be logged. `PendingDecisions` accepts `{ store }` and gains
  `restore()`; `wrapAction` gains the opt-in `pendingStore` option, and with it
  `onDelivered(record)`, which receives the issued record (so a partial delivery's
  `unreached` list reaches the caller).
  For people writing their own adapter: an adapter that takes `pending` or
  `pendingStore` in its config (`PendingDecisionsSource`) builds its book-keeping with
  `pendingDecisionsFor(config)`, which returns a new in-memory `PendingDecisions` when
  neither is set. The built-in adapters do not take either option; each keeps its own
  in-memory `PendingDecisions`.
- `resolveRule(name, request, { store, org }, { approvers: "vouched" })` resolves a policy
  rule into **vouched** approvers, the form the chat and email adapters accept, so the
  policy layer can feed a Slack / Telegram / WhatsApp Route. Quorum 1 only: any other
  quorum is refused, never downgraded. An optional `channel` keeps only members on one
  channel (`"slack"` → `slack:*`). No registry is needed in this mode. Default (keyed)
  resolution is unchanged. The `ResolveOptions` and `VouchedResolveDeps` types are
  exported.
- Slack adapter: optional `appId` / `teamId` (`SLACK_APP_ID`, `SLACK_TEAM_ID`); a signed
  interactivity payload from another app or workspace is refused with 403.
- **WhatsApp recipient modes, opt-in** (`recipientMode`, `WHATSAPP_RECIPIENT_MODE`). With
  no mode, every request goes to `to` / `WHATSAPP_TO` with no check on the approvers,
  exactly as in 0.2.0 (and construction without `WHATSAPP_TO` still throws the 0.2.0
  error). `"approvers"` sends one template to each `whatsapp:<number>` approver the Intent
  names (no `to` needed) and refuses an Intent naming none or naming one not written as
  bare E.164 digits (the webhook reports `from` without a `+`). `"single"` sends to `to`
  and refuses an Intent whose WhatsApp approvers are not exactly that number, instead of
  sending it and silently ignoring the press. Exported type `WhatsAppRecipientMode`.
- `DeliveryPartialError` (from `adapters/whatsapp`, and the package root): in
  `"approvers"` mode, a send that fails after earlier recipients were sent the request
  throws it, with `intentId`, `reached` and `unreached` actor lists and the send error as
  `cause`. A failure on the first send throws the plain send error. With plain
  `wrapAction` the call rejects and a reached approver's press is ignored (tell them the
  request was withdrawn); `DurableDecisions` keeps the Intent pending instead (see
  Resumable decisions). Nothing delivers to only the unreached; issue a new Intent.
- WhatsApp adapter: opt-in `requirePhoneNumberId` (`WHATSAPP_REQUIRE_PHONE_NUMBER_ID=1`),
  which ignores webhook changes addressed to another `phone_number_id` or carrying none;
  `templateBody` (`WHATSAPP_TEMPLATE_BODY`); and opt-in `confirmDecisions`
  (`WHATSAPP_CONFIRM_DECISIONS=1`), which replies "Decision recorded: … by … at …" to the
  presser after a press.
- **`enforceLimits: true`** on the Telegram, Slack and WhatsApp adapters: count message
  text in UTF-16 code units (never fewer than the platform's characters), and for
  WhatsApp also refuse a variable with four or more spaces in a row and a template body
  over the limit once the variables are filled in, so nobody approves text the platform
  might cut. Off by default.
- Message-limit constants `TELEGRAM_MAX_MESSAGE_LENGTH` (4096),
  `SLACK_MAX_SECTION_TEXT_LENGTH` (3000) and `WHATSAPP_MAX_TEMPLATE_BODY_LENGTH` (1024),
  each overridable (`maxMessageLength`, `maxSectionTextLength`, `maxTemplateBodyLength`),
  and `TelegramPollingConflictError`. Every field added to `SlackConfig`,
  `TelegramConfig` and `WhatsAppConfig` is optional, and a resolved config that sets none
  of them has exactly the 0.2.0 keys, so config objects written for 0.2.0 still compile.
- **Python client: `create_intent(fields, agent_secret_key, *, agent_id, intent_id=None,
  created_at=None)`** builds and signs an Intent with every rule of the reference's
  `createIntent`; byte-identical to the reference for the same id and time (checked
  against the vectors and, through `tsx`, against the reference itself).
- **Python client: `FileReceiptLog`**, a file-backed receipt log in the reference's format
  (same lines, hash chain and head) with `append`, `record`, `read`, `history`, `head`,
  `verify_chain` and `verify_all`. Every write is fsync'd. A torn last line is handled
  exactly as the reference does: it raises by default, and with `repair_torn_tail=True`
  reads report it in `tornTails` without changing the file while the writer quarantines
  it before its next append (`repair()` on demand). Logs written by either
  implementation verify in the other with identical reports.
- Python client: interop tests against the TypeScript reference (skipped when Node is not
  installed).
- `tests/canonical-rfc8785.test.ts` pins where canonical JSON already matches RFC 8785
  (numbers, string escapes, UTF-16 key order, the RFC's own examples) and where it differs
  (lone surrogates, duplicate keys). Behaviour unchanged.

### Fixed
- **`ReceiptLog` no longer glues a receipt onto a last entry that lost its newline.**
  In 0.2.0 an append to a file whose last whole entry had no trailing newline (a crash
  between the entry and its newline, or a hand edit) joined the two on one line, and
  every later read threw "corrupt". Now, by default, the append path writes the missing
  newline first, but only after the rest of the file has been read without error and only
  when the last segment is this log's own last chain entry (its seq, its hash and its link
  to the line before). An append that fails (a corrupt line elsewhere) writes nothing, as
  in 0.2.0. Nothing is cut or moved, reads never write, and any other last segment is left
  exactly as in 0.2.0. The Python `FileReceiptLog` does the same.
- Python client: `webauthn-p256:` passkey descriptors are checked as strictly as in the
  reference (canonical base64url, 65 bytes, uncompressed-point marker); before, any
  non-empty string passed.
- Python client: a receipt carrying `"webauthn": null` no longer verifies as a plain
  ed25519 receipt, matching the reference.
- Python client: `create_intent` raises `CountersignError` naming the field for a lone
  UTF-16 surrogate in any text field, instead of a raw `UnicodeEncodeError`. The
  reference accepts such an Intent; the difference is written up in
  `docs/proposals/0005`.
- Docs, the WhatsApp example and `.env.example` now agree that `WHATSAPP_APP_SECRET` is
  required.
- The Telegram example and guide name the approver by the presser's user id
  (`TELEGRAM_APPROVER_ID`), which differs from the chat id in groups.

### Docs
- `docs/proposals/`: seven written proposals from the first reference deployment (content
  binding, approver-receipt deadline checks, withdraw and change-requested, a signed
  receipt chain, RFC 8785 canonical JSON, resumable decisions, Route delivery and message
  limits). Not applied; no spec, schema or vector change.
- SECURITY.md and the security review no longer describe the spec as v0.1, and the review
  no longer claims the keyed self-anchoring receipt log shipped in v0.2.
- README: "Durable before anyone acts", "Keep the Intents too" and a new "Resumable
  decisions" section; adapters guide covers WhatsApp approver delivery, Slack app/team
  pinning and how Telegram approvers are identified.

### Security
- **Spec §4 finality enforced at the shared layer.** `PendingDecisions` keeps a
  wall-clock-gated tombstone of each resolved intent, so a resolved intent can never be
  reopened — a re-`wait()` returns the recorded decision and a late or second approver's
  receipt is ignored — for *every* caller (any adapter instance, a raw `awaitResolution`),
  not just one adapter. Gated on `Date.now()` vs the deadline (the same authority
  `record()`/`settle()` use), so it is immune to Node's ~24.8-day timer ceiling and to
  backward wall-clock steps.
- **Passkey verification hardening.** `verifyCountersignature` reads the receipt's
  `public_key` once, so an accessor-backed field can no longer return one key to the trust
  check and another to the signature check; `verifyWebAuthnAssertion` rejects a non-array
  `allowedOrigins` (closing a substring-match fail-open) and the impossible
  Backup-State-without-Backup-Eligibility flag combination; and `SigningServer` binds a
  recorded passkey timestamp to the intent deadline (no post-dating a decision past a short
  window) without a cross-clock-domain comparison that would false-reject a genuine
  multi-host approval.
- **A human veto can no longer be flipped to an approve Default at the deadline boundary.**
  `awaitWithDefault` discards a decision *observed* at/after the deadline in favor of the
  Default (a stale/overdue adapter must not beat the timeout). Because the observation runs
  in a promise microtask, a `reject` recorded in-window (record()/settle() gate on the
  clock, so it was in time) whose reaction ran a microtask later was being discarded — and
  for `default:"approve"` (quorum 1) that meant `mintDefault` returned **approve**, turning
  a human's NO into a YES. The past-deadline branch now never lets an approve Default
  override a reject: a reject-shaped resolution is honored and still adjudicated by
  `verifyResolution` (a genuine listed-approver veto passes; a forged/unlisted/contradictory
  one fails closed). Trade-off, by design: a genuinely post-deadline veto from a *custom*
  adapter may now deny an action whose Default would have approved — an availability/finality
  choice, never an unauthorized execution. Found by adversarial review, confirmed by a
  second engine, and locked by a red-first fake-timer test.
- Hardening surfaced by a convergence review loop (second-engine review + workflow code
  review + adversarial review), each fix locked by a red-first regression test and
  re-validated by the browser + WebAuthn human-simulation harness. 361 tests.

## [0.2.0] — 2026-07-17

Per-approver-key quorum: `quorum > 1` is now **cryptographic separation of duty**, not a
count the single authority vouches for. This is the first wire-format change since 0.1
(`countersign: "0.2"`).

### Added
- **Per-approver-key quorum (`keyed` approvers).** For `quorum > 1`, every approver signs
  their own receipt with their own key, which the authority never holds — so a party in
  possession of the authority key can neither forge the quorum nor swap an approver's
  bound key (each key is bound in the agent-signed Intent). Four-eyes becomes cryptographic
  separation of duty. Vouched approvers remain available for a single approver; mixing a
  vouched slot into `quorum > 1` is rejected.
- **Enrollment registry (`ApproverRegistry`).** An org-root-attested, hash-chained,
  append-only log anchoring each `actor → key` binding — signed by an org-root key distinct
  from the runtime authority, with proof-of-possession required for every key (a
  raw-ed25519 self-signature, or a WebAuthn assertion for a passkey), plus revocation and a
  strict `assertApproversEnrolled` check. New `enroll` CLI.
- **Human passkey / WebAuthn signing** (`@experimental`). `SigningServer` (a deep-linked
  signing page + single-use link + receipt collection) and `SigningLinkAdapter` (delivers a
  keyed passkey quorum through the `wrapAction` path). Security matches every keyed path —
  the server holds no approver key — but the async delivery/collection glue is not yet
  frozen; for production keyed approvals today, use the raw-ed25519 `approve` CLI or vouched
  chat/email approvers.
- **`approve` CLI** — a raw-ed25519 keyed approver signs a receipt out of band (the stable
  keyed path).
- **Conformance test vectors + suite** ([`vectors/`](vectors/)) — a deterministic,
  language-neutral fixture set any independent implementation can check itself against, so
  signature interop is *provable*, not assumed: canonical-JSON known-answers, key
  derivation, `signContext` message + signature vectors, signed Intents,
  keyed/vouched/timeout-default receipts, `verifyResolution` accept **and** reject cases
  (under-quorum, forged-quorum, wrong-authority-key), and the receipt-log hash-chain head.
  Regenerate with `npm run gen:vectors`; the reference impl is re-checked against the
  committed vectors on every `npm test` ([`tests/conformance.test.ts`](tests/conformance.test.ts)).
  See [`vectors/README.md`](vectors/README.md). Shipped in the npm package. Passkey/WebAuthn
  receipts (non-deterministic P-256) are not yet vectored — planned.

### Changed
- **Wire version → `0.2`** (the `countersign` field and every signature context). A
  **deliberate compatibility break**: v0.1 integrity-only receipts predate per-approver keys
  and were forgeable by a compromised authority server, so a v0.2 verifier does not accept
  them — they fault loudly, never silently. Audit existing v0.1 archives with a v0.1 install.
- **`verifyAll` audit model.** Keyed, vouched, and timeout-Default receipts all require
  `authorityKey` to be audited (mirroring `verifyResolution`); `trustedKeys` /
  `trustedAgentKeys` are additional filters, compared by credential material so a passkey
  descriptor and its raw form are one identity. Malformed / empty option inputs are rejected
  with clear errors rather than silently misreporting an honest log.
- **`wrapAction` reconciles the authority key** (as well as the WebAuthn policy) with the
  adapter and fails fast before delivery, so a human is never told "approved" on a request
  the runtime would then silently block.

### Security
- The keyed-quorum path went through repeated adversarial review rounds (a convergence loop)
  plus a browser + WebAuthn human-simulation harness exercising approve / veto /
  timeout-Default / wrong-key end to end. 328 tests.

### Fixed
- Many fail-closed and audit-consistency fixes across `verifyAll`, the shim, the adapters,
  and the enrollment / receipt-log CLIs, surfaced during review (see the
  `fix(v0.2): resolve round-N findings` history).

## [0.1.3] — 2026-07-15

### Security
- **Fixed an authorization bypass (BLOCKER):** `verifyResolution` gated its
  quorum check on the attacker-supplied `resolution.policy`, so a `policy:"default"`
  approve with a single authority-signed receipt (even the public timeout-reject
  receipt) authorized any quorum-N Intent. Quorum is now enforced for every
  `approve` regardless of policy; each receipt's decision must match the resolution.
- **Fail-closed hardening:** enforcement path validates Intent invariants +
  agent signature; `quorumOf` throws on a malformed quorum; a NaN/huge
  `created_at`/`timeout` can no longer collapse the veto window.
- **Webhooks fail closed:** `WHATSAPP_APP_SECRET` required; Telegram
  `webhookHandler` refuses to run without `TELEGRAM_WEBHOOK_SECRET` (constant-time
  check). Telegram keys the approver on the stable numeric id, not the `@username`.
- **DoS:** `readBody` size-capped (1 MiB); `PendingDecisions` reaps entries at
  their deadline. Actor dedup normalizes (NFC+trim+casefold).
- **Honesty:** ReceiptLog "tamper-evident" and quorum "four-eyes" claims corrected
  — the chain needs an anchored `head()`, and quorum is authority-enforced, not
  cryptographic separation of duty. Keyed self-anchoring log + per-approver-key
  quorum are on the v0.2 roadmap. See [docs/security-review.md](docs/security-review.md).
- **Adversarial second-engine review (Codex):** additionally (1) enforce that only
  the Intent's signed `approvers` may decide — an unlisted channel member's click
  is ignored, so membership is not authority; (2) fix a timeout-reaper race so
  silence reliably yields the signed Default instead of throwing; (3) catch an
  oversized Telegram webhook body (no unhandled rejection); (4) ignore any decision
  processed at/after the deadline (an event-loop stall could otherwise let a late
  approval beat the Default). Demos updated to name the real approver identity.
- Regression tests encode each exploit (121 total). No wire-format change; v0.1.x receipts still verify.

## [0.1.2] — 2026-07-09

### Added
- **Hash-chained ReceiptLog** — each log entry now commits to a SHA-256 of the
  entry before it, so the stored history is tamper-evident for *completeness*,
  not just per-receipt authenticity: an edit, reorder, insertion, or mid-stream
  deletion breaks the chain. `verifyChain()` walks the links and names the first
  break; `verifyAll()` folds the chain result into `ok` (true only when every
  receipt is genuine **and** the chain is intact).
- **`head()` / `expectedHead`** — checkpoint the chain head and anchor it
  externally to detect tail truncation (which a forward chain alone cannot).
- New types: `ChainEntry`, `ChainHead`, `ChainReport`; `ReceiptLogReport` gains a
  `chain` field.

### Changed
- On-disk log format is now a chained envelope (`{ seq, prev, receipt }`) per
  line instead of a bare receipt. Reading a pre-chain (v0.1.1) log still works;
  `verifyChain()` flags such entries as `unchained-entry`. No change to the
  protocol or the Countersignature wire format — receipts inside are byte-for-byte
  the same portable artifact.

## [0.1.1] — 2026-07-09

### Added
- **`ReceiptLog`** — an opt-in, append-only, tamper-evident approval history
  stored where the runtime is installed. Each line is the canonical JSON of one
  Countersignature, so the file is a portable audit trail: replay and re-verify
  every decision offline with `read()`, `history()`, and `verifyAll()`. Pass one
  to `wrapAction({ receiptLog })` and every resolution (approval, veto, or timeout
  Default) is recorded before the guarded action runs (fail-closed audit).
- **`ReceiptSink`** interface — back the history with a file (`ReceiptLog`),
  SQLite, Postgres, or a log pipeline without changing call sites.
- Reference implementation stays stateless unless a sink is supplied; no change
  to the protocol or wire format.

## [0.1.0] — 2026-07-08

First public draft of the protocol and reference implementation.

### Protocol (spec v0.1)
- Four nouns: **Intent**, **Route**, **Countersignature**, **Default**.
- ed25519 signatures over domain-separated canonical JSON (distinct contexts for
  Intent, Countersignature, and email decision links).
- **Quorum**: optional M-of-N (two-person / four-eyes) approval — authorized only
  when `quorum` distinct actors approve; any single reject vetoes; a timeout for a
  quorum Intent fails closed.
- Normative security requirements: verify before acting, integrity is not
  authority, silence resolves to the declared Default.

### Reference implementation (TypeScript, Node 20+, ESM)
- Core: create/sign/verify Intent and Countersignature, Resolution + timeout/Default
  handling, `verifyResolution` authority binding.
- `wrapAction` shim — gate any function behind human approval in ~5 lines.
- One `Adapter` interface; five adapters: **Telegram, Discord, Slack, WhatsApp
  (Meta Cloud API), email** (signed single-use links, GET-cannot-decide), plus a
  no-network **local** approver.
- JSON Schema (draft 2020-12) for Intent and Countersignature; signed example /
  conformance payloads.
- 74 tests (vitest); runnable demos per adapter.

### Security
- Authority binding (`verifyCountersignature(cs, { trustedKeys })` and
  `awaitWithDefault`): integrity is never accepted as authority.
- Signature domain separation across artifact types.
- Adapter hardening: Slack/Discord/WhatsApp request-signature verification;
  Discord/Slack message-injection defenses; one-time warnings for unauthenticated
  webhooks.
- Quorum fail-safe: distinct-actor dedup; `quorum > 1` + `default: approve`
  refused at construction; timeout on a quorum Intent forces `reject`.
- Verifiers are total (never throw on hostile input); `canonicalize` depth-guarded;
  `timeout` bounded against `setTimeout` clamping.
- Full write-up: [`docs/security-review.md`](docs/security-review.md).

### Compliance
- [`COMPLIANCE.md`](COMPLIANCE.md): maps a Countersignature to control areas in
  SOC 2, ISO/IEC 27001, the NIST AI RMF, and EU AI Act Article 14 (human
  oversight), framed as evidence — not a compliance guarantee.

### Licensing
- Code: Apache-2.0. Specification text: CC BY 4.0 (vendored as
  `LICENSE-CC-BY-4.0.txt`).

[Unreleased]: https://github.com/countersign-labs/counter-sign/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/countersign-labs/counter-sign/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/countersign-labs/counter-sign/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/countersign-labs/counter-sign/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/countersign-labs/counter-sign/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/countersign-labs/counter-sign/releases/tag/v0.1.0
