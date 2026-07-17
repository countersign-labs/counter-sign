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

### Added
- **Conformance vectors for passkey / WebAuthn receipts** (`webauthn` section,
  [`vectors/`](vectors/)): deterministic `webauthn-ed25519` accept cases, a frozen
  verify-only `webauthn-p256` fixture (ECDSA signing is randomized; the generator
  re-verifies the fixture on every run), and the negatives — wrong origin, cross-origin
  frame, missing User-Present, UV-required-but-absent, forged authenticator key,
  cross-intent replay, and the no-RP-policy fail-closed rule — plus resolution-level
  accept/reject including a 2-of-2 passkey quorum, a forged slot, and under-quorum.
  346 tests.

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
