# Changelog

All notable changes to counter-sign are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
1.0. Until then, `0.x` minor bumps may include breaking changes.

## [Unreleased]

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

[Unreleased]: https://github.com/countersign-labs/counter-sign/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/countersign-labs/counter-sign/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/countersign-labs/counter-sign/releases/tag/v0.1.0
