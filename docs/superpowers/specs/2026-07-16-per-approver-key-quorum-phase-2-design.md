# Per-approver-key quorum — Phase 2 (passkey / WebAuthn signing UX)

**Status:** Design, planned (depends on Phase 1)
**Date:** 2026-07-16
**Milestone:** let *human* keyed approvers sign with a passkey (Face ID / Touch ID / security key) via a signing page a channel message deep-links to — button-like UX, hardware-backed, server cannot forge.

## Problem / goal

Phase 1 gives keyed approvers a raw ed25519 signer (great for bots/CLI, poor for a CEO on a phone). Phase 2 adds a **WebAuthn** path so a human's keyed receipt is produced by their authenticator, not a key file, while keeping the "tap → confirm → done" feel. The server still never holds the signing key.

## Approach (decided)

A keyed receipt may be produced two ways, both verifying against the approver's **bound key** in the agent-signed Intent:

1. **raw ed25519** (Phase 1) — no `webauthn` block; `signature` is ed25519 over the canonical receipt; `public_key` is the approver's raw ed25519 key.
2. **WebAuthn assertion** (Phase 2) — the approver's bound `public_key` is their credential's **COSE** public key; the receipt carries a `webauthn` block and `signature` is the authenticator's assertion. Supported COSE algorithms: **Ed25519 (alg -8, preferred)** and **ECDSA P-256 (alg -7, for broad authenticator support)**. This adds a P-256 verifier to `core/keys`.

The WebAuthn **challenge** is `SHA-256(canonical receipt with signature/webauthn absent)`, binding the assertion to this exact decision (anti-replay).

### Countersignature extension

Add an optional block, present iff the credential is a passkey:

```ts
interface WebAuthnAssertion {
  authenticator_data: string;   // base64url
  client_data_json: string;     // base64url (contains challenge, origin, type)
  alg: -8 | -7;                 // COSE alg of the credential
}
// Countersignature gains: webauthn?: WebAuthnAssertion
```

A raw-ed25519 keyed receipt omits `webauthn`. Domain separation and version (`0.2`) carry over from Phase 1.

### Verification (`verifyResolution` / `verifyCountersignature`)

For a keyed receipt with a `webauthn` block:
1. Parse `client_data_json`; require `type === "webauthn.get"`, `origin` ∈ the configured allow-list, and `challenge === base64url(SHA-256(canonical receipt))`.
2. Verify the assertion signature over `authenticator_data || SHA-256(client_data_json)` using the bound COSE `public_key` (Ed25519 or P-256 per `alg`).
3. Require the `authenticator_data` RP-ID hash to match the configured RP ID, and the **User Present** (and, for high-risk, **User Verified**) flag set.
Without a `webauthn` block, verify as raw ed25519 (Phase 1). Either way the credential key MUST equal the Intent-bound `public_key`.

### Signing page + delivery

- A self-contained signing page served on a **stable origin** (the WebAuthn RP ID) — inlined HTML/JS, no external deps (matches the repo's no-CDN posture). Reuses the existing **email link-callback token** pattern: a single-use, signed-expiry token binds `{intent_id, actor}`; **GET** shows the human-readable `summary` + Approve/Reject; the decision triggers `navigator.credentials.get({ challenge })`; the page **POSTs** the assembled keyed Countersignature back. GET never decides (spec §2 link-safety rules are load-bearing and reused verbatim).
- **Adapters:** a keyed approver receives a **deep-link** (URL button) to the signing page instead of an inline decision button; vouched approvers keep inline buttons. The signing endpoint feeds the received keyed receipt into the same `PendingDecisions.settle` / `awaitResolution` path, so `verifyResolution` is the unchanged choke point. A new `SigningServer` (framework-agnostic Node handler, like the existing webhook handlers) hosts GET/POST.

## Scope

**In:** the `webauthn` receipt block; Ed25519 + P-256 assertion verification in `core/keys`; challenge/origin/RP-ID/flag checks; the signing-page handler + single-use token; adapter deep-link delivery for keyed approvers; tests incl. a Playwright end-to-end passkey ceremony (virtual authenticator) and negative cases (wrong origin, replayed challenge, swapped credential, absent UP flag).
**Out:** enrollment/registration of credentials (Phase 3 — Phase 2 tests register a virtual authenticator inline); non-WebAuthn second factors.

## Security notes

- **Challenge binding** to the receipt digest prevents cross-decision replay; the single-use signed-expiry token prevents link replay; RP-ID + origin allow-list prevent a phishing origin from harvesting assertions.
- The signing server may run *inside* the (possibly compromised) integration server — that is fine: it only relays an assertion it cannot forge (no private key), and `verifyResolution` re-checks everything against the Intent-bound key. A compromised server can drop or delay an approval (availability) but cannot fabricate one (integrity) — the property we want.
- P-256 verification is the main new crypto surface; it is adversarially reviewed and tested against WebAuthn spec vectors.

## Testing

Playwright virtual authenticator for the happy path (Ed25519 and P-256), plus unit tests for assertion verification and every negative (bad challenge/origin/RP-ID/flags/signature/mismatched credential). All Phase 1 tests continue to pass.
