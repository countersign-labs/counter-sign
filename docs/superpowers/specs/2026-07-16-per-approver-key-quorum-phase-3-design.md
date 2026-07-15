# Per-approver-key quorum — Phase 3 (enrollment & key trust)

**Status:** Design, planned (depends on Phases 1–2)
**Date:** 2026-07-16
**Milestone:** close the remaining trust anchor — *how a verifier knows a bound key really is the CEO's* — so the whole scheme resists a compromised authority server end-to-end, not just at signing time.

## Problem

Phases 1–2 verify a keyed receipt against the `public_key` **bound in the agent-signed Intent**. That is only as trustworthy as *where the agent got that key*. If a compromised authority server could pre-seed its own keys as the approvers', separation of duty is defeated again. Phase 3 provides an **approver registry** whose bindings are attested by an authority **distinct from the runtime authority key**, so the runtime server cannot mint or swap approver identities.

## Approach (decided; standalone registry as the default, IdP-pluggable)

An append-only, signed **approver registry** mapping `actor → { public_key, alg, mode, status }`:

- **Enrollment ceremony:** an approver proves possession of a key — a WebAuthn `create()` for a passkey (yielding a COSE credential key), or a signed challenge for a raw ed25519 key — and an **admin/org root key** (separate from the runtime authority key) signs an **enrollment record** binding `actor → public_key`. Proof-of-possession prevents enrolling a key the approver doesn't control; the admin signature anchors the identity claim.
- **Registry record** (signed by the org root):
  ```ts
  interface EnrollmentRecord {
    countersign: "0.2"; actor: string; public_key: string; alg: -8 | -7 | "ed25519";
    status: "active" | "revoked"; issued_at: string; prev?: string; // hash-chained
    public_key_org: string; signature: string; // org-root attested
  }
  ```
  The log is **hash-chained** (`prev` = digest of the previous record) so it is tamper-evident — dovetailing with the separately-planned self-anchoring receipt log.
- **Intent construction:** `createIntent` (or a helper) sources each keyed approver's `public_key` from the registry and binds it into the agent-signed Intent. **Verification:** `verifyResolution` continues to check against the Intent-bound key; a stricter mode additionally re-checks that the bound key matches an `active` registry record for that actor (rejecting a key that was never enrolled or has been revoked).
- **Revocation:** append a `revoked` record; verification in strict mode refuses a revoked key. Supports key rotation (revoke old, enroll new).
- **IdP-pluggable:** the registry is an interface; the default is the standalone org-root-signed store, but an adapter can source/attest bindings from an existing IdP (Okta / Google Workspace / SCIM). Deferred to a follow-up; the interface is defined here so it does not require re-architecting.

## Trust chain (end-to-end, vs a compromised runtime authority)

1. Org root key (offline / HSM, distinct from runtime authority) attests `actor → key` in the registry.
2. Agent (distinct key) binds the registry-sourced key into the signed Intent.
3. Approver signs the receipt with their key (Phase 1/2).
4. Verifier checks receipt-key = Intent-bound key = active registry record, and the agent + org signatures.

A holder of the **runtime authority key** can forge none of these links: not the registry (org-root signed), not the Intent binding (agent signed), not the receipt (approver signed). This is the property Sanjay's review demanded.

## Scope

**In:** the registry data model + hash-chained signed store; enrollment (PoP for passkey + raw key) with org-root attestation; revocation/rotation; `createIntent` registry sourcing; `verifyResolution` strict mode (bound key ∈ active registry); the `ApproverRegistry` interface (standalone default impl); a `countersign enroll` CLI + minimal enrollment page; tests including "a revoked key cannot approve" and "a key never enrolled cannot approve in strict mode."
**Out:** a hosted multi-tenant directory service; full IdP connectors (interface only); GUI admin console.

## Security notes

- Org-root key custody is the new root of trust; it MUST be distinct from the runtime authority key (ideally offline/HSM). Documented prominently.
- Registry tamper-evidence via hash-chaining. NOTE: a backward-only chain does
  not detect TAIL TRUNCATION (a valid prefix is a valid log), which could resurrect
  a revoked key. `verifyChain`/`assertApproversEnrolled` therefore accept an
  `expectedHead` (an externally-anchored `head()`); a deployment that revokes keys
  MUST capture the head somewhere the registry writer cannot roll back.
- Registry tamper-evidence via hash-chaining; a verifier SHOULD pin the registry head out-of-band (same mitigation as the receipt log §6 item).
- Enrollment PoP prevents key-confusion / planted-key attacks.

## Testing

Enrollment round-trip (passkey + raw key), org-root signature verification, hash-chain integrity (detect a spliced/edited record), revocation refusal, strict-mode rejection of an unenrolled key, and end-to-end: enroll → keyed Intent → passkey approve → verify passes; then revoke → same approver's new attempt fails. All Phase 1–2 tests continue to pass.
