// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.
//
// ApproverRegistry — Phase 3 of per-approver-key quorum. Closes the remaining
// trust anchor: how a verifier knows a keyed approver's bound key really is that
// approver's. An append-only, hash-chained log of enrollment/revocation records,
// each attested by an ORG-ROOT key that is DISTINCT from the runtime authority
// key. So a compromised authority key can forge neither the registry (org-signed)
// nor the Intent binding (agent-signed) nor the receipt (approver-signed).

import { createHash } from "node:crypto";
import { canonicalize } from "./core/canonical.js";
import { normalizeActor } from "./core/countersignature.js";
import { isCanonicalPublicKey, publicKeyFromSecret, signContext, toB64url, utf8, verifyContext } from "./core/keys.js";
import { isValidCredentialDescriptor, isWebAuthnCredential, verifyWebAuthnAssertion, type WebAuthnAssertion, type WebAuthnPolicy } from "./core/webauthn.js";
import { assertIntentInvariants, verifyIntent } from "./core/intent.js";
import { CountersignError } from "./core/errors.js";
import { COUNTERSIGN_VERSION, type Intent } from "./core/types.js";

/** Domain-separation labels (distinct from intent/countersignature/link). */
const ENROLL_CONTEXT = "countersign-enroll-v0.2";
const ENROLL_POP_CONTEXT = "countersign-enroll-pop-v0.2";

export interface EnrollmentRecord {
  countersign: typeof COUNTERSIGN_VERSION;
  typ: "enroll" | "revoke";
  /** channel:address the key belongs to */
  actor: string;
  /** the approver's key: raw ed25519 (43-char) or a passkey descriptor (webauthn-…) */
  public_key: string;
  issued_at: string;
  /** sha256 hex of the previous full record (hash chain); null for the first */
  prev: string | null;
  /** the attesting org-root public key */
  org_public_key: string;
  /** org-root signature over the canonical unsigned record */
  signature: string;
}

/** Proof of possession for a RAW ed25519 approver key: the approver signs over
 *  their actor + key, proving they hold the secret before it is enrolled. */
export function createEnrollmentProof(actor: string, approverSecret: string): string {
  return signContext(approverSecret, ENROLL_POP_CONTEXT, popMessage(actor, publicKeyFromSecret(approverSecret)));
}
function popMessage(actor: string, publicKey: string): string {
  return `${normalizeActor(actor)}\n${publicKey}`;
}

/**
 * A passkey enrollee proves possession with a WebAuthn ceremony instead of a raw
 * signature: a `webauthn.get` assertion whose challenge is THIS value — a digest
 * binding the actor and the exact credential being enrolled, under the enrollment
 * domain-separation context. The enrollee runs navigator.credentials.get with this
 * challenge; `enroll` re-derives it and verifies the assertion against the bound
 * credential + RP policy. This proves the enrollee HOLDS the credential (so a key
 * nobody controls, or a typo'd key, can't be enrolled) — it does NOT by itself prove
 * the credential belongs to `actor`, since anyone holding the key can answer the
 * challenge for any actor string. Binding the credential to the right actor is the
 * ORG ROOT's responsibility: it must verify the enrollee's identity out of band
 * before signing the record. The registry's trust anchor is the org root, not the PoP.
 */
export function enrollmentChallenge(actor: string, publicKey: string): string {
  return toB64url(createHash("sha256").update(utf8(`${ENROLL_POP_CONTEXT}\n${popMessage(actor, publicKey)}`)).digest());
}

/** A passkey enrollee's WebAuthn proof of possession for `enroll`. */
export interface PasskeyEnrollmentProof {
  /** the authenticator assertion (from navigator.credentials.get over enrollmentChallenge) */
  assertion: WebAuthnAssertion;
  /** base64url assertion signature */
  signature: string;
  /** RP policy the ceremony was scoped to (rpId + allowed origins) */
  policy: WebAuthnPolicy;
}

/** sha256 hex of a full record (including its signature) — the chain link. */
function chainHash(rec: EnrollmentRecord): string {
  return createHash("sha256").update(canonicalize(rec)).digest("hex");
}

/** A checkpointed chain head — the record count and tip hash to anchor externally. */
export interface RegistryHead {
  length: number;
  hash: string;
}
const REGISTRY_GENESIS = "genesis";

export class ApproverRegistry {
  private records: EnrollmentRecord[] = [];

  /** Load a persisted registry (one JSON record per line). Verifies nothing yet. */
  static fromJSONL(text: string): ApproverRegistry {
    const reg = new ApproverRegistry();
    reg.records = text
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => {
        // Fail closed on a non-object line ("null", "123", "[]", …): otherwise it
        // becomes a record and verifyChain/activeKeys dereference it, throwing an
        // uncaught TypeError instead of a clean rejection (mirrors ReceiptLog's guard).
        const rec: unknown = JSON.parse(l);
        if (!rec || typeof rec !== "object" || Array.isArray(rec))
          throw new CountersignError("malformed registry line: each record must be a JSON object");
        return rec as EnrollmentRecord;
      });
    return reg;
  }
  toJSONL(): string {
    return this.records.map((r) => JSON.stringify(r)).join("\n") + (this.records.length ? "\n" : "");
  }
  get all(): readonly EnrollmentRecord[] {
    return this.records;
  }

  /**
   * Enroll an approver key, attested by the org-root key. EVERY key requires proof of
   * possession before the org root attests it — so a key nobody controls (or a typo'd
   * key) can't be enrolled:
   *  - a RAW ed25519 key needs `opts.pop` (createEnrollmentProof) — the approver's
   *    own signature over their actor + key;
   *  - a PASSKEY descriptor needs `opts.webauthnPop` — a WebAuthn assertion over
   *    `enrollmentChallenge(actor, key)`, proving the authenticator holds the
   *    credential, verified against the bound key + RP policy.
   * NOTE: PoP proves POSSESSION, not that the key belongs to `actor` — a holder of the
   * key can answer the challenge for any actor. The org root (which signs the record)
   * is responsible for verifying the enrollee's identity out of band before enrolling;
   * that identity check, not the PoP, is what binds the actor to the key. Fails closed
   * on a malformed key, a missing/invalid PoP, or an already-active binding.
   */
  enroll(
    actor: string,
    publicKey: string,
    orgSecret: string,
    opts: { pop?: string; webauthnPop?: PasskeyEnrollmentProof } = {},
  ): EnrollmentRecord {
    const isRaw = isCanonicalPublicKey(publicKey);
    if (!isRaw && !isValidCredentialDescriptor(publicKey))
      throw new CountersignError(`cannot enroll ${actor}: malformed or non-canonical public_key`);
    if (isRaw) {
      if (!opts.pop || !verifyContext(publicKey, ENROLL_POP_CONTEXT, popMessage(actor, publicKey), opts.pop))
        throw new CountersignError(`cannot enroll ${actor}: missing or invalid proof of possession`);
    } else if (isWebAuthnCredential(publicKey)) {
      // A descriptor alone does NOT prove a registration ceremony happened — require
      // a WebAuthn assertion over the actor/key-bound enrollment challenge, verified
      // against the credential and the ceremony's RP policy.
      const p = opts.webauthnPop;
      if (
        !p ||
        !verifyWebAuthnAssertion(p.assertion, p.signature, {
          credential: publicKey,
          expectedChallenge: enrollmentChallenge(actor, publicKey),
          rpId: p.policy.rpId,
          allowedOrigins: p.policy.allowedOrigins,
          requireUserVerification: p.policy.requireUserVerification,
        })
      )
        throw new CountersignError(`cannot enroll ${actor}: missing or invalid WebAuthn proof of possession`);
    }
    if (this.isActive(actor, publicKey))
      throw new CountersignError(`${actor} is already enrolled with this key`);
    return this.append("enroll", actor, publicKey, orgSecret);
  }

  /** Revoke a previously enrolled key (key rotation / offboarding). */
  revoke(actor: string, publicKey: string, orgSecret: string): EnrollmentRecord {
    if (!this.isActive(actor, publicKey))
      throw new CountersignError(`${actor} has no active enrollment for this key to revoke`);
    return this.append("revoke", actor, publicKey, orgSecret);
  }

  private append(typ: "enroll" | "revoke", actor: string, publicKey: string, orgSecret: string): EnrollmentRecord {
    const orgPub = publicKeyFromSecret(orgSecret);
    // A registry has ONE org root throughout (verifyChain requires it). Refuse to
    // append under a different root, which would corrupt the chain unverifiably.
    const last = this.records[this.records.length - 1];
    if (last && last.org_public_key !== orgPub)
      throw new CountersignError(`cannot append under a different org-root key than the existing registry`);
    const prev = last ? chainHash(last) : null;
    const unsigned = {
      countersign: COUNTERSIGN_VERSION,
      typ,
      actor,
      public_key: publicKey,
      issued_at: new Date().toISOString(),
      prev,
      org_public_key: orgPub,
    };
    const signature = signContext(orgSecret, ENROLL_CONTEXT, canonicalize(unsigned));
    const rec: EnrollmentRecord = { ...unsigned, signature };
    this.records.push(rec);
    return rec;
  }

  /** The current chain head (count + tip hash). Capture and anchor it externally
   *  (a store the registry writer cannot roll back) to detect tail truncation. */
  head(): RegistryHead {
    return { length: this.records.length, hash: this.records.length ? chainHash(this.records[this.records.length - 1]) : REGISTRY_GENESIS };
  }

  /**
   * Verify the whole log against a TRUSTED org-root key: every record is
   * org-signed, all under the same org key, and the hash chain is intact — so an
   * edited, removed, or reordered record is detected. A backward-only chain does
   * NOT by itself detect TAIL TRUNCATION (a valid prefix is a valid log), which
   * would silently resurrect a revoked key. To close that, capture `head()`
   * out-of-band and pass it as `expectedHead`: verification then also requires the
   * log to still contain that many records with the same tip hash at that point.
   */
  verifyChain(orgPublicKey: string, expectedHead?: RegistryHead): boolean {
    let prev: string | null = null;
    for (const rec of this.records) {
      if (rec.org_public_key !== orgPublicKey) return false;
      if (rec.prev !== prev) return false;
      const { signature, ...unsigned } = rec;
      if (typeof signature !== "string" || !verifyContext(orgPublicKey, ENROLL_CONTEXT, canonicalize(unsigned), signature)) return false;
      prev = chainHash(rec);
    }
    if (expectedHead) {
      // The log may have grown (append-only), but must not have been truncated or
      // rolled back below the anchored head.
      if (this.records.length < expectedHead.length) return false;
      const at = expectedHead.length > 0 ? chainHash(this.records[expectedHead.length - 1]) : REGISTRY_GENESIS;
      if (at !== expectedHead.hash) return false;
    }
    return true;
  }

  /** The keys currently ACTIVE (enrolled and not later revoked) for an actor. */
  activeKeys(actor: string): Set<string> {
    const na = normalizeActor(actor);
    const active = new Set<string>();
    for (const rec of this.records) {
      if (normalizeActor(rec.actor) !== na) continue;
      if (rec.typ === "enroll") active.add(rec.public_key);
      else active.delete(rec.public_key);
    }
    return active;
  }
  isActive(actor: string, publicKey: string): boolean {
    return this.activeKeys(actor).has(publicKey);
  }

  /** All currently-active keys grouped by normalized actor, built in ONE pass over the
   *  log — so a multi-approver check is O(records + approvers), not O(records × approvers). */
  activeKeyMap(): Map<string, Set<string>> {
    const map = new Map<string, Set<string>>();
    for (const rec of this.records) {
      const na = normalizeActor(rec.actor);
      let set = map.get(na);
      if (!set) {
        set = new Set<string>();
        map.set(na, set);
      }
      if (rec.typ === "enroll") set.add(rec.public_key);
      else set.delete(rec.public_key);
    }
    return map;
  }
}

/**
 * Strict enrollment check: every KEYED approver in the Intent must have its bound
 * key present as an ACTIVE enrollment for that actor in a registry whose chain
 * verifies under `orgPublicKey`. Throws CountersignError on any mismatch. Compose
 * this before acting on a resolution to require registry-anchored identities.
 *
 * `expectedAuthorityPublicKey` is REQUIRED so this can enforce the Phase 3 trust
 * model's cornerstone: the org-root key MUST be distinct from the runtime
 * authority key. If they were the same key, a compromise of the runtime authority
 * would also let the attacker mint valid enrollment/revocation records for
 * approver keys it controls — anchoring the quorum to keys the authority itself
 * chose, which defeats the whole registry. Reject that configuration up front.
 *
 * Pass `expectedHead` (an externally-anchored `registry.head()`) to also detect
 * tail truncation / rollback — WITHOUT it a dropped `revoke` record can resurrect
 * a revoked key, so a deployment that revokes keys MUST anchor the head.
 */
export function assertApproversEnrolled(
  intent: Intent,
  registry: ApproverRegistry,
  orgPublicKey: string,
  expectedAuthorityPublicKey: string,
  expectedHead?: RegistryHead,
): void {
  // Self-validate the Intent so this holds even when called standalone (its own doc
  // says to compose it with verifyResolution, but don't rely on caller discipline):
  // a malformed/hostile Intent's approvers must never be trusted here either. Verify
  // the agent signature too — like verifyResolution and ReceiptLog.verifyAll do —
  // before trusting the Intent's keyed-approver bindings.
  assertIntentInvariants(intent);
  if (!verifyIntent(intent))
    throw new CountersignError(`intent ${intent.intent_id} does not carry a valid agent signature`);
  if (!isCanonicalPublicKey(expectedAuthorityPublicKey))
    throw new CountersignError("expected authority public key is not a canonical ed25519 key");
  // Both keys must be canonical or the distinctness compare below could be dodged by
  // a non-canonical alias of the authority key passed as the org key (it decodes to
  // the same bytes verifyChain accepts, yet mismatches the `===`).
  if (!isCanonicalPublicKey(orgPublicKey))
    throw new CountersignError("org-root public key is not a canonical ed25519 key");
  if (orgPublicKey === expectedAuthorityPublicKey)
    throw new CountersignError(
      "the approver registry's org-root key must be distinct from the runtime authority key — sharing them collapses the separation of duty the registry provides",
    );
  if (!registry.verifyChain(orgPublicKey, expectedHead))
    throw new CountersignError("approver registry chain, org signature, or anchored head does not verify");
  // Build the active-key map once (single log pass) and look each approver up, rather
  // than rescanning the whole log per approver.
  const active = registry.activeKeyMap();
  for (const a of intent.approvers) {
    if (a.mode !== "keyed") continue;
    if (!a.public_key || !active.get(normalizeActor(a.actor))?.has(a.public_key))
      throw new CountersignError(`keyed approver ${a.actor} is not bound to an active enrollment`);
  }
}
