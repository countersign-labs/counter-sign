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
import { isCanonicalPublicKey, publicKeyFromSecret, signContext, verifyContext } from "./core/keys.js";
import { isValidCredentialDescriptor } from "./core/webauthn.js";
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
      .map((l) => JSON.parse(l) as EnrollmentRecord);
    return reg;
  }
  toJSONL(): string {
    return this.records.map((r) => JSON.stringify(r)).join("\n") + (this.records.length ? "\n" : "");
  }
  get all(): readonly EnrollmentRecord[] {
    return this.records;
  }

  /**
   * Enroll an approver key, attested by the org-root key. A RAW ed25519 key
   * REQUIRES a valid proof of possession (createEnrollmentProof). A passkey
   * descriptor is accepted as-is (it originates from a WebAuthn registration
   * ceremony that already proved possession). Fails closed on a malformed key,
   * a missing/invalid PoP, or an already-active binding.
   */
  enroll(actor: string, publicKey: string, orgSecret: string, opts: { pop?: string } = {}): EnrollmentRecord {
    const isRaw = isCanonicalPublicKey(publicKey);
    if (!isRaw && !isValidCredentialDescriptor(publicKey))
      throw new CountersignError(`cannot enroll ${actor}: malformed or non-canonical public_key`);
    if (isRaw) {
      if (!opts.pop || !verifyContext(publicKey, ENROLL_POP_CONTEXT, popMessage(actor, publicKey), opts.pop))
        throw new CountersignError(`cannot enroll ${actor}: missing or invalid proof of possession`);
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
}

/**
 * Strict enrollment check: every KEYED approver in the Intent must have its bound
 * key present as an ACTIVE enrollment for that actor in a registry whose chain
 * verifies under `orgPublicKey`. Throws CountersignError on any mismatch. Compose
 * this before acting on a resolution to require registry-anchored identities.
 *
 * Pass `expectedHead` (an externally-anchored `registry.head()`) to also detect
 * tail truncation / rollback — WITHOUT it a dropped `revoke` record can resurrect
 * a revoked key, so a deployment that revokes keys MUST anchor the head.
 */
export function assertApproversEnrolled(
  intent: Intent,
  registry: ApproverRegistry,
  orgPublicKey: string,
  expectedHead?: RegistryHead,
): void {
  if (!registry.verifyChain(orgPublicKey, expectedHead))
    throw new CountersignError("approver registry chain, org signature, or anchored head does not verify");
  for (const a of intent.approvers) {
    if (a.mode !== "keyed") continue;
    if (!a.public_key || !registry.isActive(a.actor, a.public_key))
      throw new CountersignError(`keyed approver ${a.actor} is not bound to an active enrollment`);
  }
}
