// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { publicKeyFromSecret, signContext, toB64url, utf8, verifyContext } from "./keys.js";
import { isWebAuthnCredential, verifyWebAuthnAssertion, type WebAuthnPolicy } from "./webauthn.js";
import {
  COUNTERSIGN_VERSION,
  COUNTERSIGNATURE_CONTEXT,
  type Countersignature,
  type Decision,
  type Intent,
  type Policy,
} from "./types.js";

/**
 * Canonical form of an `actor` for distinct-approver counting. Raw-string
 * equality lets one human masquerade as several ("alice", "alice ", "Alice",
 * or NFC/NFD twins) and fill a multi-person quorum alone. We fold Unicode (NFC),
 * trim, and casefold: for every shipped channel the address part is numeric
 * (Discord/Telegram-id/WhatsApp) or case-assigned-unique (Slack IDs, email), so
 * casefolding never merges two genuinely distinct approvers — it only defeats
 * case-variant spoofing. Adapters must still key on STABLE ids (never a mutable
 * username) so the identity itself can't be swapped between approvals.
 */
export function normalizeActor(actor: string): string {
  return String(actor).normalize("NFC").trim().toLowerCase();
}

export interface VerifyOptions {
  /**
   * The authority key(s) the verifier trusts for this Route. When provided,
   * verification additionally requires that the receipt was signed by one of
   * them — closing the gap where a self-signed receipt is "valid" but carries
   * no authority. STRONGLY recommended for any party acting on a receipt.
   */
  trustedKeys?: readonly string[] | string;
  /**
   * Deployment policy for verifying passkey (WebAuthn) receipts. REQUIRED to
   * verify a receipt whose `public_key` is a passkey descriptor — without it a
   * passkey receipt cannot be verified and fails closed.
   */
  webauthn?: WebAuthnPolicy;
}

/**
 * Produce a signed Countersignature over an Intent. `authoritySecret` is
 * the base64url ed25519 seed of whoever vouches for the decision — an
 * adapter acting on a human's button press, or the runtime firing a Default.
 */
export function signDecision(
  intent: Intent,
  decision: Decision,
  actor: string,
  authoritySecret: string,
  policy: Policy = "approver",
  /**
   * ISO 8601 time the decision was made. Defaults to now. The timeout Default
   * overrides this with the deadline itself, so its receipt is never stamped
   * before the window it represents even if the wall clock has drifted back.
   */
  timestamp: string = new Date().toISOString(),
): Countersignature {
  const unsigned = {
    countersign: COUNTERSIGN_VERSION,
    intent_id: intent.intent_id,
    decision,
    actor,
    policy,
    timestamp,
    public_key: publicKeyFromSecret(authoritySecret),
  };
  const signature = signContext(authoritySecret, COUNTERSIGNATURE_CONTEXT, canonicalize(unsigned));
  return { ...unsigned, signature };
}

/**
 * Verify a Countersignature.
 *
 * With no options this checks INTEGRITY only: that the embedded `public_key`
 * signed the canonical receipt. Integrity alone is NOT authority — anyone can
 * mint an integrity-valid receipt with their own key. To act on a receipt,
 * pass `trustedKeys` so verification also proves the receipt was signed by an
 * authority you trust for this Route.
 */
export function verifyCountersignature(cs: Countersignature, opts: VerifyOptions = {}): boolean {
  try {
    const { signature, webauthn, ...unsigned } = cs;
    if (typeof signature !== "string" || typeof cs.public_key !== "string") return false;
    if (opts.trustedKeys !== undefined) {
      const trusted = typeof opts.trustedKeys === "string" ? [opts.trustedKeys] : opts.trustedKeys;
      if (!trusted.includes(cs.public_key)) return false;
    }
    const passkey = isWebAuthnCredential(cs.public_key);
    if (passkey || webauthn !== undefined) {
      // Passkey (WebAuthn) receipt: the signature is an authenticator assertion,
      // not a plain ed25519 signature over the receipt. A webauthn block with a
      // non-passkey key (or vice versa) is malformed → reject. Without an RP
      // policy a passkey receipt cannot be verified → fail closed.
      if (!passkey || !webauthn || typeof webauthn !== "object" || !opts.webauthn) return false;
      // The assertion binds to THIS decision via challenge = digest of the
      // canonical receipt (minus signature and webauthn), domain-separated.
      const challenge = toB64url(
        createHash("sha256").update(utf8(`${COUNTERSIGNATURE_CONTEXT}\n${canonicalize(unsigned)}`)).digest(),
      );
      return verifyWebAuthnAssertion(webauthn, signature, {
        credential: cs.public_key,
        expectedChallenge: challenge,
        rpId: opts.webauthn.rpId,
        allowedOrigins: opts.webauthn.allowedOrigins,
        requireUserVerification: opts.webauthn.requireUserVerification,
      });
    }
    return verifyContext(cs.public_key, COUNTERSIGNATURE_CONTEXT, canonicalize(unsigned), signature);
  } catch {
    return false;
  }
}
