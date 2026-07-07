// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { canonicalize } from "./canonical.js";
import { publicKeyFromSecret, signContext, verifyContext } from "./keys.js";
import {
  COUNTERSIGN_VERSION,
  COUNTERSIGNATURE_CONTEXT,
  type Countersignature,
  type Decision,
  type Intent,
  type Policy,
} from "./types.js";

export interface VerifyOptions {
  /**
   * The authority key(s) the verifier trusts for this Route. When provided,
   * verification additionally requires that the receipt was signed by one of
   * them — closing the gap where a self-signed receipt is "valid" but carries
   * no authority. STRONGLY recommended for any party acting on a receipt.
   */
  trustedKeys?: readonly string[] | string;
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
): Countersignature {
  const unsigned = {
    countersign: COUNTERSIGN_VERSION,
    intent_id: intent.intent_id,
    decision,
    actor,
    policy,
    timestamp: new Date().toISOString(),
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
    const { signature, ...unsigned } = cs;
    if (typeof signature !== "string" || typeof cs.public_key !== "string") return false;
    if (opts.trustedKeys !== undefined) {
      const trusted = typeof opts.trustedKeys === "string" ? [opts.trustedKeys] : opts.trustedKeys;
      if (!trusted.includes(cs.public_key)) return false;
    }
    return verifyContext(cs.public_key, COUNTERSIGNATURE_CONTEXT, canonicalize(unsigned), signature);
  } catch {
    return false;
  }
}
