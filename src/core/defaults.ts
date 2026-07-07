// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { signDecision, verifyCountersignature } from "./countersignature.js";
import { InvalidCountersignatureError } from "./errors.js";
import { quorumOf } from "./intent.js";
import { publicKeyFromSecret } from "./keys.js";
import type { Intent, Resolution } from "./types.js";

/** Epoch milliseconds at which the Intent's Default fires. */
export function deadline(intent: Intent): number {
  return Date.parse(intent.created_at) + intent.timeout * 1000;
}

export function isExpired(intent: Intent, now: number = Date.now()): boolean {
  return now >= deadline(intent);
}

/**
 * The Resolution produced when nobody completed the quorum in time: the
 * Intent's declared Default, signed by the enforcing runtime. Silence is
 * never ambiguous — this receipt is as explicit as a human decision.
 */
export function defaultResolution(intent: Intent, authoritySecret: string): Resolution {
  return {
    decision: intent.default,
    policy: "default",
    countersignatures: [signDecision(intent, intent.default, "default:timeout", authoritySecret, "default")],
  };
}

/**
 * Independently validate a Resolution before it is acted on. Never trusts the
 * producer's word: every receipt must decide this exact `intent_id` and be
 * signed by the expected authority, and an `approve` resolution must be backed
 * by `quorum` DISTINCT approvers whose receipts all say `approve`. Throws
 * InvalidCountersignatureError on any failure.
 */
export function verifyResolution(intent: Intent, resolution: Resolution, expectedAuthorityPublicKey: string): void {
  const receipts = resolution.countersignatures;
  if (!Array.isArray(receipts) || receipts.length === 0)
    throw new InvalidCountersignatureError(`resolution for ${intent.intent_id} carries no receipts`);

  for (const cs of receipts) {
    if (cs.intent_id !== intent.intent_id)
      throw new InvalidCountersignatureError(
        `receipt intent_id ${cs.intent_id} does not match intent ${intent.intent_id}`,
      );
    if (!verifyCountersignature(cs, { trustedKeys: expectedAuthorityPublicKey }))
      throw new InvalidCountersignatureError(
        `a receipt for ${intent.intent_id} was not signed by the expected authority (got ${cs.public_key})`,
      );
  }

  if (resolution.decision === "approve") {
    // Re-derive the quorum from the receipts; do not trust an asserted count.
    const distinctApprovers = new Set<string>();
    for (const cs of receipts) {
      if (cs.decision !== "approve")
        throw new InvalidCountersignatureError(
          `approve resolution for ${intent.intent_id} contains a non-approve receipt`,
        );
      distinctApprovers.add(cs.actor);
    }
    const need = quorumOf(intent);
    if (distinctApprovers.size < need)
      throw new InvalidCountersignatureError(
        `approve resolution for ${intent.intent_id} has ${distinctApprovers.size} distinct approver(s), needs ${need}`,
      );
  }
}

/**
 * Race a pending resolution against the Intent's deadline. Resolves with the
 * adapter's Resolution if the Intent resolves in time (quorum approvals or a
 * veto), otherwise with the Default's Resolution.
 *
 * Whatever comes back is bound to the caller's authority before it is
 * returned (see verifyResolution): every receipt MUST decide this exact
 * `intent_id` and be signed by the key derived from `authoritySecret`, and an
 * `approve` MUST be backed by `quorum` distinct approvers. This is the choke
 * point that stops a rogue or misconfigured adapter from having a self-signed
 * or under-quorum "approve" accepted — integrity alone is not authority. The
 * adapter that produces decisions therefore MUST sign with the same authority
 * key passed here.
 */
export async function awaitWithDefault(
  intent: Intent,
  resolution: Promise<Resolution>,
  authoritySecret: string,
): Promise<Resolution> {
  const remaining = deadline(intent) - Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // A late adapter rejection after the Default fires must not crash the process.
  resolution.catch(() => {});

  const winner =
    remaining <= 0
      ? defaultResolution(intent, authoritySecret)
      : await Promise.race([
          resolution,
          new Promise<Resolution>((resolve) => {
            timer = setTimeout(() => resolve(defaultResolution(intent, authoritySecret)), remaining);
          }),
        ]).finally(() => clearTimeout(timer));

  verifyResolution(intent, winner, publicKeyFromSecret(authoritySecret));
  return winner;
}
