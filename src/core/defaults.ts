// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { signDecision, verifyCountersignature } from "./countersignature.js";
import { InvalidCountersignatureError } from "./errors.js";
import { publicKeyFromSecret } from "./keys.js";
import type { Countersignature, Intent } from "./types.js";

/** Epoch milliseconds at which the Intent's Default fires. */
export function deadline(intent: Intent): number {
  return Date.parse(intent.created_at) + intent.timeout * 1000;
}

export function isExpired(intent: Intent, now: number = Date.now()): boolean {
  return now >= deadline(intent);
}

/**
 * The Countersignature produced when nobody answered in time: the Intent's
 * declared Default, signed by the enforcing runtime. Silence is never
 * ambiguous — this receipt is as explicit as a human decision.
 */
export function defaultCountersignature(intent: Intent, authoritySecret: string): Countersignature {
  return signDecision(intent, intent.default, "default:timeout", authoritySecret, "default");
}

/**
 * Race a pending decision against the Intent's deadline. Resolves with the
 * adapter's Countersignature if a human decides in time, otherwise with the
 * Default's Countersignature.
 *
 * Whatever comes back is bound to the caller's authority before it is
 * returned: the receipt MUST decide this exact `intent_id` AND be signed by
 * the key derived from `authoritySecret`. This is the choke point that stops
 * a rogue or misconfigured adapter from having a self-signed "approve"
 * accepted — integrity alone is not authority. The adapter that produces
 * decisions therefore MUST sign with the same authority key passed here.
 */
export async function awaitWithDefault(
  intent: Intent,
  decision: Promise<Countersignature>,
  authoritySecret: string,
): Promise<Countersignature> {
  const remaining = deadline(intent) - Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // A late adapter rejection after the Default fires must not crash the process.
  decision.catch(() => {});

  const winner =
    remaining <= 0
      ? defaultCountersignature(intent, authoritySecret)
      : await Promise.race([
          decision,
          new Promise<Countersignature>((resolve) => {
            timer = setTimeout(() => resolve(defaultCountersignature(intent, authoritySecret)), remaining);
          }),
        ]).finally(() => clearTimeout(timer));

  if (winner.intent_id !== intent.intent_id)
    throw new InvalidCountersignatureError(
      `Countersignature intent_id ${winner.intent_id} does not match intent ${intent.intent_id}`,
    );
  const expectedAuthority = publicKeyFromSecret(authoritySecret);
  if (!verifyCountersignature(winner, { trustedKeys: expectedAuthority }))
    throw new InvalidCountersignatureError(
      `Countersignature for ${intent.intent_id} was not signed by the expected authority ` +
        `(got ${winner.public_key}); the decision adapter must share the runtime's authority key`,
    );
  return winner;
}
