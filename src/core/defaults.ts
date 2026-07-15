// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { normalizeActor, signDecision, verifyCountersignature } from "./countersignature.js";
import { InvalidCountersignatureError } from "./errors.js";
import { assertIntentInvariants, quorumOf, verifyIntent } from "./intent.js";
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
  // A multi-person quorum always fails closed on timeout: silence must never
  // authorize an action that required distinct approvers, even if a
  // non-conforming Intent declared default: approve.
  const decision = quorumOf(intent) > 1 ? "reject" : intent.default;
  return {
    decision,
    policy: "default",
    countersignatures: [signDecision(intent, decision, "default:timeout", authoritySecret, "default")],
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
  // The Intent we authorize against must itself be structurally sound and
  // agent-signed — never act on a resolution for a malformed or forged Intent.
  assertIntentInvariants(intent);
  if (!verifyIntent(intent))
    throw new InvalidCountersignatureError(`intent ${intent.intent_id} does not carry a valid agent signature`);

  const receipts = resolution?.countersignatures;
  if (!Array.isArray(receipts) || receipts.length === 0)
    throw new InvalidCountersignatureError(`resolution for ${intent.intent_id} carries no receipts`);
  if (resolution.decision !== "approve" && resolution.decision !== "reject")
    throw new InvalidCountersignatureError(`resolution for ${intent.intent_id} has invalid decision ${JSON.stringify(resolution.decision)}`);

  for (const cs of receipts) {
    if (cs.intent_id !== intent.intent_id)
      throw new InvalidCountersignatureError(
        `receipt intent_id ${cs.intent_id} does not match intent ${intent.intent_id}`,
      );
    if (!verifyCountersignature(cs, { trustedKeys: expectedAuthorityPublicKey }))
      throw new InvalidCountersignatureError(
        `a receipt for ${intent.intent_id} was not signed by the expected authority (got ${cs.public_key})`,
      );
    // Every receipt's OWN decision must match the resolution's claimed decision,
    // so a set of `reject` receipts (e.g. the public timeout receipt) can never
    // be presented as an `approve`.
    if (cs.decision !== resolution.decision)
      throw new InvalidCountersignatureError(
        `a receipt for ${intent.intent_id} says ${cs.decision} but the resolution claims ${resolution.decision}`,
      );
  }

  // An `approve` is justified in EXACTLY two ways, and the check NEVER branches
  // on the attacker-supplied `resolution.policy` to decide whether to run — it
  // branches only to decide WHICH of the two proofs is required, and rejects any
  // other policy. (Formerly, policy:"default" skipped quorum entirely.)
  if (resolution.decision === "approve") {
    if (resolution.policy === "approver") {
      // A human quorum: `quorum` DISTINCT approvers, each of whom MUST be named in
      // the Intent's signed `approvers` allowlist. Without this, any actor the
      // trusted authority vouches for (e.g. any member of the delivery channel)
      // could satisfy quorum — the signed `approvers` field would be decorative.
      const allow = new Set(intent.approvers.map(normalizeActor));
      const distinct = new Set<string>();
      for (const cs of receipts) {
        const actor = normalizeActor(cs.actor);
        if (!allow.has(actor))
          throw new InvalidCountersignatureError(
            `approve resolution for ${intent.intent_id} has a receipt from ${cs.actor}, who is not in the Intent's approvers`,
          );
        distinct.add(actor);
      }
      const need = quorumOf(intent);
      if (distinct.size < need)
        throw new InvalidCountersignatureError(
          `approve resolution for ${intent.intent_id} has ${distinct.size} distinct approver(s), needs ${need}`,
        );
    } else if (resolution.policy === "default") {
      // The declared timeout Default — legitimate ONLY for a single-approver
      // Intent that declares default:"approve", evidenced by exactly one
      // default:timeout receipt. Anything else is an attempt to smuggle an
      // approval past the quorum requirement.
      if (quorumOf(intent) !== 1 || intent.default !== "approve")
        throw new InvalidCountersignatureError(
          `a default:approve resolution for ${intent.intent_id} is only valid for a quorum-1 Intent that declares default:"approve"`,
        );
      if (receipts.length !== 1 || receipts[0].policy !== "default" || normalizeActor(receipts[0].actor) !== "default:timeout")
        throw new InvalidCountersignatureError(
          `a default:approve resolution for ${intent.intent_id} must be exactly one default:timeout receipt`,
        );
    } else {
      throw new InvalidCountersignatureError(
        `approve resolution for ${intent.intent_id} has an unrecognized policy ${JSON.stringify(resolution.policy)}`,
      );
    }
  }
}

/**
 * Race a pending resolution against the Intent's deadline. Resolves with the
 * adapter's Resolution if the Intent resolves in time (quorum approvals or a
 * veto), otherwise with the Default's Resolution.
 *
 * Whatever comes back is bound to the caller's authority before it is
 * returned (see verifyResolution): the Intent must be valid and agent-signed,
 * every receipt MUST decide this exact `intent_id`, be signed by the key derived
 * from `authoritySecret`, and carry the resolution's own decision; an `approve`
 * MUST be backed by `quorum` distinct approvers (or be the narrow quorum-1
 * timeout Default). This choke point stops an under-quorum, wrong-key,
 * decision-mismatched, or policy-mislabelled "approve" from being accepted —
 * integrity alone is not authority.
 *
 * It does NOT provide separation of duty against the authority key itself:
 * distinctness is over `actor` strings the authority vouches for, so a holder of
 * that key can still mint `quorum` distinct receipts. The adapter that produces
 * decisions MUST sign with the same authority key passed here, and MUST be
 * trusted to map real humans to actors. See the spec §1 "Trust model".
 */
export async function awaitWithDefault(
  intent: Intent,
  resolution: Promise<Resolution>,
  authoritySecret: string,
): Promise<Resolution> {
  // Validate BEFORE computing a deadline: a NaN/huge created_at or timeout on a
  // wire Intent would otherwise collapse the review window (setTimeout(NaN) fires
  // immediately), silently erasing the human veto. Fail closed on a bad Intent.
  assertIntentInvariants(intent);

  // Guard the adapter's resolution at the CORE level — not only in the shipped
  // PendingDecisions helper — so the deadline rule holds for ANY Adapter: a
  // decision OBSERVED at/after the deadline is discarded in favor of the Default,
  // so a late resolution (e.g. an adapter whose timer is overdue after an
  // event-loop stall) can never beat the timeout. A rejected adapter promise
  // never wins the race; the Default timer decides.
  const guarded: Promise<Resolution> = resolution.then(
    (r) => (Date.now() >= deadline(intent) ? defaultResolution(intent, authoritySecret) : r),
    () => new Promise<Resolution>(() => {}),
  );

  const remaining = deadline(intent) - Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;

  const winner =
    remaining <= 0
      ? defaultResolution(intent, authoritySecret)
      : await Promise.race([
          guarded,
          new Promise<Resolution>((resolve) => {
            timer = setTimeout(() => resolve(defaultResolution(intent, authoritySecret)), remaining);
          }),
        ]).finally(() => clearTimeout(timer));

  verifyResolution(intent, winner, publicKeyFromSecret(authoritySecret));
  return winner;
}
