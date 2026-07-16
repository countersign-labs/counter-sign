// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { normalizeActor, signDecision, verifyCountersignature } from "./countersignature.js";
import { CountersignError, InvalidCountersignatureError } from "./errors.js";
import { assertIntentInvariants, quorumOf, verifyIntent } from "./intent.js";
import { isCanonicalPublicKey, publicKeyFromSecret } from "./keys.js";
import { credentialKeyMaterial } from "./webauthn.js";
import type { WebAuthnPolicy } from "./webauthn.js";
import type { Approver, Intent, Resolution } from "./types.js";

/** Node's setTimeout ceiling (2^31-1 ms ≈ 24.8 days); larger delays clamp to ~1 ms. */
const MAX_TIMER_MS = 2_147_483_647;
/** Reserved actor for the runtime's timeout Default; never a human approver. */
export const DEFAULT_TIMEOUT_ACTOR = "default:timeout";

/** Epoch milliseconds at which the Intent's Default fires. */
export function deadline(intent: Intent): number {
  return Date.parse(intent.created_at) + intent.timeout * 1000;
}

export function isExpired(intent: Intent, now: number = Date.now()): boolean {
  return now >= deadline(intent);
}

/**
 * Mint the timeout Default receipt — the Resolution produced when nobody
 * completed the quorum in time: the Intent's declared Default, signed by the
 * enforcing runtime. Silence is never ambiguous; this receipt is as explicit
 * as a human decision.
 *
 * INTERNAL: the caller MUST have already
 * established that the deadline is reached (the runtime timer fired, or the
 * Intent was observed already-expired). It performs no wall-clock check, so it
 * never throws on the honest timeout path — the timer firing is the
 * authoritative "deadline reached" signal, robust to a wall clock that has
 * stepped backward relative to the monotonic timer after scheduling.
 *
 * The receipt is stamped at `max(now, deadline)`, never before the deadline it
 * represents: a Default fires AT the deadline, so even if the wall clock reads
 * earlier (NTP step-back, VM resume), the record is honest and passes the
 * `verifyResolution` timestamp gate.
 */
function mintDefault(intent: Intent, authoritySecret: string): Resolution {
  // A multi-person quorum always fails closed on timeout: silence must never
  // authorize an action that required distinct approvers, even if a
  // non-conforming Intent declared default: approve.
  const decision = quorumOf(intent) > 1 ? "reject" : intent.default;
  const stamp = new Date(Math.max(Date.now(), deadline(intent))).toISOString();
  return {
    decision,
    policy: "default",
    countersignatures: [signDecision(intent, decision, "default:timeout", authoritySecret, "default", stamp)],
  };
}

/**
 * The timeout Default as a signed Resolution. Refuses to mint before the
 * deadline (fail closed): an early Default would fabricate a timeout that has
 * not happened — a false "nobody responded" record, or an approval before the
 * review window closed. The enforcing runtime's own timer path mints via the
 * internal `mintDefault` instead, so this guard protects EXTERNAL callers
 * without being able to throw on the honest timeout path.
 */
export function defaultResolution(intent: Intent, authoritySecret: string): Resolution {
  // Validate first (fail closed): a malformed created_at/timeout makes deadline() NaN,
  // so the `Date.now() < deadline` guard is false and mintDefault would hit
  // `new Date(NaN).toISOString()` → uncaught RangeError. External callers must get the
  // documented CountersignError instead. (awaitWithDefault already validates up front.)
  assertIntentInvariants(intent);
  if (Date.now() < deadline(intent))
    throw new CountersignError(`intent ${intent.intent_id} has not reached its deadline — the Default cannot fire early`);
  return mintDefault(intent, authoritySecret);
}

/**
 * Independently validate a Resolution before it is acted on. Never trusts the
 * producer's word: every receipt must decide this exact `intent_id` and be
 * signed by the expected authority; an `approve` must be backed by `quorum`
 * DISTINCT approvers whose receipts all say `approve`; a `reject` must come
 * from a listed approver too (a veto is authority as much as an approval) or
 * be the canonical timeout Default. Throws InvalidCountersignatureError on
 * any failure.
 */
export function verifyResolution(
  intent: Intent,
  resolution: Resolution,
  expectedAuthorityPublicKey: string,
  webauthn?: WebAuthnPolicy,
): void {
  // The Intent we authorize against must itself be structurally sound and
  // agent-signed — never act on a resolution for a malformed or forged Intent.
  assertIntentInvariants(intent);
  if (!verifyIntent(intent))
    throw new InvalidCountersignatureError(`intent ${intent.intent_id} does not carry a valid agent signature`);

  // The expected authority key must be canonical, or the equality checks below
  // (against the agent key and each keyed approver's key) could be bypassed by a
  // non-canonical base64url alias that decodes to the same key — a verifier
  // configured with such an alias would let a slot bound to the *canonical*
  // authority key slip through. Approver/agent keys are already required canonical.
  if (!isCanonicalPublicKey(expectedAuthorityPublicKey))
    throw new InvalidCountersignatureError(`expected authority public key is not a canonical ed25519 key`);

  // Separation of duty starts with the Intent's author: the agent key binds each
  // approver's key into the signed Intent, so if it equals the authority key a
  // holder of the authority secret could mint a fresh Intent binding approver keys
  // it controls and then sign every keyed slot with them — forging a whole quorum.
  // The spec requires the agent and authority keys be distinct; enforce it here,
  // where both public keys are in hand. (For a vouched flow it likewise collapses
  // the author/relayer separation.)
  if (intent.agent?.public_key === expectedAuthorityPublicKey)
    throw new InvalidCountersignatureError(
      `intent ${intent.intent_id} was authored by the authority key — the agent and authority keys must be distinct`,
    );

  const receipts = resolution?.countersignatures;
  if (!Array.isArray(receipts) || receipts.length === 0)
    throw new InvalidCountersignatureError(`resolution for ${intent.intent_id} carries no receipts`);
  if (resolution.decision !== "approve" && resolution.decision !== "reject")
    throw new InvalidCountersignatureError(`resolution for ${intent.intent_id} has invalid decision ${JSON.stringify(resolution.decision)}`);

  // Structural checks shared by every receipt: identity and decision consistency.
  // Signature verification is done PER RECEIPT below, against the key its
  // approver's MODE requires — the authority key for a `vouched` receipt (or the
  // Default), the approver's OWN bound key for a `keyed` receipt. A blanket
  // authority-key check here would be wrong now that keyed receipts exist.
  for (const cs of receipts) {
    if (cs.intent_id !== intent.intent_id)
      throw new InvalidCountersignatureError(
        `receipt intent_id ${cs.intent_id} does not match intent ${intent.intent_id}`,
      );
    // Every receipt's OWN decision must match the resolution's claimed decision,
    // so a set of `reject` receipts (e.g. the public timeout receipt) can never
    // be presented as an `approve`.
    if (cs.decision !== resolution.decision)
      throw new InvalidCountersignatureError(
        `a receipt for ${intent.intent_id} says ${cs.decision} but the resolution claims ${resolution.decision}`,
      );
  }

  // A resolution — approve OR reject — is justified in EXACTLY two ways, and
  // the check NEVER branches on the attacker-supplied `resolution.policy` to
  // decide whether to run — it branches only to decide WHICH of the two proofs
  // is required, and rejects any other policy. (Formerly only `approve` was
  // policy-checked, so an authority-signed reject from an actor outside the
  // allowlist — or under an unknown policy — could veto any operation.)
  if (resolution.policy === "approver") {
    // Human decisions: EVERY receipt's actor MUST be named in the Intent's signed
    // `approvers` allowlist, and each receipt is verified against the key its
    // approver's MODE requires. A `keyed` approver's receipt must be signed by
    // their OWN bound key — the authority key cannot forge it, which is the
    // cryptographic separation of duty; a `vouched` receipt by the authority key.
    // `default:timeout` is reserved and can never be a human approver.
    const byActor = new Map<string, Approver>();
    for (const a of intent.approvers) {
      const na = normalizeActor(a.actor);
      if (na !== DEFAULT_TIMEOUT_ACTOR) byActor.set(na, a);
    }
    const distinct = new Set<string>();
    for (const cs of receipts) {
      // Resolution.policy is unsigned wrapper metadata. Bind this proof to the
      // receipt's signed policy so a Default receipt cannot be relabelled as a
      // human approval or veto.
      if (cs.policy !== "approver")
        throw new InvalidCountersignatureError(
          `${resolution.decision} resolution for ${intent.intent_id} has a receipt whose signed policy is ${JSON.stringify(cs.policy)}, not "approver"`,
        );
      const actor = normalizeActor(cs.actor);
      if (actor === DEFAULT_TIMEOUT_ACTOR)
        throw new InvalidCountersignatureError(
          `${resolution.decision} resolution for ${intent.intent_id} uses reserved actor default:timeout as an approver`,
        );
      const approver = byActor.get(actor);
      if (!approver)
        throw new InvalidCountersignatureError(
          `${resolution.decision} resolution for ${intent.intent_id} has a receipt from ${cs.actor}, who is not in the Intent's approvers`,
        );
      let trustedKey: string;
      if (approver.mode === "keyed") {
        if (!approver.public_key)
          throw new InvalidCountersignatureError(`keyed approver ${cs.actor} for ${intent.intent_id} has no bound key`);
        // A keyed slot must belong to the approver, not the authority — binding the
        // authority key here would let the authority-key holder forge that slot,
        // silently degrading separation of duty. See through a WebAuthn wrapper:
        // `webauthn-ed25519:<authority-key>` is still the authority key.
        if (credentialKeyMaterial(approver.public_key) === expectedAuthorityPublicKey)
          throw new InvalidCountersignatureError(
            `keyed approver ${cs.actor} for ${intent.intent_id} is bound to the authority key — a keyed slot must be the approver's own key`,
          );
        trustedKey = approver.public_key;
      } else {
        trustedKey = expectedAuthorityPublicKey;
      }
      if (!verifyCountersignature(cs, { trustedKeys: trustedKey, webauthn }))
        throw new InvalidCountersignatureError(
          `a ${approver.mode} receipt from ${cs.actor} for ${intent.intent_id} was not signed by the expected key (got ${cs.public_key})`,
        );
      distinct.add(actor);
    }
    // An approve additionally needs a full quorum of DISTINCT approvers; a
    // single listed approver's reject is a complete veto.
    if (resolution.decision === "approve") {
      const need = quorumOf(intent);
      if (distinct.size < need)
        throw new InvalidCountersignatureError(
          `approve resolution for ${intent.intent_id} has ${distinct.size} distinct approver(s), needs ${need}`,
        );
    }
  } else if (resolution.policy === "default") {
    // The declared timeout Default — evidenced by exactly one default:timeout
    // receipt whose decision matches what defaultResolution would produce:
    // reject for a multi-person quorum (fail closed), the Intent's declared
    // `default` otherwise. Anything else smuggles a decision past the declared
    // Default — an approve past the quorum requirement, or a reject (a forged
    // veto) past a default:"approve" window.
    const expected = quorumOf(intent) > 1 ? "reject" : intent.default;
    if (resolution.decision !== expected)
      throw new InvalidCountersignatureError(
        `a default:${resolution.decision} resolution for ${intent.intent_id} contradicts the Intent's Default (${expected})`,
      );
    if (receipts.length !== 1 || receipts[0].policy !== "default" || normalizeActor(receipts[0].actor) !== "default:timeout")
      throw new InvalidCountersignatureError(
        `a default resolution for ${intent.intent_id} must be exactly one default:timeout receipt`,
      );
    // The timeout Default is minted by the enforcing runtime, so it must be signed
    // by the authority key (never an approver key).
    if (!verifyCountersignature(receipts[0], { trustedKeys: expectedAuthorityPublicKey }))
      throw new InvalidCountersignatureError(
        `the timeout Default for ${intent.intent_id} was not signed by the expected authority (got ${receipts[0].public_key})`,
      );
    // The Default fires AT the deadline, so its signed timestamp can never
    // precede it. Without this, an early-minted "timeout" receipt verifies —
    // a false timeout audit record, or an approval before the review window
    // closed. The negated comparison also fails an unparseable timestamp.
    if (!(Date.parse(receipts[0].timestamp) >= deadline(intent)))
      throw new InvalidCountersignatureError(
        `a default resolution for ${intent.intent_id} is timestamped before the Intent's deadline — the Default cannot fire early`,
      );
  } else {
    throw new InvalidCountersignatureError(
      `resolution for ${intent.intent_id} has an unrecognized policy ${JSON.stringify(resolution.policy)}`,
    );
  }
}

/**
 * Race a pending resolution against the Intent's deadline. Resolves with the
 * adapter's Resolution if the Intent resolves in time (quorum approvals or a
 * veto), otherwise with the Default's Resolution.
 *
 * Whatever comes back is bound to the caller's authority before it is
 * returned (see verifyResolution): the Intent must be valid and agent-signed,
 * every receipt MUST decide this exact `intent_id`, carry the resolution's own
 * decision, and be signed by the key its approver's MODE requires — the authority
 * key (from `authoritySecret`) for a `vouched` receipt or the timeout Default,
 * the approver's OWN bound key for a `keyed` receipt. An `approve` MUST be backed
 * by `quorum` distinct approvers (or be the narrow quorum-1 timeout Default), and
 * a `reject` MUST come from a listed approver or be the canonical timeout Default.
 *
 * For a `keyed` quorum (required when `quorum > 1`), this DOES provide
 * cryptographic separation of duty against the authority key: keyed receipts are
 * signed by approver keys the authority never holds, so a holder of the authority
 * key cannot forge the quorum. The residual trust is the agent key (which binds
 * each approver's key into the signed Intent, and MUST be distinct from the
 * authority key) and the source of those keys. See the spec §1 "Trust model".
 */
export async function awaitWithDefault(
  intent: Intent,
  resolution: Promise<Resolution>,
  authoritySecret: string,
  webauthn?: WebAuthnPolicy,
): Promise<Resolution> {
  // Consume the caller's adapter promise unconditionally as a safety net, BEFORE
  // any check that can throw: a rejecting adapter must NEVER leak as an unhandled
  // rejection (a process crash on modern Node) if a synchronous check below throws
  // before the promise is wired into the race. assertIntentInvariants can now throw
  // on a malformed agent identity too, so this MUST come first. The real handling
  // still happens in `guarded`.
  void resolution.catch(() => {});

  // Validate BEFORE computing a deadline: a NaN/huge created_at or timeout on a
  // wire Intent would otherwise collapse the review window (setTimeout(NaN) fires
  // immediately), silently erasing the human veto. Fail closed on a bad Intent.
  assertIntentInvariants(intent);

  // Compute the deadline window and reject a far-future Intent BEFORE wiring up
  // `guarded`: its CS-28 rejection handler can throw, so orphaning it here (by
  // failing closed after it was created) would surface as an unhandled rejection.
  const remaining = deadline(intent) - Date.now();
  // A far-future (but parseable) created_at makes `remaining` exceed Node's timer
  // ceiling; setTimeout would clamp it to ~1 ms and fire the Default immediately,
  // collapsing the review window (an auto-approve for default:"approve"). No
  // legitimate window is that long — timeout is bounded to ~24.8 days — so refuse.
  if (remaining > MAX_TIMER_MS)
    throw new CountersignError(`intent ${intent.intent_id} has an implausibly far-future deadline`);

  // Guard the adapter's resolution at the CORE level — not only in the shipped
  // PendingDecisions helper — so the deadline rule holds for ANY Adapter: a
  // decision OBSERVED at/after the deadline is discarded in favor of the Default,
  // so a late resolution (e.g. an adapter whose timer is overdue after an
  // event-loop stall) can never beat the timeout. A rejected adapter promise
  // never wins the race; the Default timer decides.
  const expectedAuthorityPublicKey = publicKeyFromSecret(authoritySecret);
  // What the runtime itself would decide at the deadline — a multi-person quorum
  // always fails closed to reject, otherwise the Intent's declared Default.
  const expectedDefaultDecision: "approve" | "reject" = quorumOf(intent) > 1 ? "reject" : intent.default;
  const guarded: Promise<Resolution> = resolution.then(
    (r) => {
      if (Date.now() >= deadline(intent)) return mintDefault(intent, authoritySecret);
      // An adapter delivering a Default before the deadline is discarded so the
      // runtime's own timer mints the genuine one on time. Recognise that ONLY
      // when the receipt is EXACTLY what the runtime would mint at the deadline:
      // a single default:timeout receipt for this intent, signed by the expected
      // authority, whose decision matches the Intent's own Default. Never trust
      // an unverified `policy` field, and never discard a receipt that merely
      // looks default-shaped but CONTRADICTS the Default (wrong decision) or is
      // forged/foreign — that would let a bogus "default" suppress the real
      // decision and hand the timer an approval (CS-26, CS-28). Anything that is
      // not an authenticated, decision-consistent Default falls through to
      // verifyResolution and fails closed. This also ignores the attacker-set
      // Resolution.policy wrapper entirely (CS-24).
      const receipts = (r as Resolution | null)?.countersignatures;
      const isEarlyDefaultDelivery =
        Array.isArray(receipts) &&
        receipts.length === 1 &&
        receipts[0]?.policy === "default" &&
        receipts[0].decision === expectedDefaultDecision &&
        receipts[0].intent_id === intent.intent_id &&
        normalizeActor(receipts[0].actor) === DEFAULT_TIMEOUT_ACTOR &&
        verifyCountersignature(receipts[0], { trustedKeys: expectedAuthorityPublicKey });
      if (isEarlyDefaultDelivery) return new Promise<Resolution>(() => {});
      return r;
    },
    (err) => {
      // An adapter ERROR is not silence. Before the deadline it means the review
      // channel failed while the window was still open — never fall through to the
      // timer, which would auto-approve a default:"approve" Intent on a broken
      // channel. Fail closed. Past the deadline the Default has already decided
      // (spec §4), so a late error is moot — yield the Default. (CS-28)
      if (Date.now() >= deadline(intent)) return mintDefault(intent, authoritySecret);
      throw err instanceof Error ? err : new CountersignError(`adapter resolution failed for ${intent.intent_id}`);
    },
  );

  let timer: ReturnType<typeof setTimeout> | undefined;

  const winner =
    remaining <= 0
      ? mintDefault(intent, authoritySecret)
      : await Promise.race([
          guarded,
          // The timer fires on the monotonic clock after `remaining` ms: that IS
          // the deadline being reached, so mint unconditionally. Re-checking the
          // wall clock here (as defaultResolution does) would throw in this
          // callback — uncaught — if the wall clock stepped backward meanwhile.
          new Promise<Resolution>((resolve) => {
            timer = setTimeout(() => resolve(mintDefault(intent, authoritySecret)), remaining);
          }),
        ]).finally(() => clearTimeout(timer));

  verifyResolution(intent, winner, expectedAuthorityPublicKey, webauthn);
  return winner;
}
