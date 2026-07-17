// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import type { IncomingMessage } from "node:http";
import { CountersignError } from "./core/errors.js";
import { normalizeActor, signDecision, verifyCountersignature } from "./core/countersignature.js";
import { deadline, DEFAULT_TIMEOUT_ACTOR } from "./core/defaults.js";
import { quorumOf } from "./core/intent.js";
import { fromB64url, generateKeypair, verifyContext } from "./core/keys.js";
import type { WebAuthnPolicy } from "./core/webauthn.js";
import { LINK_CONTEXT, type Approver, type Countersignature, type Decision, type Intent, type Resolution } from "./core/types.js";

/**
 * The single interface every counter-sign adapter implements. Adapters are
 * intentionally dumb: deliver the Intent to where the approvers live, and
 * hand back the resolved decision once enough of them have decided. Timeout
 * and Default resolution live in core, not here.
 */
export interface Adapter {
  /** channel name used as the actor prefix, e.g. "telegram" */
  readonly channel: string;
  /**
   * The WebAuthn policy this adapter's signer verifies passkey assertions against,
   * if any. Exposed so wrapAction can verify with the SAME policy the adapter's
   * SigningServer signs against — a divergence would reject a valid assertion after
   * approval. Absent for adapters that don't serve passkeys.
   */
  readonly webauthn?: WebAuthnPolicy;
  /**
   * The authority PUBLIC key this adapter signs vouched receipts (and the timeout Default) with,
   * if it signs any. Exposed so wrapAction can confirm the runtime verifies with the SAME authority
   * key the adapter signs with — a divergence would reject a valid receipt AFTER approval (a
   * post-approval split-brain). Absent for adapters that don't authority-sign (e.g. keyed-only ones).
   */
  readonly authorityPublicKey?: string;
  /** Push the Intent to the approver's channel. */
  deliver(intent: Intent): Promise<void>;
  /**
   * Resolve once the Intent is resolved by human decision: quorum distinct
   * approvals, or a single veto. Returns the set of receipts that produced it.
   */
  awaitResolution(intent: Intent): Promise<Resolution>;
  /** Release any resources (polling loops, servers). Optional. */
  close?(): Promise<void> | void;
}

/** Fields common to every settle outcome. */
interface SettleBase {
  /** the receipt just produced for this decision */
  countersignature: Countersignature;
  /** distinct approvals collected so far */
  collected: number;
  /** distinct approvals required */
  quorum: number;
}

/**
 * What recording one decision did to a pending Intent. Discriminated on
 * `status`: a "resolved" result always carries the final `decision`, a
 * "pending" one never does — so callers can read `decision` without a guard.
 */
export type SettleResult =
  | (SettleBase & { status: "pending" })
  | (SettleBase & { status: "resolved"; decision: Decision });

interface PendingEntry {
  intent: Intent;
  quorum: number;
  /** normalized identities allowed to decide via server-vouched settle (`vouched` approvers) */
  approverSet: Set<string>;
  /** normalized actor -> the `keyed` approver, who signs their own receipt (via record) */
  keyedApprovers: Map<string, Approver>;
  /** approve receipts keyed by distinct actor, so one person cannot fill a multi-person quorum */
  approvals: Map<string, Countersignature>;
  resolve: (r: Resolution) => void;
  reject: (err: Error) => void;
  /** the promise handed to every wait() for this intent (so a repeat wait is idempotent) */
  promise: Promise<Resolution>;
  /** reaper that evicts the entry at the Intent's deadline (prevents unbounded growth) */
  timer?: ReturnType<typeof setTimeout>;
}

/**
 * Guard for a VOUCHED-only adapter (chat buttons, email links): these can only
 * relay a server-vouched decision, so a `keyed` approver's input can't reach the
 * quorum — settle() would drop it and the Intent would fall to its Default with no
 * usable veto channel. Such adapters MUST refuse a keyed Intent in deliver() and
 * route keyed approvers through the SigningServer instead.
 */
export function assertVouchedApprovers(intent: Intent): void {
  if (intent.approvers.some((a) => a.mode === "keyed"))
    throw new CountersignError(
      `this adapter cannot serve keyed approvers (they must sign their own receipt via the SigningServer / approve CLI); intent ${intent.intent_id} has a keyed approver`,
    );
}

/** Book-keeping shared by all adapters: intents awaiting human decisions. */
export class PendingDecisions {
  private entries = new Map<string, PendingEntry>();
  /**
   * Terminal outcomes (spec §4 finality). Once an intent RESOLVES, its live entry is
   * deleted but a tombstone is kept here until its deadline. A later wait() for that
   * intent_id returns the recorded resolution instead of minting a FRESH entry — which
   * would let an un-consumed approver record a contradictory SECOND resolution for an
   * already-decided intent. Enforced at this layer so it protects EVERY caller (any
   * adapter instance, a raw awaitResolution), not just one. Only real resolutions are
   * tombstoned — a cancel/abort is not terminal, so a failed delivery can still retry.
   */
  private resolved = new Map<string, { resolution: Resolution; deadline: number }>();

  wait(intent: Intent): Promise<Resolution> {
    // Finality: a resolved intent yields its recorded decision, never a reopenable wait.
    // Gated on the WALL CLOCK (Date.now() vs the recorded deadline) — the SAME authority
    // record()/settle() use — not a timer. That makes finality immune to Node's ~24.8-day
    // setTimeout ceiling AND to backward wall-clock steps: a timer-based reaper could clamp
    // or fire early and reopen an already-decided intent; a wall-clock gate cannot. Past the
    // deadline the tombstone is inert (record()/settle() reject anyway), so drop it lazily.
    const done = this.resolved.get(intent.intent_id);
    if (done) {
      if (Date.now() < done.deadline) return Promise.resolve(done.resolution);
      this.resolved.delete(intent.intent_id);
    }
    // Idempotent: exactly one pending decision per intent_id. A second wait() for the
    // same intent returns the SAME promise instead of overwriting the entry — an
    // overwrite would strand the first promise (its resolve/reject would be orphaned,
    // so it could never settle).
    const existing = this.entries.get(intent.intent_id);
    if (existing) return existing.promise;

    let resolve!: (r: Resolution) => void;
    let reject!: (err: Error) => void;
    const promise = new Promise<Resolution>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const entry: PendingEntry = {
      intent,
      quorum: quorumOf(intent),
      // Only `vouched` approvers can be settled by the server (it signs on their
      // behalf). A `keyed` approver signs their own receipt off-server, so the
      // server must not vouch for them here. `default:timeout` is reserved and can
      // never be a human approver — mirrors verifyResolution's choke-point checks.
      approverSet: new Set(
        intent.approvers
          .filter((a) => a.mode === "vouched")
          .map((a) => normalizeActor(a.actor))
          .filter((a) => a !== DEFAULT_TIMEOUT_ACTOR),
      ),
      keyedApprovers: new Map(
        intent.approvers
          .filter((a) => a.mode === "keyed" && normalizeActor(a.actor) !== DEFAULT_TIMEOUT_ACTOR)
          .map((a) => [normalizeActor(a.actor), a] as const),
      ),
      approvals: new Map(),
      resolve,
      reject,
      promise,
    };
    this.entries.set(intent.intent_id, entry);
    // Evict the entry at the deadline so a timed-out Intent doesn't leak
    // forever (the runtime's awaitWithDefault fires the actual Default; this
    // only reclaims memory). Rejection is swallowed by awaitWithDefault.
    const remaining = deadline(intent) - Date.now();
    if (Number.isFinite(remaining)) {
      entry.timer = setTimeout(() => {
        // Evict the timed-out entry to reclaim memory, but do NOT reject this
        // promise: awaitWithDefault races it against its OWN default timer, and
        // rejecting here (the reaper is registered first, so at an equal deadline
        // it fires first) would make that race reject instead of resolving to the
        // signed Default. Leave the promise pending; it is GC'd once the race
        // settles to the Default. A late decision after eviction is ignored by
        // settle() (unknown intent_id → null), matching "the Default already decided".
        // A far-future (> ~24.8-day) delay clamps to ~1 ms and evicts early — harmless
        // here (a later decision finds no entry → ignored; awaitWithDefault rejects the
        // far-future intent up front), and it self-cleans rather than leaking the entry.
        if (this.entries.get(intent.intent_id) === entry) this.entries.delete(intent.intent_id);
      }, Math.max(0, remaining));
      entry.timer.unref?.();
    }
    return promise;
  }

  get size(): number {
    return this.entries.size;
  }

  has(intentId: string): boolean {
    return this.entries.has(intentId);
  }

  get(intentId: string): Intent | undefined {
    return this.entries.get(intentId)?.intent;
  }

  /**
   * Record one decision toward resolving an Intent. A `reject` vetoes
   * immediately and finally. An `approve` counts once per distinct `actor`
   * and resolves the Intent when `quorum` distinct actors have approved.
   * Returns null if the intent is unknown or already resolved (resolution is
   * single-shot); otherwise a SettleResult telling the caller whether the
   * Intent is now resolved or still awaiting more approvals.
   */
  settle(intentId: string, decision: Decision, actor: string, authoritySecret: string): SettleResult | null {
    const entry = this.entries.get(intentId);
    if (!entry) return null;
    // Past the deadline the Default has authority (spec §4). Gate on the clock, not
    // just the reaper timer: if the event loop stalled past expiry, the reaper is
    // overdue but the entry is still here, and a late decision processed before it
    // fires must NOT beat the timeout. Evict and ignore.
    if (Date.now() >= deadline(entry.intent)) {
      clearTimeout(entry.timer);
      this.entries.delete(intentId);
      return null;
    }
    // Only the Intent's named approvers can decide. An unlisted actor's click is
    // ignored — it neither counts toward quorum nor vetoes — so channel membership
    // is not authority. (The timeout Default is signed elsewhere, not via settle.)
    if (!entry.approverSet.has(normalizeActor(actor))) return null;
    const cs = signDecision(entry.intent, decision, actor, authoritySecret);

    if (decision === "reject") {
      this.finish(intentId, entry, { decision: "reject", policy: "approver", countersignatures: [cs] });
      return { countersignature: cs, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "reject" };
    }

    // Dedupe approvals by CANONICAL actor identity so one person cannot fill a
    // multi-person quorum via "alice"/"alice "/"Alice" variants.
    entry.approvals.set(normalizeActor(actor), cs);
    if (entry.approvals.size >= entry.quorum) {
      this.finish(intentId, entry, { decision: "approve", policy: "approver", countersignatures: [...entry.approvals.values()] });
      return { countersignature: cs, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "approve" };
    }
    return { countersignature: cs, status: "pending", collected: entry.approvals.size, quorum: entry.quorum };
  }

  /**
   * Record a PRE-SIGNED `keyed` receipt toward resolving an Intent. Unlike
   * settle — where the server signs a vouched approver's button press with the
   * authority key — here the approver has signed their OWN receipt off-server
   * (CLI in Phase 1, passkey in Phase 2); the server only VERIFIES it against the
   * approver's bound key and accumulates it. This is how a keyed quorum is
   * collected, and the server cannot forge it (it holds no approver key).
   *
   * Returns null (ignored) if the intent is unknown, resolved, or past its
   * deadline; or the receipt is not a valid `keyed`-approver decision for this
   * intent (wrong intent, non-keyed/unlisted actor, bad signature, wrong policy).
   * A `reject` from a listed keyed approver vetoes immediately; an `approve`
   * counts once per distinct actor and resolves at `quorum`.
   */
  record(receipt: Countersignature, webauthn?: WebAuthnPolicy): SettleResult | null {
    if (!receipt || typeof receipt !== "object") return null;
    const entry = this.entries.get(receipt.intent_id);
    if (!entry) return null;
    if (Date.now() >= deadline(entry.intent)) {
      clearTimeout(entry.timer);
      this.entries.delete(receipt.intent_id);
      return null;
    }
    if (receipt.policy !== "approver") return null;
    if (receipt.decision !== "approve" && receipt.decision !== "reject") return null;
    const actor = normalizeActor(receipt.actor);
    const approver = entry.keyedApprovers.get(actor);
    // Must be a keyed approver of THIS intent, and the receipt must verify against
    // that approver's bound key — the server never vouches for a keyed decision.
    // A passkey (WebAuthn) receipt needs the RP policy to verify; without it, fail closed.
    if (!approver?.public_key) return null;
    if (!verifyCountersignature(receipt, { trustedKeys: approver.public_key, webauthn })) return null;

    if (receipt.decision === "reject") {
      this.finish(receipt.intent_id, entry, { decision: "reject", policy: "approver", countersignatures: [receipt] });
      return { countersignature: receipt, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "reject" };
    }
    entry.approvals.set(actor, receipt);
    if (entry.approvals.size >= entry.quorum) {
      this.finish(receipt.intent_id, entry, { decision: "approve", policy: "approver", countersignatures: [...entry.approvals.values()] });
      return { countersignature: receipt, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "approve" };
    }
    return { countersignature: receipt, status: "pending", collected: entry.approvals.size, quorum: entry.quorum };
  }

  /** Resolve a pending entry: cancel its reaper, drop it from the map, settle the promise,
   *  and leave a finality tombstone until the deadline so the intent cannot be reopened. */
  private finish(intentId: string, entry: PendingEntry, resolution: Resolution): void {
    clearTimeout(entry.timer);
    this.entries.delete(intentId);
    // Tombstone the terminal outcome, gated on the wall clock (see wait()): a re-wait
    // before the deadline returns THIS resolution instead of a fresh reopenable entry;
    // at/after the deadline the tombstone is inert and dropped lazily. No timer — finality
    // must not depend on one (clamping or a clock step could reopen a decided intent).
    // Sweep expired tombstones here (finish is the only place they are added) so the map
    // stays bounded to intents resolved within the current deadline window.
    const now = Date.now();
    for (const [id, t] of this.resolved) if (now >= t.deadline) this.resolved.delete(id);
    this.resolved.set(intentId, { resolution, deadline: deadline(entry.intent) });
    entry.resolve(resolution);
  }

  /**
   * Cancel a single pending wait and reclaim it NOW — e.g. delivery to the
   * approvers failed, so the Intent will never resolve and should not sit in the
   * map until its deadline reaper fires. Rejects the wait promise (the caller
   * that awaits it, if any, sees `err`) and clears the reaper. A no-op for an
   * unknown/already-settled intent.
   */
  cancel(intentId: string, err: Error): void {
    const entry = this.entries.get(intentId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.entries.delete(intentId);
    entry.reject(err);
  }

  abortAll(err: Error): void {
    for (const entry of this.entries.values()) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.entries.clear();
    this.resolved.clear(); // tombstones are timer-free; just drop them
  }
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new CountersignError(`missing required environment variable ${name}`);
  return value;
}

const warned = new Set<string>();

/** Emit a security warning at most once per process per key. */
export function warnOnce(key: string, message: string): void {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`[countersign] ${message}`);
}

let ephemeralAuthority: string | undefined;

/**
 * The authority key adapters sign Countersignatures with. Comes from
 * COUNTERSIGN_AUTHORITY_KEY; if unset, an ephemeral per-process key is
 * generated (fine for demos, useless for receipts you want to verify later).
 */
export function authorityKeyFromEnv(): string {
  if (process.env.COUNTERSIGN_AUTHORITY_KEY) return process.env.COUNTERSIGN_AUTHORITY_KEY;
  warnOnce(
    "authority:ephemeral",
    "COUNTERSIGN_AUTHORITY_KEY is not set — signing with an EPHEMERAL authority key that changes " +
      "every restart and is lost on exit. Receipts issued now will NOT be verifiable later. Generate a " +
      "persistent key (npm run keygen) for anything beyond a throwaway demo.",
  );
  ephemeralAuthority ??= generateKeypair().secretKey;
  return ephemeralAuthority;
}

/** Parse "cs:<intent_id>:<approve|reject>" button payloads. */
export function parseDecisionPayload(payload: string): { intentId: string; decision: Decision } | null {
  const match = /^cs:([0-9a-f-]{36}):(approve|reject)$/.exec(payload);
  if (!match) return null;
  return { intentId: match[1], decision: match[2] as Decision };
}

export function decisionPayload(intent: Intent, decision: Decision): string {
  return `cs:${intent.intent_id}:${decision}`;
}

/**
 * Drop `key -> expiry(ms)` entries whose expiry has passed. The ONE prune for every
 * single-use bearer-link bookkeeping map (SigningServer's spent-links, EmailAdapter's
 * decided-intents) — keep one copy so a replay-window fix can't land in only one.
 */
export function pruneExpired(map: Map<string, number>, now: number): void {
  for (const [k, exp] of map) if (now >= exp) map.delete(k);
}

/**
 * Verify a signed single-use bearer token of the form `b64url(bodyJSON).signature` under
 * LINK_CONTEXT, returning the parsed body (caller applies its own shape check) or null on ANY
 * failure — bad shape, bad signature, non-JSON. The ONE decode+verify mechanism for every
 * link/signing token, so a hardening fix (length cap, constant-time compare) is applied once.
 */
export function verifyBearerToken(token: string, authorityPublicKey: string): unknown {
  try {
    const dot = token.indexOf(".");
    if (dot < 0) return null;
    const body = fromB64url(token.slice(0, dot)).toString("utf8");
    if (!verifyContext(authorityPublicKey, LINK_CONTEXT, body, token.slice(dot + 1))) return null;
    return JSON.parse(body);
  } catch {
    return null;
  }
}

/**
 * The ONE strict HTML escaper for every adapter-facing page (escapes & < > " ').
 * Security-relevant: keep a single copy — two escapers drift (one grew the
 * single-quote escape, the other didn't), and a hardening fix applied to one
 * silently misses the other.
 */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** Human-readable rendering of an Intent for chat messages and emails. */
export function formatIntent(intent: Intent): string {
  const quorum = quorumOf(intent);
  return [
    "counter-sign approval request",
    `Action:  ${intent.action}`,
    `Summary: ${intent.summary}`,
    `Risk:    ${intent.risk_tier}`,
    `Agent:   ${intent.agent.id}`,
    ...(quorum > 1 ? [`Requires: ${quorum} distinct approvals`] : []),
    `If nobody answers within ${intent.timeout}s, the default is: ${intent.default}.`,
    `Intent:  ${intent.intent_id}`,
  ].join("\n");
}

/**
 * Max webhook body we buffer. counter-sign envelopes are tiny; anything larger
 * is refused BEFORE parsing or signature verification, so an unauthenticated
 * attacker can't exhaust memory with a giant POST ahead of the auth check.
 */
const MAX_BODY_BYTES = 1_048_576; // 1 MiB

export async function readBody(req: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > maxBytes) throw new CountersignError(`request body exceeds ${maxBytes} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}
