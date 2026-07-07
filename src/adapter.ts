// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import type { IncomingMessage } from "node:http";
import { CountersignError } from "./core/errors.js";
import { signDecision } from "./core/countersignature.js";
import { quorumOf } from "./core/intent.js";
import { generateKeypair } from "./core/keys.js";
import type { Countersignature, Decision, Intent, Resolution } from "./core/types.js";

/**
 * The single interface every Countersign adapter implements. Adapters are
 * intentionally dumb: deliver the Intent to where the approvers live, and
 * hand back the resolved decision once enough of them have decided. Timeout
 * and Default resolution live in core, not here.
 */
export interface Adapter {
  /** channel name used as the actor prefix, e.g. "telegram" */
  readonly channel: string;
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

/** What recording one decision did to a pending Intent. */
export interface SettleResult {
  /** the receipt just produced for this decision */
  countersignature: Countersignature;
  /** "resolved" once quorum is met or a veto lands; "pending" while more approvals are needed */
  status: "pending" | "resolved";
  /** distinct approvals collected so far */
  collected: number;
  /** distinct approvals required */
  quorum: number;
  /** the final decision, present when status === "resolved" */
  decision?: Decision;
}

interface PendingEntry {
  intent: Intent;
  quorum: number;
  /** approve receipts keyed by distinct actor, so one person cannot fill a multi-person quorum */
  approvals: Map<string, Countersignature>;
  resolve: (r: Resolution) => void;
  reject: (err: Error) => void;
}

/** Book-keeping shared by all adapters: intents awaiting human decisions. */
export class PendingDecisions {
  private entries = new Map<string, PendingEntry>();

  wait(intent: Intent): Promise<Resolution> {
    return new Promise((resolve, reject) => {
      this.entries.set(intent.intent_id, {
        intent,
        quorum: quorumOf(intent),
        approvals: new Map(),
        resolve,
        reject,
      });
    });
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
    const cs = signDecision(entry.intent, decision, actor, authoritySecret);

    if (decision === "reject") {
      this.entries.delete(intentId);
      entry.resolve({ decision: "reject", policy: "approver", countersignatures: [cs] });
      return { countersignature: cs, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "reject" };
    }

    // Dedupe approvals by actor so one person cannot fill a multi-person quorum.
    entry.approvals.set(actor, cs);
    if (entry.approvals.size >= entry.quorum) {
      this.entries.delete(intentId);
      entry.resolve({ decision: "approve", policy: "approver", countersignatures: [...entry.approvals.values()] });
      return { countersignature: cs, status: "resolved", collected: entry.approvals.size, quorum: entry.quorum, decision: "approve" };
    }
    return { countersignature: cs, status: "pending", collected: entry.approvals.size, quorum: entry.quorum };
  }

  abortAll(err: Error): void {
    for (const entry of this.entries.values()) entry.reject(err);
    this.entries.clear();
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

/** Human-readable rendering of an Intent for chat messages and emails. */
export function formatIntent(intent: Intent): string {
  const quorum = quorumOf(intent);
  return [
    "Countersign approval request",
    `Action:  ${intent.action}`,
    `Summary: ${intent.summary}`,
    `Risk:    ${intent.risk_tier}`,
    `Agent:   ${intent.agent.id}`,
    ...(quorum > 1 ? [`Requires: ${quorum} distinct approvals`] : []),
    `If nobody answers within ${intent.timeout}s, the default is: ${intent.default}.`,
    `Intent:  ${intent.intent_id}`,
  ].join("\n");
}

export async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}
