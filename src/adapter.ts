// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import type { IncomingMessage } from "node:http";
import { CountersignError } from "./core/errors.js";
import { signDecision } from "./core/countersignature.js";
import { generateKeypair } from "./core/keys.js";
import type { Countersignature, Decision, Intent } from "./core/types.js";

/**
 * The single interface every Countersign adapter implements. Adapters are
 * intentionally dumb: deliver the Intent to where the approver lives, and
 * hand back a signed Countersignature when a decision arrives. Timeout and
 * Default resolution live in core, not here.
 */
export interface Adapter {
  /** channel name used as the actor prefix, e.g. "telegram" */
  readonly channel: string;
  /** Push the Intent to the approver's channel. */
  deliver(intent: Intent): Promise<void>;
  /** Resolve with the signed Countersignature once the approver decides. */
  awaitDecision(intent: Intent): Promise<Countersignature>;
  /** Release any resources (polling loops, servers). Optional. */
  close?(): Promise<void> | void;
}

interface PendingEntry {
  intent: Intent;
  resolve: (cs: Countersignature) => void;
  reject: (err: Error) => void;
}

/** Book-keeping shared by all adapters: intents awaiting a human decision. */
export class PendingDecisions {
  private entries = new Map<string, PendingEntry>();

  wait(intent: Intent): Promise<Countersignature> {
    return new Promise((resolve, reject) => {
      this.entries.set(intent.intent_id, { intent, resolve, reject });
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
   * Record a decision: sign the Countersignature with the adapter's
   * authority key and resolve the waiting promise. Returns null if the
   * intent is unknown or already settled (decisions are single-shot).
   */
  settle(intentId: string, decision: Decision, actor: string, authoritySecret: string): Countersignature | null {
    const entry = this.entries.get(intentId);
    if (!entry) return null;
    this.entries.delete(intentId);
    const cs = signDecision(entry.intent, decision, actor, authoritySecret);
    entry.resolve(cs);
    return cs;
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
  return [
    "Countersign approval request",
    `Action:  ${intent.action}`,
    `Summary: ${intent.summary}`,
    `Risk:    ${intent.risk_tier}`,
    `Agent:   ${intent.agent.id}`,
    `If nobody answers within ${intent.timeout}s, the default is: ${intent.default}.`,
    `Intent:  ${intent.intent_id}`,
  ].join("\n");
}

export async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}
