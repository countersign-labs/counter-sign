// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { randomUUID } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { CountersignError } from "./errors.js";
import { signContext, verifyContext, type Keypair } from "./keys.js";
import { COUNTERSIGN_VERSION, INTENT_CONTEXT, type Intent, type IntentFields } from "./types.js";

export interface AgentIdentity {
  id: string;
  keypair: Keypair;
}

const RISK_TIERS = new Set(["low", "medium", "high", "critical"]);
const DECISIONS = new Set(["approve", "reject"]);
/** floor((2^31 - 1) / 1000): largest timeout whose ms value setTimeout won't clamp. */
const MAX_TIMEOUT_SECONDS = 2147483;

export function createIntent(fields: IntentFields, agent: AgentIdentity): Intent {
  if (!fields.action) throw new CountersignError("Intent.action is required");
  if (!fields.summary) throw new CountersignError("Intent.summary is required");
  if (!RISK_TIERS.has(fields.risk_tier)) throw new CountersignError(`invalid risk_tier: ${fields.risk_tier}`);
  if (!Array.isArray(fields.approvers) || fields.approvers.length === 0)
    throw new CountersignError("Intent.approvers must be a non-empty array");
  // Upper bound keeps timeout*1000 within Node's setTimeout range (2^31-1 ms),
  // so the Default always fires at the deadline rather than being clamped and
  // firing immediately — a silent-early-approve footgun if default is "approve".
  if (!Number.isInteger(fields.timeout) || fields.timeout < 1 || fields.timeout > MAX_TIMEOUT_SECONDS)
    throw new CountersignError(`Intent.timeout must be an integer number of seconds in [1, ${MAX_TIMEOUT_SECONDS}]`);
  if (!DECISIONS.has(fields.default)) throw new CountersignError(`invalid default: ${fields.default}`);

  const unsigned = {
    countersign: COUNTERSIGN_VERSION,
    intent_id: randomUUID(),
    agent: { id: agent.id, public_key: agent.keypair.publicKey },
    action: fields.action,
    summary: fields.summary,
    risk_tier: fields.risk_tier,
    approvers: [...fields.approvers],
    timeout: fields.timeout,
    default: fields.default,
    callback: fields.callback ?? null,
    created_at: new Date().toISOString(),
  };
  const signature = signContext(agent.keypair.secretKey, INTENT_CONTEXT, canonicalize(unsigned));
  return { ...unsigned, signature };
}

/** Verify the agent's signature over the canonical envelope. Never throws. */
export function verifyIntent(intent: Intent): boolean {
  try {
    const { signature, ...unsigned } = intent;
    if (typeof signature !== "string" || typeof intent.agent?.public_key !== "string") return false;
    return verifyContext(intent.agent.public_key, INTENT_CONTEXT, canonicalize(unsigned), signature);
  } catch {
    return false;
  }
}
