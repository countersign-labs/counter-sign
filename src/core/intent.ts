// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import { randomUUID } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { normalizeActor } from "./countersignature.js";
import { CountersignError } from "./errors.js";
import { isCanonicalPublicKey, signContext, verifyContext, type Keypair } from "./keys.js";
import { COUNTERSIGN_VERSION, INTENT_CONTEXT, type Approver, type Intent, type IntentFields } from "./types.js";

export interface AgentIdentity {
  id: string;
  keypair: Keypair;
}

const RISK_TIERS = new Set(["low", "medium", "high", "critical"]);
const DECISIONS = new Set(["approve", "reject"]);
const APPROVER_MODES = new Set(["vouched", "keyed"]);
/** Reserved actor for the runtime timeout Default; never a real approver. */
const DEFAULT_TIMEOUT_ACTOR = "default:timeout";
/** floor((2^31 - 1) / 1000): largest timeout whose ms value setTimeout won't clamp. */
const MAX_TIMEOUT_SECONDS = 2147483;

/** Coerce a bare string approver into a `vouched` Approver; pass objects through. */
function normalizeApprover(input: string | Approver): Approver {
  if (typeof input === "string") return { actor: input, mode: "vouched" };
  if (!input || typeof input !== "object") throw new CountersignError("each approver must be a string or an object");
  const { actor, mode, public_key } = input;
  return public_key === undefined ? { actor, mode } : { actor, mode, public_key };
}

/**
 * Validate a normalized approver list against the Intent's invariants. Shared by
 * createIntent (authorship) and assertIntentInvariants (a received wire Intent),
 * so both enforce identical rules. A `keyed` approver MUST carry a key and no two
 * keyed approvers may share one (one key must not fill two slots); `quorum > 1`
 * requires EVERY approver be `keyed` — otherwise a "four-eyes" could be satisfied
 * by server-forgeable `vouched` slots (see the per-approver-key-quorum spec §1).
 */
function validateApprovers(approvers: Approver[], quorum: number): void {
  const keys = new Set<string>();
  for (const a of approvers) {
    if (!a || typeof a !== "object" || typeof a.actor !== "string" || a.actor.length === 0)
      throw new CountersignError("each approver must have a non-empty string actor");
    if (!APPROVER_MODES.has(a.mode)) throw new CountersignError(`approver ${a.actor} has invalid mode ${JSON.stringify(a.mode)}`);
    if (normalizeActor(a.actor) === DEFAULT_TIMEOUT_ACTOR)
      throw new CountersignError(`approver actor ${JSON.stringify(a.actor)} is reserved`);
    if (a.mode === "keyed") {
      if (typeof a.public_key !== "string" || a.public_key.length === 0)
        throw new CountersignError(`keyed approver ${a.actor} must carry a public_key`);
      // Require the CANONICAL base64url encoding of a 32-byte key, so the exact-string
      // distinctness check below is sound — two encodings of ONE key must not fill two
      // quorum slots (that would break separation of duty).
      if (!isCanonicalPublicKey(a.public_key))
        throw new CountersignError(`keyed approver ${a.actor} has a non-canonical or malformed public_key`);
      if (keys.has(a.public_key))
        throw new CountersignError(`approver public_key ${a.public_key} is used by more than one approver`);
      keys.add(a.public_key);
    } else if (a.public_key !== undefined) {
      throw new CountersignError(`vouched approver ${a.actor} must not carry a public_key`);
    }
  }
  if (quorum > 1 && approvers.some((a) => a.mode !== "keyed"))
    throw new CountersignError(
      "Intent.quorum > 1 requires every approver to be keyed (a vouched slot in a quorum is server-forgeable)",
    );
}

export function createIntent(fields: IntentFields, agent: AgentIdentity): Intent {
  if (!fields.action) throw new CountersignError("Intent.action is required");
  if (!fields.summary) throw new CountersignError("Intent.summary is required");
  if (!RISK_TIERS.has(fields.risk_tier)) throw new CountersignError(`invalid risk_tier: ${fields.risk_tier}`);
  if (!Array.isArray(fields.approvers) || fields.approvers.length === 0)
    throw new CountersignError("Intent.approvers must be a non-empty array");
  const approvers = fields.approvers.map(normalizeApprover);
  const quorum = fields.quorum ?? 1;
  if (!Number.isInteger(quorum) || quorum < 1)
    throw new CountersignError("Intent.quorum must be an integer >= 1");
  validateApprovers(approvers, quorum);
  // A multi-person quorum with an approve-on-silence Default is self-defeating:
  // a timeout would authorize the action without the required approvers.
  if (quorum > 1 && fields.default === "approve")
    throw new CountersignError("Intent.quorum > 1 must not be combined with default: approve (a timeout would bypass the required approvers)");
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
    approvers,
    quorum,
    timeout: fields.timeout,
    default: fields.default,
    callback: fields.callback ?? null,
    created_at: new Date().toISOString(),
  };
  const signature = signContext(agent.keypair.secretKey, INTENT_CONTEXT, canonicalize(unsigned));
  return { ...unsigned, signature };
}

/**
 * Distinct approvals required to authorize an Intent. An ABSENT quorum means 1
 * (the wire format makes it optional); a PRESENT-but-malformed quorum FAILS
 * CLOSED by throwing, rather than silently downgrading to 1 — a downgrade would
 * let a `quorum: "3"` or `quorum: 2.5` Intent be authorized by a single approver.
 */
export function quorumOf(intent: Intent): number {
  const q = intent.quorum;
  if (q === undefined || q === null) return 1;
  if (!Number.isInteger(q) || q < 1)
    throw new CountersignError(`Intent.quorum must be an integer >= 1 (got ${JSON.stringify(q)})`);
  return q;
}

/**
 * Re-validate a received Intent's structural invariants — the same rules
 * createIntent enforces at authorship — before acting on it. Intents cross trust
 * boundaries (a2a, callbacks), so the enforcing runtime MUST NOT trust that a
 * wire Intent's fields are well-formed just because its signature verifies:
 * verifyIntent proves the agent authored the bytes, not that quorum/timeout/
 * created_at are in range. Throws CountersignError on any violation (fail closed).
 */
export function assertIntentInvariants(intent: Intent): void {
  if (!intent || typeof intent !== "object") throw new CountersignError("intent must be an object");
  if (typeof intent.intent_id !== "string" || intent.intent_id.length === 0)
    throw new CountersignError("Intent.intent_id must be a non-empty string");
  if (typeof intent.action !== "string" || intent.action.length === 0)
    throw new CountersignError("Intent.action is required");
  if (typeof intent.summary !== "string" || intent.summary.length === 0)
    throw new CountersignError("Intent.summary is required");
  if (!RISK_TIERS.has(intent.risk_tier)) throw new CountersignError(`invalid risk_tier: ${intent.risk_tier}`);
  if (!Array.isArray(intent.approvers) || intent.approvers.length === 0)
    throw new CountersignError("Intent.approvers must be a non-empty array");
  const quorum = intent.quorum ?? 1;
  if (!Number.isInteger(quorum) || quorum < 1)
    throw new CountersignError("Intent.quorum must be an integer >= 1");
  if (quorum > 1 && intent.default === "approve")
    throw new CountersignError("Intent.quorum > 1 must not be combined with default: approve");
  // A wire Intent's approver objects must be well-formed and obey the keyed rules —
  // never trust that a received Intent's approvers are valid just because it is
  // agent-signed (a malformed/hostile Intent must fail closed here).
  validateApprovers(intent.approvers, quorum);
  if (!Number.isInteger(intent.timeout) || intent.timeout < 1 || intent.timeout > MAX_TIMEOUT_SECONDS)
    throw new CountersignError(`Intent.timeout must be an integer number of seconds in [1, ${MAX_TIMEOUT_SECONDS}]`);
  if (!DECISIONS.has(intent.default)) throw new CountersignError(`invalid default: ${intent.default}`);
  if (typeof intent.created_at !== "string" || !Number.isFinite(Date.parse(intent.created_at)))
    throw new CountersignError("Intent.created_at must be a valid ISO 8601 timestamp");
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
