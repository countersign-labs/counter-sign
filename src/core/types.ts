// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

export const COUNTERSIGN_VERSION = "0.1" as const;

/**
 * Signature domain-separation contexts. Each artifact type signs under a
 * distinct label so a signature is only ever valid for the artifact it was
 * minted for. Bump alongside COUNTERSIGN_VERSION on any wire-format change.
 */
export const INTENT_CONTEXT = "countersign-intent-v0.1" as const;
export const COUNTERSIGNATURE_CONTEXT = "countersign-countersignature-v0.1" as const;
export const LINK_CONTEXT = "countersign-link-v0.1" as const;

export type RiskTier = "low" | "medium" | "high" | "critical";
export type Decision = "approve" | "reject";
/** "approver" = an explicit human decision; "default" = the Intent's declared Default fired. */
export type Policy = "approver" | "default";

/** A signed statement of what an agent wants to do. */
export interface Intent {
  countersign: typeof COUNTERSIGN_VERSION;
  intent_id: string;
  agent: {
    id: string;
    /** base64url raw ed25519 public key of the agent */
    public_key: string;
  };
  action: string;
  summary: string;
  risk_tier: RiskTier;
  approvers: string[];
  /** seconds until the Default fires, counted from created_at */
  timeout: number;
  /** what silence means: the decision that fires at the deadline */
  default: Decision;
  /** optional URL the Countersignature is POSTed to once produced */
  callback: string | null;
  created_at: string;
  /** base64url ed25519 signature by agent.public_key over the canonical envelope */
  signature: string;
}

/** A signed, portable receipt of a decision over an Intent. */
export interface Countersignature {
  countersign: typeof COUNTERSIGN_VERSION;
  intent_id: string;
  decision: Decision;
  /** who decided, as channel:address — e.g. "telegram:8675309", "default:timeout" */
  actor: string;
  policy: Policy;
  timestamp: string;
  /** base64url raw ed25519 public key of the signing authority */
  public_key: string;
  /** base64url ed25519 signature over the canonical receipt */
  signature: string;
}

/** The caller-supplied fields of an Intent; everything else is derived. */
export interface IntentFields {
  action: string;
  summary: string;
  risk_tier: RiskTier;
  approvers: string[];
  timeout: number;
  default: Decision;
  callback?: string | null;
}
