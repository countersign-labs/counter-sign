// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

export const COUNTERSIGN_VERSION = "0.2" as const;

/**
 * Signature domain-separation contexts. Each artifact type signs under a
 * distinct label so a signature is only ever valid for the artifact it was
 * minted for. Bump alongside COUNTERSIGN_VERSION on any wire-format change.
 */
export const INTENT_CONTEXT = "countersign-intent-v0.2" as const;
export const COUNTERSIGNATURE_CONTEXT = "countersign-countersignature-v0.2" as const;
export const LINK_CONTEXT = "countersign-link-v0.2" as const;

export type RiskTier = "low" | "medium" | "high" | "critical";
export type Decision = "approve" | "reject";
/** "approver" = an explicit human decision; "default" = the Intent's declared Default fired. */
export type Policy = "approver" | "default";

/**
 * How an approver's decision is authenticated.
 * - `vouched`: the integration server signs "actor X approved" with the authority
 *   key (the frictionless button flow). Fine for low-stakes; a compromised server
 *   could forge it.
 * - `keyed`: approver X signs their own receipt with their own key (`public_key`),
 *   which the server never holds — so the server cannot forge it and the receipt
 *   is independently verifiable. Required for `quorum > 1` (real separation of duty).
 */
export type ApproverMode = "vouched" | "keyed";

/** A single approver slot on an Intent. */
export interface Approver {
  /** channel:address, e.g. "telegram:8675309", "email:ops@example.com" */
  actor: string;
  mode: ApproverMode;
  /** base64url raw ed25519 (or, from Phase 2, COSE) public key. REQUIRED iff mode === "keyed". */
  public_key?: string;
}

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
  /** who may countersign, each bound to a mode (and a key, if keyed). */
  approvers: Approver[];
  /** number of distinct approvers whose approve is required (M-of-N); >= 1 */
  quorum: number;
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
  /**
   * base64url signing key. For a `vouched` receipt or the Default this is the
   * authority's raw ed25519 key; for a raw-keyed approver, their ed25519 key;
   * for a passkey approver, a WebAuthn credential descriptor
   * (`webauthn-ed25519:…` / `webauthn-p256:…`).
   */
  public_key: string;
  /** base64url signature: an ed25519 signature over the canonical receipt, OR
   *  (when `webauthn` is present) the WebAuthn assertion signature. */
  signature: string;
  /**
   * Present iff this is a passkey (WebAuthn) receipt. The authenticator output;
   * the assertion's challenge binds it to the canonical receipt digest. Absent
   * for ed25519 (vouched / raw-keyed / Default) receipts.
   */
  webauthn?: { authenticator_data: string; client_data_json: string };
}

/** The caller-supplied fields of an Intent; everything else is derived. */
export interface IntentFields {
  action: string;
  summary: string;
  risk_tier: RiskTier;
  /** A bare string is shorthand for a `vouched` approver; an object sets mode/key. */
  approvers: (string | Approver)[];
  /** distinct approvals required (M-of-N); optional, defaults to 1. */
  quorum?: number;
  timeout: number;
  default: Decision;
  callback?: string | null;
}

/**
 * The outcome of resolving an Intent: the final decision and the set of
 * receipts that produced it. For an approval under `quorum: N`, that is the
 * N distinct `approve` Countersignatures; for a veto, the single `reject`;
 * for a timeout, the single Default receipt. Every receipt is independently
 * verifiable and bound to the same `intent_id`.
 */
export interface Resolution {
  decision: Decision;
  policy: Policy;
  countersignatures: Countersignature[];
}
