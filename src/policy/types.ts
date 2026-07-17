// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// The policy layer: approvers (from ApproverRegistry) grouped into Roles, referenced
// by Rules that carry quorum + default + timeout. Every change is a signed, hash-chained
// PolicyLog entry (admin-attested). resolveRule turns a named Rule into IntentFields.

import type { ApproverRegistry } from "../registry.js";
import type { Decision, RiskTier } from "../core/types.js";
import { COUNTERSIGN_VERSION } from "../core/types.js";

/** Domain-separation context for policy-log entry signatures. */
export const POLICY_CONTEXT = "countersign-policy-v0.2" as const;

/** A named group of approvers (by actor id) within an org. Membership only. */
export interface Role {
  id: string;
  org: string;
  name: string;
  description?: string;
  members: string[]; // approver actor ids
}

/** A named approval rule an agent references. Resolves to IntentFields. */
export interface Rule {
  id: string;
  org: string;
  name: string;
  roles: string[]; // role ids whose members may approve
  quorum: number;
  default: Decision;
  timeout_seconds: number;
  risk_tier?: RiskTier;
  action?: string;
}

/** An admin key that may sign policy-log changes and access the console. */
export interface AdminKey {
  org: string;
  public_key: string; // raw ed25519 or a webauthn-* descriptor
  name?: string;
}

/** One change recorded in the policy log. */
export type PolicyChange =
  | { kind: "admin-add"; org: string; public_key: string; name?: string }
  | { kind: "admin-revoke"; org: string; public_key: string }
  | { kind: "role-set"; role: Role }
  | { kind: "role-delete"; org: string; id: string }
  | { kind: "rule-set"; rule: Rule }
  | { kind: "rule-delete"; org: string; id: string };

/** A signed, hash-chained policy-log entry. */
export interface PolicyEntry {
  countersign: typeof COUNTERSIGN_VERSION;
  seq: number; // 0-based
  change: PolicyChange;
  issued_at: string; // ISO 8601
  prev: string | null; // sha256 hex of the previous entry; null for genesis
  signer_public_key: string; // the admin key that signed this entry
  signature: string; // signContext(adminSecret, POLICY_CONTEXT, canonicalPolicyEntry(unsigned))
}

/** The current state derived by folding a verified policy log. */
export interface PolicyState {
  admins: Map<string, AdminKey>; // public_key -> active AdminKey
  roles: Map<string, Role>; // role id -> Role
  rules: Map<string, Rule>; // rule id -> Rule
}

/** Read surface consumed by resolveRule and the console. */
export interface PolicyStore {
  getRule(org: string, name: string): Rule | undefined;
  getRoleById(org: string, id: string): Role | undefined;
  listRoles(org: string): Role[];
  listRules(org: string): Rule[];
  listAdmins(org: string): AdminKey[];
  /** Verify the store's underlying log against its own chain (and, if given, an
   *  externally-anchored head to detect rollback/tail-truncation). resolveRule must
   *  call this before trusting any rule read from the store (spec §5: "verified state"). */
  verify(expectedHead?: { length: number; hash: string }): boolean;
}

/** The specific request context an agent supplies when resolving a rule. */
export interface RuleRequest {
  summary: string; // the concrete action description
  action?: string; // overrides rule.action when given
  risk_tier?: RiskTier; // overrides rule.risk_tier when given
}

/** Dependencies resolveRule needs. */
export interface ResolveDeps {
  store: PolicyStore;
  registry: ApproverRegistry;
  org: string;
}
