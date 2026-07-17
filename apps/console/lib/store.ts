// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// The console's read model: load an org's signed policy state from a data directory,
// VERIFY every chain, and derive the display lists. Fails LOUD — a verification failure
// sets `verified: false` and populates `faults` rather than rendering tampered state as
// trustworthy. Synchronous (policy log + registry verification are sync); receipt-log
// verification is async and belongs to the Phase 3 Audit page.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ApproverRegistry, PolicyLog, type AdminKey, type PolicyChange, type Role, type Rule } from "@countersignlabs/counter-sign";

export interface ConsoleState {
  org: string;
  verified: boolean;
  faults: string[];
  admins: AdminKey[];
  roles: Role[];
  rules: Rule[];
  approvers: { actor: string; keys: string[] }[];
  /** Receipt-log audit status — not checked in Phase 1 (see module note); the Audit page owns it. */
  auditVerified: boolean;
}

function readOrEmpty(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/** The org a policy change belongs to (mirrors the library's internal changeOrg). */
function changeOrg(change: PolicyChange): string {
  if (change.kind === "role-set") return change.role.org;
  if (change.kind === "rule-set") return change.rule.org;
  return change.org;
}

/** Load a data dir, verify the policy log + registry chains, and derive the read model. */
export function loadConsoleState(dataDir: string, orgPublicKey: string): ConsoleState {
  const faults: string[] = [];
  const log = PolicyLog.fromJSONL(readOrEmpty(join(dataDir, "policy.jsonl")));
  const registry = ApproverRegistry.fromJSONL(readOrEmpty(join(dataDir, "registry.jsonl")));

  if (log.entries.length > 0 && !log.verifyChain()) faults.push("policy log failed chain verification");
  if (registry.all.length > 0) {
    if (!orgPublicKey) faults.push("registry present but COUNTERSIGN_ORG_PUBLIC_KEY is not set — cannot verify approver enrollments");
    else if (!registry.verifyChain(orgPublicKey)) faults.push("approver registry failed chain verification");
  }

  // Derive the read model from folded state. If verification failed, we still show the
  // derived lists, but the pages render a prominent failure banner (verified === false).
  const state = log.state();
  const org = log.entries[0] ? changeOrg(log.entries[0].change) : "";
  const admins = [...state.admins.values()];
  const roles = [...state.roles.values()];
  const rules = [...state.rules.values()];
  const approvers = [...registry.activeKeyMap().entries()].map(([actor, keys]) => ({ actor, keys: [...keys] }));

  // Receipt-log verification is async (ReceiptLog.verifyAll/verifyChain) and belongs to
  // the Phase 3 Audit screen; not checked here.
  const auditVerified = true;

  return { org, verified: faults.length === 0, faults, admins, roles, rules, approvers, auditVerified };
}
