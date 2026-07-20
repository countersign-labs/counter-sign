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
import { errMsg, isRenderSafeAdmin, isRenderSafeApprover, isRenderSafeRole, isRenderSafeRule } from "./schema";

export interface ConsoleState {
  org: string;
  verified: boolean;
  /** True iff the POLICY log alone verified — independent of the approver registry, so the
   *  Audit page can label the policy log without being tripped by a registry-only fault. */
  policyVerified: boolean;
  faults: string[];
  admins: AdminKey[];
  roles: Role[];
  rules: Rule[];
  approvers: { actor: string; keys: string[] }[];
  /** Receipt-log audit status — not checked in Phase 1 (see module note); the Audit page owns it. */
  auditVerified: boolean;
}

/** Read a JSONL log. Returns "" ONLY when the file is absent (ENOENT). Any other read
 *  error (EACCES/EIO/EISDIR/…) means a real file exists but could not be read — that must
 *  propagate as a fault, never be silently treated as an empty (and therefore "verified,
 *  empty") org. Swallowing it would render a trusted blank console over a live policy. */
function readLog(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw new Error(`cannot read ${path}: ${(e as Error).message ?? String(e)}`);
  }
}

/** The org a policy change belongs to (mirrors the library's internal changeOrg). */
function changeOrg(change: PolicyChange): string {
  if (change.kind === "role-set") return change.role.org;
  if (change.kind === "rule-set") return change.rule.org;
  return change.org;
}

/** Load a data dir, verify the policy log + registry chains, and derive the read model.
 *  Fails LOUD: an unreadable file, a corrupt log, an unknown change kind, or a broken chain
 *  becomes a fault (verified:false) — never an uncaught throw (which would 500 every page and
 *  hide the fault) and never a silently-trusted empty render. */
export function loadConsoleState(dataDir: string, orgPublicKey: string): ConsoleState {
  const policyFaults: string[] = [];
  const registryFaults: string[] = [];

  // --- Policy log: read + verify chain. Any failure is a policy fault. ---
  let log: PolicyLog | null = null;
  try {
    log = PolicyLog.fromJSONL(readLog(join(dataDir, "policy.jsonl")));
    if (log.entries.length > 0 && !log.verifyChain()) policyFaults.push("policy log failed chain verification");
  } catch (e) {
    policyFaults.push(`policy log unreadable or corrupt: ${errMsg(e)}`);
    log = null;
  }

  // --- Approver registry: read + verify chain. Independent fault bucket. ---
  let registry: ApproverRegistry | null = null;
  try {
    registry = ApproverRegistry.fromJSONL(readLog(join(dataDir, "registry.jsonl")));
    if (registry.all.length > 0) {
      if (!orgPublicKey) registryFaults.push("registry present but COUNTERSIGN_ORG_PUBLIC_KEY is not set — cannot verify approver enrollments");
      else if (!registry.verifyChain(orgPublicKey)) registryFaults.push("approver registry failed chain verification");
    }
  } catch (e) {
    registryFaults.push(`approver registry unreadable or corrupt: ${errMsg(e)}`);
    registry = null;
  }

  // Derive the read model ONLY from a VERIFIED log. An unverified log must never project its
  // (untrusted, possibly malformed) state into the pages or the write forms — the banner shows
  // the fault and the lists stay empty. A forged role-set with `members: null`, for example,
  // parses and folds but fails verifyChain; folding it anyway would crash the Roles page at
  // `r.members.join(...)` BEFORE the banner renders. Folding can also throw (unknown change
  // kind) even on a chain that verifies — that too becomes a fault, never a page crash.
  let org = "";
  let admins: AdminKey[] = [];
  let roles: Role[] = [];
  let rules: Rule[] = [];
  if (log && policyFaults.length === 0) {
    try {
      const state = log.state();
      org = log.entries[0] ? changeOrg(log.entries[0].change) : "";
      admins = [...state.admins.values()];
      roles = [...state.roles.values()];
      rules = [...state.rules.values()];
      // verifyChain validates required fields but NOT the `org` field or optional string fields
      // (admin `name`, role `description`) — a signed record can still carry an object there, which
      // would render as "[object Object]" in the header or throw at {a.name}/{r.description}. Treat
      // any non-render-safe record (or a non-string org) as a fault.
      if (typeof org !== "string" || !admins.every(isRenderSafeAdmin) || !roles.every(isRenderSafeRole) || !rules.every(isRenderSafeRule)) {
        throw new Error("a policy record has a malformed field (not render-safe)");
      }
    } catch (e) {
      policyFaults.push(`policy log could not be interpreted: ${errMsg(e)}`);
      org = "";
      admins = [];
      roles = [];
      rules = [];
    }
  }

  // Approver projection can THROW (a signed registry record with a malformed actor/key) and must
  // never render an object — guard it inside the registry fault bucket, same as the policy list.
  let approvers: { actor: string; keys: string[] }[] = [];
  if (registry && registryFaults.length === 0) {
    try {
      approvers = [...registry.activeKeyMap().entries()].map(([actor, keys]) => ({ actor, keys: [...keys] }));
      if (!approvers.every(isRenderSafeApprover)) throw new Error("an approver record has a malformed field (not render-safe)");
    } catch (e) {
      registryFaults.push(`approver registry could not be interpreted: ${errMsg(e)}`);
      approvers = [];
    }
  }

  // Receipt-log verification is async (ReceiptLog.verifyAll/verifyChain) and belongs to
  // the Phase 3 Audit screen; not checked here.
  const auditVerified = true;

  const faults = [...policyFaults, ...registryFaults];
  return {
    org,
    verified: faults.length === 0,
    policyVerified: policyFaults.length === 0,
    faults,
    admins,
    roles,
    rules,
    approvers,
    auditVerified,
  };
}
