// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Async audit loader for the Audit page: the tamper-evident receipt log (decisions +
// chain-intact status) and the policy change log (who changed which rule/role/admin).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { PolicyLog, ReceiptLog, type PolicyChange } from "@countersignlabs/counter-sign";

export interface AuditDecision {
  intent_id: string;
  decision: string;
  actor: string;
  policy: string; // "approver" | "default"
  timestamp: string;
}
export interface AuditChange {
  seq: number;
  kind: string;
  target: string;
  signer: string;
  issued_at: string;
}
export interface AuditData {
  decisions: AuditDecision[];
  receiptChain: { intact: boolean; length: number; reason?: string };
  changes: AuditChange[];
}

function readOrEmpty(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/** A short human description of what a policy change targets. */
function changeTarget(change: PolicyChange): string {
  switch (change.kind) {
    case "admin-add":
      return `${change.name ? change.name + " · " : ""}${change.public_key.slice(0, 10)}…`;
    case "admin-revoke":
      return `${change.public_key.slice(0, 10)}…`;
    case "role-set":
      return `role ${change.role.name}`;
    case "role-delete":
      return `role ${change.id}`;
    case "rule-set":
      return `rule ${change.rule.name}`;
    case "rule-delete":
      return `rule ${change.id}`;
  }
}

export async function loadAuditData(dataDir: string): Promise<AuditData> {
  const decisions: AuditDecision[] = [];
  let receiptChain = { intact: true, length: 0 } as AuditData["receiptChain"];

  const receiptsPath = join(dataDir, "receipts.jsonl");
  if (existsSync(receiptsPath) && readOrEmpty(receiptsPath).trim().length > 0) {
    const rl = new ReceiptLog(receiptsPath);
    for (const r of await rl.read()) {
      decisions.push({ intent_id: r.intent_id, decision: r.decision, actor: r.actor, policy: r.policy, timestamp: r.timestamp });
    }
    const chain = await rl.verifyChain();
    receiptChain = { intact: chain.intact, length: chain.length, reason: chain.reason };
  }

  const log = PolicyLog.fromJSONL(readOrEmpty(join(dataDir, "policy.jsonl")));
  const changes: AuditChange[] = log.entries.map((e) => ({
    seq: e.seq,
    kind: e.change.kind,
    target: changeTarget(e.change),
    signer: e.signer_public_key,
    issued_at: e.issued_at,
  }));

  return { decisions, receiptChain, changes };
}
