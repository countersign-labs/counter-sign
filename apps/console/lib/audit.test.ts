// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ReceiptLog, generateKeypair, signDecision, createIntent } from "@countersignlabs/counter-sign";
import { seedSampleData } from "./seed";
import { loadAuditData } from "./audit";

describe("loadAuditData", () => {
  it("reports the policy change log from a seeded data dir", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    const a = await loadAuditData(dir);
    // genesis admin-add + role-set + rule-set
    expect(a.changes.map((c) => c.kind)).toEqual(["admin-add", "role-set", "rule-set"]);
    expect(a.changes.find((c) => c.kind === "rule-set")?.target).toContain("refund");
    expect(a.decisions).toEqual([]); // no receipts yet
  });

  it("reports decisions and an intact chain when receipts exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    const agent = { id: "agent:t", keypair: generateKeypair() };
    const authority = generateKeypair();
    const intent = createIntent({ action: "billing.refund", summary: "Refund", risk_tier: "high", approvers: ["m:cfo"], quorum: 1, timeout: 300, default: "reject" }, agent);
    const rl = new ReceiptLog(join(dir, "receipts.jsonl"));
    await rl.append(signDecision(intent, "approve", "m:cfo", authority.secretKey, "approver"));

    const a = await loadAuditData(dir);
    expect(a.decisions.length).toBe(1);
    expect(a.decisions[0]).toMatchObject({ decision: "approve", actor: "m:cfo", policy: "approver" });
    expect(a.receiptChain.intact).toBe(true);
    expect(a.receiptChain.length).toBe(1);
  });
});
