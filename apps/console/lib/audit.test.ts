// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, appendFileSync, writeFileSync } from "node:fs";
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
    expect(a.decisions[0]).toMatchObject({ decision: "approve", actor: "m:cfo", policy: "approver", signature: "valid" });
    expect(a.receipts.chainIntact).toBe(true);
    expect(a.receipts.total).toBe(1);
    expect(a.receipts.valid).toBe(1);
    expect(a.receipts.invalid).toBe(0);
  });

  it("flags a receipt whose signature does not verify as invalid (tamper evidence)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    const agent = { id: "agent:t", keypair: generateKeypair() };
    const authority = generateKeypair();
    const intent = createIntent({ action: "billing.refund", summary: "Refund", risk_tier: "high", approvers: ["m:cfo"], quorum: 1, timeout: 300, default: "reject" }, agent);
    const receipt = signDecision(intent, "approve", "m:cfo", authority.secretKey, "approver");
    // Tamper AFTER signing: flip the decision. The signature no longer matches.
    const forged = { ...receipt, decision: "reject" };
    appendFileSync(join(dir, "receipts.jsonl"), JSON.stringify(forged) + "\n");

    const a = await loadAuditData(dir);
    expect(a.decisions.length).toBe(1);
    expect(a.decisions[0].signature).toBe("invalid");
    expect(a.receipts.invalid).toBe(1);
    expect(a.receipts.valid).toBe(0);
  });

  it("never renders an object receipt field — shows a flagged placeholder instead of crashing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    const agent = { id: "agent:t", keypair: generateKeypair() };
    const authority = generateKeypair();
    const intent = createIntent({ action: "billing.refund", summary: "Refund", risk_tier: "high", approvers: ["m:cfo"], quorum: 1, timeout: 300, default: "reject" }, agent);
    const receipt = signDecision(intent, "approve", "m:cfo", authority.secretKey, "approver");
    // A receipt whose `actor` is an object (read() does not force it to be a string).
    const malformed = { ...receipt, actor: {} };
    appendFileSync(join(dir, "receipts.jsonl"), JSON.stringify(malformed) + "\n");

    const a = await loadAuditData(dir); // must not throw
    expect(a.decisions.length).toBe(1);
    expect(typeof a.decisions[0].actor).toBe("string"); // never an object to JSX
    expect(a.decisions[0].signature).toBe("invalid");
  });

  it("does not crash on a corrupt receipt line — reports it and still renders policy changes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    writeFileSync(join(dir, "receipts.jsonl"), "not a valid receipt line\n");
    const a = await loadAuditData(dir);
    expect(a.receipts.readable).toBe(false);
    expect(a.receipts.chainIntact).toBe(false);
    expect(a.decisions).toEqual([]);
    // The independent policy change log still renders.
    expect(a.policyReadable).toBe(true);
    expect(a.changes.map((c) => c.kind)).toEqual(["admin-add", "role-set", "rule-set"]);
  });

  it("does not crash on a corrupt policy line — reports it and still renders receipt decisions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-audit-"));
    seedSampleData(dir);
    writeFileSync(join(dir, "policy.jsonl"), "not valid json\n");
    const a = await loadAuditData(dir);
    expect(a.policyReadable).toBe(false);
    expect(a.changes).toEqual([]);
  });
});
