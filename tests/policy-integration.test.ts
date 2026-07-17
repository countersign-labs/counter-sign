// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PolicyLog, resolveRule } from "../src/index.js";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";

describe("policy layer end-to-end", () => {
  it("bootstrap admin -> role -> rule -> resolve -> Intent, with a verifiable policy chain", () => {
    const root = generateKeypair();
    const org = generateKeypair();
    const agent = { id: "agent:x", keypair: generateKeypair() };
    const cfo = generateKeypair();
    const ceo = generateKeypair();

    const reg = new ApproverRegistry();
    reg.enroll("m:cfo", cfo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });
    reg.enroll("m:ceo", ceo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:ceo", ceo.secretKey) });

    const log = new PolicyLog();
    log.append({ kind: "admin-add", org: "o1", public_key: root.publicKey, name: "root" }, root.secretKey);
    log.append({ kind: "role-set", role: { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] } }, root.secretKey);
    log.append({ kind: "rule-set", rule: { id: "u1", org: "o1", name: "wire", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 7200, action: "treasury.wire", risk_tier: "critical" } }, root.secretKey);

    expect(log.verifyChain()).toBe(true);

    const fields = resolveRule("wire", { summary: "Wire $250k to escrow" }, { store: log, registry: reg, org: "o1" });
    const intent = createIntent(fields, agent);
    expect(verifyIntent(intent)).toBe(true);
    expect(intent.quorum).toBe(2);
    expect(intent.timeout).toBe(7200);

    // Round-trips through JSONL unchanged.
    const reloaded = PolicyLog.fromJSONL(log.toJSONL());
    expect(reloaded.verifyChain()).toBe(true);
    expect(reloaded.getRule("o1", "wire")?.action).toBe("treasury.wire");
  });
});
