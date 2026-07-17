// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PolicyLog } from "../src/policy/log.js";
import { resolveRule } from "../src/policy/resolve.js";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Role, Rule } from "../src/policy/types.js";

const org = generateKeypair(); // org-root (registry attester)
const agent = { id: "agent:x", keypair: generateKeypair() };
const cfo = generateKeypair();
const ceo = generateKeypair();

function enrolledRegistry(): ApproverRegistry {
  const reg = new ApproverRegistry();
  reg.enroll("m:cfo", cfo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });
  reg.enroll("m:ceo", ceo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:ceo", ceo.secretKey) });
  return reg;
}

function storeWith(role: Role, rule: Rule): PolicyLog {
  const admin = generateKeypair();
  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "o1", public_key: admin.publicKey, name: "root" }, admin.secretKey);
  log.append({ kind: "role-set", role }, admin.secretKey);
  log.append({ kind: "rule-set", rule }, admin.secretKey);
  return log;
}

describe("resolveRule", () => {
  const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
  const rule: Rule = { id: "u1", org: "o1", name: "big-refund", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 3600, risk_tier: "high" };

  it("resolves a rule into IntentFields that produce a valid Intent", () => {
    const store = storeWith(role, rule);
    const fields = resolveRule("big-refund", { summary: "Refund $9,000 to cust 42", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" });
    expect(fields.quorum).toBe(2);
    expect(fields.default).toBe("reject");
    expect(fields.timeout).toBe(3600);
    expect(fields.approvers.map((a) => a.actor).sort()).toEqual(["m:ceo", "m:cfo"]);
    expect(fields.approvers.every((a) => a.mode === "keyed" && a.public_key)).toBe(true);
    const intent = createIntent(fields, agent);
    expect(verifyIntent(intent)).toBe(true);
  });

  it("throws on an unknown rule name", () => {
    const store = storeWith(role, rule);
    expect(() => resolveRule("nope", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/no rule/i);
  });

  it("throws when a member has no active enrolled key", () => {
    const store = storeWith({ ...role, members: ["m:cfo", "m:unknown"] }, rule);
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/no active enrolled key/i);
  });

  it("throws when the rule references an unknown role", () => {
    const store = storeWith(role, { ...rule, roles: ["r-missing"] });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/unknown role/i);
  });

  it("requires an action (from rule or request)", () => {
    const store = storeWith(role, { ...rule, action: undefined });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/action/i);
  });
});
