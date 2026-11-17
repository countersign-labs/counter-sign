// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PolicyLog } from "../src/policy/log.js";
import { resolveRule } from "../src/policy/resolve.js";
import { ApproverRegistry, createEnrollmentProof } from "../src/registry.js";
import { createIntent, verifyIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { assertVouchedApprovers } from "../src/adapter.js";
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

  it("throws when an actor has multiple active keys", () => {
    const store = storeWith(role, rule);
    const reg = new ApproverRegistry();
    reg.enroll("m:cfo", cfo.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", cfo.secretKey) });
    const secondKp = generateKeypair();
    reg.enroll("m:cfo", secondKp.publicKey, org.secretKey, { pop: createEnrollmentProof("m:cfo", secondKp.secretKey) });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: reg, org: "o1" })).toThrow(/multiple active keys/i);
  });

  it("throws when distinct approvers are fewer than the rule's quorum", () => {
    const store = storeWith({ ...role, members: ["m:cfo"] }, { ...rule, quorum: 2, default: "reject" });
    expect(() => resolveRule("big-refund", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/quorum/i);
  });

  it("requires a risk_tier (from rule or request)", () => {
    const store = storeWith(role, { ...rule, risk_tier: undefined });
    expect(() => resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/risk_tier/i);
  });

  it("requires a summary", () => {
    const store = storeWith(role, rule);
    expect(() => resolveRule("big-refund", { summary: "", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" })).toThrow(/summary/i);
  });

  it("fails closed when the underlying policy log is tampered (unverified store)", () => {
    const store = storeWith(role, rule);
    // Confirm the valid path works before tampering.
    expect(() =>
      resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" }),
    ).not.toThrow();

    // Tamper a persisted entry's change post-signature (bypasses append()'s validation,
    // simulating a signed-but-then-edited log file on disk).
    const entries = JSON.parse(JSON.stringify(store.entries)) as typeof store.entries;
    (entries[2].change as { rule: Rule }).rule.quorum = 99;
    const tampered = new PolicyLog(entries);
    expect(tampered.verifyChain()).toBe(false);

    expect(() =>
      resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store: tampered, registry: enrolledRegistry(), org: "o1" }),
    ).toThrow(/verification|tampered|unverified/i);
  });

  it("dedups an actor referenced by multiple roles", () => {
    const r1: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
    const r2: Role = { id: "r2", org: "o1", name: "exec", members: ["m:cfo"] };
    const admin = generateKeypair();
    const log = new PolicyLog();
    log.append({ kind: "admin-add", org: "o1", public_key: admin.publicKey, name: "root" }, admin.secretKey);
    log.append({ kind: "role-set", role: r1 }, admin.secretKey);
    log.append({ kind: "role-set", role: r2 }, admin.secretKey);
    log.append({ kind: "rule-set", rule: { ...rule, roles: ["r1", "r2"], quorum: 2 } }, admin.secretKey);
    const fields = resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store: log, registry: enrolledRegistry(), org: "o1" });
    expect(fields.approvers.filter((a) => a.actor === "m:cfo").length).toBe(1);
  });
});

// Opt-in vouched resolution: a policy rule feeding a chat (button-webhook) adapter.
// The chat adapters accept only vouched approvers (assertVouchedApprovers), and a
// vouched slot is only allowed at quorum 1, so this path refuses any other quorum.
describe("resolveRule with { approvers: \"vouched\" }", () => {
  const chatRole: Role = { id: "r-chat", org: "o1", name: "post-approvers", members: ["slack:U024BE7LH", "Telegram:8675309 "] };
  const chatRule: Rule = { id: "u-chat", org: "o1", name: "publish-post", roles: ["r-chat"], quorum: 1, default: "reject", timeout_seconds: 259200, risk_tier: "high", action: "kaviyam.post.publish" };
  const authority = generateKeypair();

  it("leaves the default (keyed) output unchanged, which a chat adapter refuses", () => {
    const store = storeWith(role(), rule());
    const fields = resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" });
    expect(fields.approvers.every((a) => a.mode === "keyed")).toBe(true);
    expect(() => assertVouchedApprovers(createIntent(fields, agent))).toThrow(/keyed/);
  });

  it("resolves members to vouched approvers that a chat adapter accepts, with no registry needed", () => {
    const store = storeWith(chatRole, chatRule);
    const fields = resolveRule("publish-post", { summary: "Post to LinkedIn: the words" }, { store, org: "o1" }, { approvers: "vouched" });
    expect(fields.approvers).toEqual([
      { actor: "slack:u024be7lh", mode: "vouched" },
      { actor: "telegram:8675309", mode: "vouched" },
    ]);
    expect(fields.quorum).toBe(1);
    expect(fields.default).toBe("reject");
    expect(fields.timeout).toBe(259200);
    expect(fields.action).toBe("kaviyam.post.publish");
    const intent = createIntent(fields, agent);
    expect(verifyIntent(intent)).toBe(true);
    expect(() => assertVouchedApprovers(intent)).not.toThrow();
    // A vouched receipt from a listed member resolves the Intent end to end.
    const cs = signDecision(intent, "approve", "slack:U024BE7LH", authority.secretKey);
    expect(() => verifyResolution(intent, { decision: "approve", policy: "approver", countersignatures: [cs] }, authority.publicKey)).not.toThrow();
  });

  it("ignores the registry even when one is supplied (no key is bound to a vouched slot)", () => {
    const store = storeWith({ ...chatRole, members: ["m:cfo"] }, chatRule);
    const fields = resolveRule("publish-post", { summary: "x" }, { store, registry: enrolledRegistry(), org: "o1" }, { approvers: "vouched" });
    expect(fields.approvers).toEqual([{ actor: "m:cfo", mode: "vouched" }]);
  });

  it("refuses a rule whose quorum is above 1, naming the reason", () => {
    const store = storeWith({ ...chatRole, members: ["slack:a", "slack:b"] }, { ...chatRule, quorum: 2 });
    expect(() => resolveRule("publish-post", { summary: "x" }, { store, org: "o1" }, { approvers: "vouched" })).toThrow(
      /quorum 2.*vouched.*quorum 1/i,
    );
  });

  it("can keep only the members on one channel, and refuses when none are left", () => {
    const store = storeWith(chatRole, chatRule);
    const fields = resolveRule("publish-post", { summary: "x" }, { store, org: "o1" }, { approvers: "vouched", channel: "telegram" });
    expect(fields.approvers).toEqual([{ actor: "telegram:8675309", mode: "vouched" }]);
    expect(() => resolveRule("publish-post", { summary: "x" }, { store, org: "o1" }, { approvers: "vouched", channel: "whatsapp" })).toThrow(
      /no member on channel whatsapp/i,
    );
  });

  it("refuses a channel filter without vouched mode, and an unknown approver mode", () => {
    const store = storeWith(role(), rule());
    expect(() =>
      resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" }, { channel: "slack" } as never),
    ).toThrow(/channel.*vouched/i);
    expect(() =>
      resolveRule("big-refund", { summary: "x", action: "billing.refund" }, { store, registry: enrolledRegistry(), org: "o1" }, { approvers: "both" } as never),
    ).toThrow(/approvers/i);
  });

  it("keyed mode named explicitly behaves exactly like the default and still needs the registry", () => {
    const store = storeWith(role(), rule());
    const deps = { store, registry: enrolledRegistry(), org: "o1" };
    const req = { summary: "x", action: "billing.refund" };
    expect(resolveRule("big-refund", req, deps, { approvers: "keyed" })).toEqual(resolveRule("big-refund", req, deps));
    expect(() => resolveRule("big-refund", req, { store, org: "o1" } as never, { approvers: "keyed" })).toThrow(/registry/i);
  });

  it("still fails closed on an unverified policy store", () => {
    const store = storeWith(chatRole, chatRule);
    const entries = JSON.parse(JSON.stringify(store.entries)) as typeof store.entries;
    // Swap the signed member list for an attacker's chat account after signing.
    (entries[1].change as { role: Role }).role.members = ["slack:attacker"];
    const tampered = new PolicyLog(entries);
    expect(() => resolveRule("publish-post", { summary: "x" }, { store: tampered, org: "o1" }, { approvers: "vouched" })).toThrow(
      /verification|tampered|unverified/i,
    );
  });

  // Helpers so the keyed fixtures above can be reused without hoisting them.
  function role(): Role {
    return { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
  }
  function rule(): Rule {
    return { id: "u1", org: "o1", name: "big-refund", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 3600, risk_tier: "high" };
  }
});
