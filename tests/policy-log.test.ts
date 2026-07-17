// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { canonicalPolicyEntry, hashEntry, PolicyLog } from "../src/policy/log.js";
import { POLICY_CONTEXT, type PolicyEntry } from "../src/policy/types.js";
import type { Role, Rule } from "../src/policy/types.js";
import { generateKeypair, signContext, verifyContext } from "../src/core/keys.js";

const admin = generateKeypair();
function unsigned(): Omit<PolicyEntry, "signature"> {
  return {
    countersign: "0.2", seq: 0,
    change: { kind: "admin-add", org: "o1", public_key: admin.publicKey, name: "root" },
    issued_at: "2026-01-01T00:00:00.000Z", prev: null, signer_public_key: admin.publicKey,
  };
}

describe("policy entry signing", () => {
  it("round-trips a signature over the canonical unsigned entry", () => {
    const u = unsigned();
    const sig = signContext(admin.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(u));
    expect(verifyContext(admin.publicKey, POLICY_CONTEXT, canonicalPolicyEntry(u), sig)).toBe(true);
  });
  it("hashEntry is stable and changes when a field changes", () => {
    const e: PolicyEntry = { ...unsigned(), signature: "sig" };
    expect(hashEntry(e)).toBe(hashEntry({ ...e }));
    expect(hashEntry(e)).not.toBe(hashEntry({ ...e, seq: 1 }));
    expect(hashEntry(e)).not.toBe(hashEntry({ ...e, signature: "other-sig" }));
  });
});

const rootA = generateKeypair();
const adminB = generateKeypair();
const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo"] };
const rule: Rule = { id: "u1", org: "o1", name: "refund", roles: ["r1"], quorum: 1, default: "reject", timeout_seconds: 3600 };

function bootstrapped(): PolicyLog {
  const log = new PolicyLog();
  log.append({ kind: "admin-add", org: "o1", public_key: rootA.publicKey, name: "root" }, rootA.secretKey);
  return log;
}

describe("PolicyLog append/state", () => {
  it("genesis must be a self-signed admin-add", () => {
    const log = new PolicyLog();
    expect(() => log.append({ kind: "role-set", role }, rootA.secretKey)).toThrow(/genesis/i);
    expect(() => log.append({ kind: "admin-add", org: "o1", public_key: adminB.publicKey }, rootA.secretKey)).toThrow(/self/i);
  });

  it("records roles and rules and folds them into state", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    log.append({ kind: "rule-set", rule }, rootA.secretKey);
    expect(log.getRule("o1", "refund")).toMatchObject({ id: "u1", quorum: 1 });
    expect(log.getRoleById("o1", "r1")?.members).toEqual(["m:cfo"]);
    expect(log.listAdmins("o1").map((a) => a.public_key)).toEqual([rootA.publicKey]);
  });

  it("rejects a change signed by a non-admin key", () => {
    const log = bootstrapped();
    expect(() => log.append({ kind: "role-set", role }, adminB.secretKey)).toThrow(/not an active admin/i);
  });

  it("an existing admin can add a second admin, who can then sign", () => {
    const log = bootstrapped();
    log.append({ kind: "admin-add", org: "o1", public_key: adminB.publicKey, name: "b" }, rootA.secretKey);
    expect(() => log.append({ kind: "role-set", role }, adminB.secretKey)).not.toThrow();
    expect(log.listAdmins("o1").length).toBe(2);
  });

  it("refuses to revoke the last remaining admin", () => {
    const log = bootstrapped();
    expect(() => log.append({ kind: "admin-revoke", org: "o1", public_key: rootA.publicKey }, rootA.secretKey)).toThrow(/last/i);
  });

  it("validates rule invariants on rule-set (quorum>1 + default approve rejected)", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    const bad: Rule = { ...rule, id: "u2", name: "bad", quorum: 2, default: "approve" };
    expect(() => log.append({ kind: "rule-set", rule: bad }, rootA.secretKey)).toThrow(/quorum > 1/);
  });
});
