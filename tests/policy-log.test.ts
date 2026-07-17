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

  it("rejects a change for a different org than the log's genesis org", () => {
    const log = bootstrapped(); // genesis org is "o1"
    expect(() => log.append({ kind: "role-set", role: { ...role, org: "o2" } }, rootA.secretKey)).toThrow(/org/i);
  });

  it("role-delete removes a role from state; deleting a missing role throws", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    expect(log.getRoleById("o1", "r1")).toBeDefined();
    log.append({ kind: "role-delete", org: "o1", id: "r1" }, rootA.secretKey);
    expect(log.getRoleById("o1", "r1")).toBeUndefined();
    expect(() => log.append({ kind: "role-delete", org: "o1", id: "r1" }, rootA.secretKey)).toThrow(/does not exist/i);
  });

  it("rule-delete removes a rule from state; deleting a missing rule throws", () => {
    const log = bootstrapped();
    log.append({ kind: "rule-set", rule }, rootA.secretKey);
    expect(log.getRule("o1", "refund")).toBeDefined();
    log.append({ kind: "rule-delete", org: "o1", id: "u1" }, rootA.secretKey);
    expect(log.getRule("o1", "refund")).toBeUndefined();
    expect(() => log.append({ kind: "rule-delete", org: "o1", id: "u1" }, rootA.secretKey)).toThrow(/does not exist/i);
  });

  it("rejects admin-add of an already-active key", () => {
    const log = bootstrapped();
    expect(() => log.append({ kind: "admin-add", org: "o1", public_key: rootA.publicKey, name: "dup" }, rootA.secretKey)).toThrow(/already active/i);
  });
});

describe("PolicyLog.verifyChain", () => {
  it("accepts an honest log", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    expect(log.verifyChain()).toBe(true);
  });
  it("rejects a tampered change (signature no longer matches)", () => {
    const log = bootstrapped();
    log.append({ kind: "rule-set", rule }, rootA.secretKey);
    const entries = JSON.parse(JSON.stringify(log.entries)) as typeof log.entries;
    (entries[1].change as { rule: Rule }).rule.quorum = 5; // tamper post-signature
    expect(new PolicyLog([...entries]).verifyChain()).toBe(false);
  });
  it("rejects an entry forged by a non-admin key", () => {
    const log = bootstrapped();
    // Hand-forge a role-set signed by adminB (never added) with a correct prev/seq.
    const prev = hashEntry(log.entries[0]);
    const unsigned = { countersign: "0.2" as const, seq: 1, change: { kind: "role-set" as const, role }, issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: adminB.publicKey };
    const signature = signContext(adminB.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([...log.entries, { ...unsigned, signature }]).verifyChain()).toBe(false);
  });
  it("rejects a broken prev link", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    const entries = JSON.parse(JSON.stringify(log.entries)) as PolicyEntry[];
    entries[1].prev = "deadbeef";
    expect(new PolicyLog(entries).verifyChain()).toBe(false);
  });
  it("rejects a hand-crafted log whose entries span more than one org", () => {
    const log = bootstrapped(); // genesis org "o1", admin rootA
    // Hand-craft a second entry that is validly signed by the active admin rootA,
    // with a correct prev/seq link, but whose change belongs to a different org.
    // append() would reject this (org mismatch); verifyChain must reject it too.
    const prev = hashEntry(log.entries[0]);
    const unsigned = {
      countersign: "0.2" as const, seq: 1,
      change: { kind: "role-set" as const, role: { ...role, org: "o2" } },
      issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: rootA.publicKey,
    };
    const signature = signContext(rootA.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([...log.entries, { ...unsigned, signature }]).verifyChain()).toBe(false);
  });

  it("rejects a seq gap/duplicate", () => {
    const log = bootstrapped();
    log.append({ kind: "role-set", role }, rootA.secretKey);
    const entries = JSON.parse(JSON.stringify(log.entries)) as PolicyEntry[];
    entries[1].seq = 5; // was 1 — the seq-contiguity check must fire before signature is even considered
    expect(new PolicyLog(entries).verifyChain()).toBe(false);
  });

  it("rejects a genesis entry where the signer is not the key being added", () => {
    // Signature verifies fine (Y really did sign it) — only the genesis self-sign
    // invariant (added key === signer) is what must catch this.
    const x = generateKeypair();
    const y = generateKeypair();
    const unsigned = {
      countersign: "0.2" as const, seq: 0,
      change: { kind: "admin-add" as const, org: "o1", public_key: x.publicKey, name: "root" },
      issued_at: "2026-01-01T00:00:00.000Z", prev: null, signer_public_key: y.publicKey,
    };
    const signature = signContext(y.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([{ ...unsigned, signature }]).verifyChain()).toBe(false);
  });

  it("rejects a forged admin-revoke targeting a key that was never an admin", () => {
    const log = bootstrapped(); // rootA
    log.append({ kind: "admin-add", org: "o1", public_key: adminB.publicKey, name: "b" }, rootA.secretKey); // rootA, adminB
    const neverAdmin = generateKeypair();
    const prev = hashEntry(log.entries[log.entries.length - 1]);
    const unsigned = {
      countersign: "0.2" as const, seq: 2,
      change: { kind: "admin-revoke" as const, org: "o1", public_key: neverAdmin.publicKey },
      issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: rootA.publicKey,
    };
    const signature = signContext(rootA.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([...log.entries, { ...unsigned, signature }]).verifyChain()).toBe(false);
  });

  it("rejects a historical revoke of the last remaining admin", () => {
    const log = bootstrapped(); // rootA only, 1 admin
    const prev = hashEntry(log.entries[0]);
    const unsigned = {
      countersign: "0.2" as const, seq: 1,
      change: { kind: "admin-revoke" as const, org: "o1", public_key: rootA.publicKey },
      issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: rootA.publicKey,
    };
    const signature = signContext(rootA.secretKey, POLICY_CONTEXT, canonicalPolicyEntry(unsigned));
    expect(new PolicyLog([...log.entries, { ...unsigned, signature }]).verifyChain()).toBe(false);
  });

  it("is a total function: returns false (never throws) on a malformed entry", () => {
    const log = bootstrapped();
    const prev = hashEntry(log.entries[0]);
    // Built as a raw literal (not via canonicalPolicyEntry/signContext, which would
    // themselves throw on the NaN) — the bogus signature is never reached because
    // canonicalize throws first, inside verifyChain's own try/catch.
    const malformed: PolicyEntry = {
      countersign: "0.2", seq: 1,
      change: { kind: "rule-set", rule: { ...rule, quorum: NaN as never } },
      issued_at: "2026-01-01T00:00:00.000Z", prev, signer_public_key: rootA.publicKey,
      signature: "sig",
    };
    const badLog = new PolicyLog([...log.entries, malformed]);
    expect(() => badLog.verifyChain()).not.toThrow();
    expect(badLog.verifyChain()).toBe(false);
  });
});
