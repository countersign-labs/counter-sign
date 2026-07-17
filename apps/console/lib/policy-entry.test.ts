// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Proves the browser-side signer produces entries the REAL library accepts: a
// browser-signed entry, when appended to a PolicyLog, passes verifyChain(). This is
// the load-bearing interop guarantee for the console's client-side write path.
import { describe, expect, it } from "vitest";
import { PolicyLog, generateKeypair } from "@countersignlabs/counter-sign";
import { signPolicyEntry, publicKeyOf } from "./policy-entry";

describe("browser-signed policy entries interoperate with the library", () => {
  it("derives the same public key format as the library", async () => {
    const kp = generateKeypair();
    expect(await publicKeyOf(kp.secretKey)).toBe(kp.publicKey);
  });

  it("a browser-signed genesis admin-add passes verifyChain", async () => {
    const admin = generateKeypair();
    const genesis = await signPolicyEntry(
      { kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root" },
      { length: 0, hash: "" },
      admin.secretKey,
    );
    expect(new PolicyLog([genesis as never]).verifyChain()).toBe(true);
  });

  it("a browser-signed role-set + rule-set chain past genesis passes verifyChain", async () => {
    const admin = generateKeypair();
    const genesis = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root" }, { length: 0, hash: "" }, admin.secretKey);
    const log1 = new PolicyLog([genesis as never]);

    const role = await signPolicyEntry(
      { kind: "role-set", role: { id: "finance", org: "acme", name: "finance", members: ["m:cfo"] } },
      log1.head(),
      admin.secretKey,
    );
    const log2 = new PolicyLog([genesis as never, role as never]);
    expect(log2.verifyChain()).toBe(true);

    const rule = await signPolicyEntry(
      { kind: "rule-set", rule: { id: "refund", org: "acme", name: "refund", roles: ["finance"], quorum: 1, default: "reject", timeout_seconds: 3600, action: "billing.refund", risk_tier: "high" } },
      log2.head(),
      admin.secretKey,
    );
    const log3 = new PolicyLog([genesis as never, role as never, rule as never]);
    expect(log3.verifyChain()).toBe(true);
  });

  it("a tampered browser-signed entry (change edited after signing) fails verifyChain", async () => {
    const admin = generateKeypair();
    const genesis = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, { length: 0, hash: "" }, admin.secretKey);
    const role = await signPolicyEntry({ kind: "role-set", role: { id: "r", org: "acme", name: "r", members: ["m:x"] } }, new PolicyLog([genesis as never]).head(), admin.secretKey);
    // Edit the signed change — the signature no longer matches.
    (role.change as { role: { members: string[] } }).role.members = ["m:evil"];
    expect(new PolicyLog([genesis as never, role as never]).verifyChain()).toBe(false);
  });
});
