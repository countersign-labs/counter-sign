// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { canonicalPolicyEntry, hashEntry } from "../src/policy/log.js";
import { POLICY_CONTEXT, type PolicyEntry } from "../src/policy/types.js";
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
