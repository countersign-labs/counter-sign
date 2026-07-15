// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Phase 3: the org-root-attested, hash-chained approver registry closes the
// trust anchor for keyed quorum — a bound key is only trusted if it is an ACTIVE
// enrollment attested by an org-root key distinct from the runtime authority.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ApproverRegistry, assertApproversEnrolled, createEnrollmentProof } from "../src/registry.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Approver, Intent, Resolution } from "../src/core/types.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);
const org = generateKeypair(); // the org-root key — DISTINCT from the authority key
const orgPub = publicKeyFromSecret(org.secretKey);
const alice = generateKeypair();
const bob = generateKeypair();

const keyed = (actor: string, kp: { publicKey: string }): Approver => ({ actor, mode: "keyed", public_key: kp.publicKey });
function keyedIntent(approvers: Approver[], quorum: number): Intent {
  return createIntent({ action: "prod.deploy", summary: "Deploy", risk_tier: "critical", approvers, quorum, timeout: 300, default: "reject" }, agent);
}

describe("enrollment", () => {
  it("enrolls a raw ed25519 key with proof of possession, refusing a bad/missing PoP", () => {
    const reg = new ApproverRegistry();
    expect(() => reg.enroll("m:alice", alice.publicKey, org.secretKey)).toThrow(/proof of possession/);
    // A PoP from the WRONG key is refused.
    expect(() => reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", bob.secretKey) })).toThrow(/proof of possession/);
    // The genuine PoP works.
    const rec = reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    expect(rec.typ).toBe("enroll");
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(true);
  });

  it("enrolls a passkey descriptor without a raw PoP (registration proved possession)", () => {
    const reg = new ApproverRegistry();
    const cred = `webauthn-p256:${Buffer.alloc(65, 4).toString("base64url")}`;
    reg.enroll("m:ceo", cred, org.secretKey);
    expect(reg.isActive("m:ceo", cred)).toBe(true);
  });

  it("refuses a malformed key and a duplicate active enrollment", () => {
    const reg = new ApproverRegistry();
    expect(() => reg.enroll("m:x", "not-a-key", org.secretKey)).toThrow(/malformed/);
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    expect(() => reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) })).toThrow(/already enrolled/);
  });
});

describe("chain integrity & revocation", () => {
  function enrolled(): ApproverRegistry {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    reg.enroll("m:bob", bob.publicKey, org.secretKey, { pop: createEnrollmentProof("m:bob", bob.secretKey) });
    return reg;
  }

  it("verifies a clean chain against the org key, and rejects a wrong org key", () => {
    const reg = enrolled();
    expect(reg.verifyChain(orgPub)).toBe(true);
    expect(reg.verifyChain(generateKeypair().publicKey)).toBe(false);
  });

  it("detects tampering (an edited record breaks the signature/chain)", () => {
    const reg = enrolled();
    const tampered = ApproverRegistry.fromJSONL(reg.toJSONL().replace("m:bob", "m:mallory"));
    expect(tampered.verifyChain(orgPub)).toBe(false);
  });

  it("detects a removed/reordered record via the hash chain", () => {
    const reg = enrolled();
    const lines = reg.toJSONL().trim().split("\n");
    const dropped = ApproverRegistry.fromJSONL(lines[1] + "\n"); // keep only the 2nd — its prev points at a missing 1st
    expect(dropped.verifyChain(orgPub)).toBe(false);
  });

  it("revocation deactivates a key; re-enrollment reactivates", () => {
    const reg = enrolled();
    reg.revoke("m:alice", alice.publicKey, org.secretKey);
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(false);
    expect(reg.verifyChain(orgPub)).toBe(true); // chain still intact
    expect(() => reg.revoke("m:alice", alice.publicKey, org.secretKey)).toThrow(/no active enrollment/);
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(true);
  });

  it("round-trips through JSONL persistence", () => {
    const reg = enrolled();
    const reloaded = ApproverRegistry.fromJSONL(reg.toJSONL());
    expect(reloaded.verifyChain(orgPub)).toBe(true);
    expect(reloaded.isActive("m:bob", bob.publicKey)).toBe(true);
  });
});

describe("assertApproversEnrolled (strict mode) + end-to-end", () => {
  const res = (css: Resolution["countersignatures"]): Resolution => ({ decision: "approve", policy: "approver", countersignatures: css });

  it("passes when every keyed approver is actively enrolled, then fails after revocation", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    reg.enroll("m:bob", bob.publicKey, org.secretKey, { pop: createEnrollmentProof("m:bob", bob.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice), keyed("m:bob", bob)], 2);

    // The cryptographic quorum verifies AND the identities are registry-anchored.
    const r = res([signDecision(i, "approve", "m:alice", alice.secretKey, "approver"), signDecision(i, "approve", "m:bob", bob.secretKey, "approver")]);
    expect(() => verifyResolution(i, r, authPub)).not.toThrow();
    expect(() => assertApproversEnrolled(i, reg, orgPub)).not.toThrow();

    // Revoke Bob → the same Intent's approvers are no longer all active.
    reg.revoke("m:bob", bob.publicKey, org.secretKey);
    expect(() => assertApproversEnrolled(i, reg, orgPub)).toThrow(/not bound to an active enrollment/);
  });

  it("rejects a keyed approver whose bound key was never enrolled", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice), keyed("m:bob", bob)], 2); // bob never enrolled
    expect(() => assertApproversEnrolled(i, reg, orgPub)).toThrow(/m:bob/);
  });

  it("rejects when the registry chain does not verify under the trusted org key", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice)], 1);
    expect(() => assertApproversEnrolled(i, reg, generateKeypair().publicKey)).toThrow(/chain or org signature/);
  });
});

describe("the enroll CLI", () => {
  it("enrolls a raw approver (computing PoP), writing a chain-valid registry, then revokes", () => {
    const path = join(mkdtempSync(join(tmpdir(), "cs-reg-")), "reg.jsonl");
    execFileSync("npx", ["tsx", "scripts/enroll.ts", "--registry", path, "--actor", "m:alice", "--approver-key", alice.secretKey, "--org-key", org.secretKey], { encoding: "utf8" });
    let reg = ApproverRegistry.fromJSONL(readFileSync(path, "utf8"));
    expect(reg.verifyChain(orgPub)).toBe(true);
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(true);

    execFileSync("npx", ["tsx", "scripts/enroll.ts", "--registry", path, "--actor", "m:alice", "--public-key", alice.publicKey, "--org-key", org.secretKey, "--revoke"], { encoding: "utf8" });
    reg = ApproverRegistry.fromJSONL(readFileSync(path, "utf8"));
    expect(reg.verifyChain(orgPub)).toBe(true);
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(false);
  });
});
