// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Phase 3: the org-root-attested, hash-chained approver registry closes the
// trust anchor for keyed quorum — a bound key is only trusted if it is an ACTIVE
// enrollment attested by an org-root key distinct from the runtime authority.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ApproverRegistry, assertApproversEnrolled, createEnrollmentProof, enrollmentChallenge, type PasskeyEnrollmentProof } from "../src/registry.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret, signBytes, toB64url, utf8 } from "../src/core/keys.js";
import type { Approver, Intent, Resolution } from "../src/core/types.js";

const RP_ID = "approve.countersignlabs.com";
const ORIGIN = `https://${RP_ID}`;

/** A real passkey (ed25519) credential + a WebAuthn proof of possession bound to `actor`. */
function passkeyEnrollment(actor: string): { cred: string; proof: PasskeyEnrollmentProof } {
  const kp = generateKeypair();
  const cred = `webauthn-ed25519:${kp.publicKey}`;
  const challenge = enrollmentChallenge(actor, cred);
  const authData = Buffer.concat([createHash("sha256").update(utf8(RP_ID)).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN }), "utf8");
  const signed = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  return {
    cred,
    proof: {
      assertion: { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) },
      signature: signBytes(kp.secretKey, signed),
      policy: { rpId: RP_ID, allowedOrigins: [ORIGIN] },
    },
  };
}

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

  it("enrolls a passkey descriptor ONLY with a valid WebAuthn proof of possession", () => {
    const reg = new ApproverRegistry();
    const { cred, proof } = passkeyEnrollment("m:ceo");
    // A descriptor ALONE is refused — it does not prove a registration ceremony,
    // so a compromised intermediary can't have the org root attest a substituted key.
    expect(() => reg.enroll("m:ceo", cred, org.secretKey)).toThrow(/WebAuthn proof of possession/);
    // A genuine PoP for m:ceo cannot enroll a DIFFERENT actor — the challenge binds
    // the actor, so re-targeting it fails.
    expect(() => reg.enroll("m:cfo", cred, org.secretKey, { webauthnPop: proof })).toThrow(/WebAuthn proof of possession/);
    // The genuine ceremony for the right actor works.
    const rec = reg.enroll("m:ceo", cred, org.secretKey, { webauthnPop: proof });
    expect(rec.typ).toBe("enroll");
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

  it("detects TAIL TRUNCATION (rollback) only when the head is anchored", () => {
    const reg = enrolled(); // enroll alice, enroll bob
    reg.revoke("m:alice", alice.publicKey, org.secretKey); // 3rd record — the tail
    expect(reg.isActive("m:alice", alice.publicKey)).toBe(false);
    const anchoredHead = reg.head(); // captured out-of-band BEFORE tampering

    // Attacker (no org key) drops the trailing revoke, resurrecting alice's key.
    const lines = reg.toJSONL().trim().split("\n");
    const truncated = ApproverRegistry.fromJSONL(lines.slice(0, 2).join("\n") + "\n");
    expect(truncated.isActive("m:alice", alice.publicKey)).toBe(true); // resurrected

    // A backward-only chain accepts a prefix — truncation is UNDETECTED without a head…
    expect(truncated.verifyChain(orgPub)).toBe(true);
    // …but the anchored head catches it.
    expect(truncated.verifyChain(orgPub, anchoredHead)).toBe(false);
    // A legitimately-unchanged log still matches its anchored head.
    expect(reg.verifyChain(orgPub, anchoredHead)).toBe(true);
  });

  it("assertApproversEnrolled with an anchored head rejects a truncated registry that resurrects a revoked key", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    reg.revoke("m:alice", alice.publicKey, org.secretKey);
    const head = reg.head();
    const i = keyedIntent([keyed("m:alice", alice)], 1);
    const truncated = ApproverRegistry.fromJSONL(reg.toJSONL().trim().split("\n")[0] + "\n");
    // Without the head the rollback slips through; with it, it fails closed.
    expect(() => assertApproversEnrolled(i, truncated, orgPub, authPub)).not.toThrow();
    expect(() => assertApproversEnrolled(i, truncated, orgPub, authPub, head)).toThrow(/anchored head|active enrollment/);
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
    expect(() => assertApproversEnrolled(i, reg, orgPub, authPub)).not.toThrow();

    // Revoke Bob → the same Intent's approvers are no longer all active.
    reg.revoke("m:bob", bob.publicKey, org.secretKey);
    expect(() => assertApproversEnrolled(i, reg, orgPub, authPub)).toThrow(/not bound to an active enrollment/);
  });

  it("rejects a keyed approver whose bound key was never enrolled", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice), keyed("m:bob", bob)], 2); // bob never enrolled
    expect(() => assertApproversEnrolled(i, reg, orgPub, authPub)).toThrow(/m:bob/);
  });

  it("rejects when the registry chain does not verify under the trusted org key", () => {
    const reg = new ApproverRegistry();
    reg.enroll("m:alice", alice.publicKey, org.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice)], 1);
    expect(() => assertApproversEnrolled(i, reg, generateKeypair().publicKey, authPub)).toThrow(/chain, org signature/);
  });

  it("rejects when the org-root key IS the runtime authority key (separation of duty)", () => {
    // The registry's whole point is an org root DISTINCT from the runtime authority.
    // If a deployment configured them as one key, a compromised authority could also
    // forge enrollments — so the check refuses that configuration outright.
    const reg = new ApproverRegistry();
    // Enroll under a registry whose org root == the authority key.
    reg.enroll("m:alice", alice.publicKey, authority.secretKey, { pop: createEnrollmentProof("m:alice", alice.secretKey) });
    const i = keyedIntent([keyed("m:alice", alice)], 1);
    expect(() => assertApproversEnrolled(i, reg, authPub, authPub)).toThrow(/distinct from the runtime authority/);
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

  it("refuses to append with a WRONG org-key (would produce a mixed-root registry) and exits nonzero", () => {
    const path = join(mkdtempSync(join(tmpdir(), "cs-reg-")), "reg.jsonl");
    execFileSync("npx", ["tsx", "scripts/enroll.ts", "--registry", path, "--actor", "m:alice", "--approver-key", alice.secretKey, "--org-key", org.secretKey], { encoding: "utf8" });
    const wrongOrg = generateKeypair();
    expect(() =>
      execFileSync("npx", ["tsx", "scripts/enroll.ts", "--registry", path, "--actor", "m:bob", "--approver-key", bob.secretKey, "--org-key", wrongOrg.secretKey], { encoding: "utf8", stdio: "pipe" }),
    ).toThrow();
    // The file is unchanged (still one record, chain valid under the original org).
    const reg = ApproverRegistry.fromJSONL(readFileSync(path, "utf8"));
    expect(reg.all.length).toBe(1);
    expect(reg.verifyChain(orgPub)).toBe(true);
  });
});
