// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Phase 2: a passkey (WebAuthn) approver's receipt is verified through the same
// choke points as any keyed receipt (verifyResolution / record), against the
// approver's bound credential and the deployment RP policy. Receipts are minted
// here exactly as the browser signing page would, so the test is independent of
// the verifier's code.

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PendingDecisions } from "../src/adapter.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { canonicalize } from "../src/core/canonical.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution, awaitWithDefault } from "../src/core/defaults.js";
import { InvalidCountersignatureError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { fromB64url, generateKeypair, publicKeyFromSecret, signBytes, toB64url, utf8 } from "../src/core/keys.js";
import { COUNTERSIGN_VERSION, COUNTERSIGNATURE_CONTEXT, type Approver, type Countersignature, type Intent, type Resolution } from "../src/core/types.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);
const rpId = "approve.countersignlabs.com";
const origin = `https://${rpId}`;
const policy = { rpId, allowedOrigins: [origin] };

interface Credential { credential: string; sign: (data: Buffer) => Buffer }
function ed25519Credential(): Credential {
  const kp = generateKeypair();
  return { credential: `webauthn-ed25519:${kp.publicKey}`, sign: (data) => fromB64url(signBytes(kp.secretKey, data)) };
}
function p256Credential(): Credential {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = publicKey.export({ type: "spki", format: "der" });
  const point = der.subarray(der.length - 65);
  return { credential: `webauthn-p256:${toB64url(point)}`, sign: (data) => cryptoSign("sha256", data, privateKey) };
}

/** Mint a passkey receipt exactly as the browser signing page would. */
function passkeyReceipt(
  intent: Intent,
  decision: "approve" | "reject",
  actor: string,
  cred: Credential,
  over: { flags?: number; org?: string } = {},
): Countersignature {
  const unsigned = {
    countersign: COUNTERSIGN_VERSION,
    intent_id: intent.intent_id,
    decision,
    actor,
    policy: "approver" as const,
    timestamp: new Date().toISOString(),
    public_key: cred.credential,
  };
  const challenge = toB64url(createHash("sha256").update(utf8(`${COUNTERSIGNATURE_CONTEXT}\n${canonicalize(unsigned)}`)).digest());
  const rpIdHash = createHash("sha256").update(utf8(rpId)).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([over.flags ?? 0x05]), Buffer.from([0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: over.org ?? origin }), "utf8");
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  return {
    ...unsigned,
    signature: toB64url(cred.sign(signedData)),
    webauthn: { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) },
  };
}

const keyedApprover = (actor: string, credential: string): Approver => ({ actor, mode: "keyed", public_key: credential });
function intentWith(approvers: Approver[], quorum: number): Intent {
  return createIntent({ action: "prod.deploy", summary: "Deploy 2.4.0", risk_tier: "critical", approvers, quorum, timeout: 300, default: "reject" }, agent);
}
const res = (decision: "approve" | "reject", css: Countersignature[]): Resolution => ({ decision, policy: "approver", countersignatures: css });

describe("passkey receipts verify through the keyed choke point", () => {
  it("accepts an Ed25519 passkey approval (quorum 1) with the RP policy", () => {
    const cred = ed25519Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const r = res("approve", [passkeyReceipt(i, "approve", "m:ceo", cred)]);
    expect(() => verifyResolution(i, r, authPub, policy)).not.toThrow();
  });

  it("accepts a P-256 passkey approval with the RP policy", () => {
    const cred = p256Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const r = res("approve", [passkeyReceipt(i, "approve", "m:ceo", cred)]);
    expect(() => verifyResolution(i, r, authPub, policy)).not.toThrow();
  });

  it("FAILS CLOSED without an RP policy (a passkey receipt cannot be verified)", () => {
    const cred = p256Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const r = res("approve", [passkeyReceipt(i, "approve", "m:ceo", cred)]);
    expect(() => verifyResolution(i, r, authPub)).toThrow(InvalidCountersignatureError);
  });

  it("rejects an assertion produced at a disallowed origin (phishing)", () => {
    const cred = ed25519Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const r = res("approve", [passkeyReceipt(i, "approve", "m:ceo", cred, { org: "https://evil.example.com" })]);
    expect(() => verifyResolution(i, r, authPub, policy)).toThrow(InvalidCountersignatureError);
  });

  it("rejects a passkey receipt replayed onto a DIFFERENT intent (challenge binds the receipt)", () => {
    const cred = p256Credential();
    const i1 = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const i2 = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const receipt = passkeyReceipt(i1, "approve", "m:ceo", cred);
    // Re-point the receipt at i2 — its assertion challenge no longer matches i2's digest.
    const replayed = { ...receipt, intent_id: i2.intent_id };
    expect(() => verifyResolution(i2, res("approve", [replayed]), authPub, policy)).toThrow(InvalidCountersignatureError);
  });

  it("a mixed keyed quorum (raw-ed25519 + passkey) verifies", () => {
    const raw = generateKeypair();
    const cred = p256Credential();
    const i = intentWith([keyedApprover("m:eng", raw.publicKey), keyedApprover("m:ceo", cred.credential)], 2);
    const r = res("approve", [
      signDecision(i, "approve", "m:eng", raw.secretKey, "approver"),
      passkeyReceipt(i, "approve", "m:ceo", cred),
    ]);
    expect(() => verifyResolution(i, r, authPub, policy)).not.toThrow();
  });

  it("record() accumulates a passkey receipt with the RP policy, and ignores it without", () => {
    const cred = ed25519Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const pd = new PendingDecisions();
    void pd.wait(i);
    const receipt = passkeyReceipt(i, "approve", "m:ceo", cred);
    expect(pd.record(receipt)).toBeNull(); // no policy → cannot verify → ignored
    expect(pd.record(receipt, policy)?.status).toBe("resolved");
  });

  it("ReceiptLog.verifyAll validates a logged passkey receipt only WITH the RP policy", async () => {
    const cred = ed25519Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    const receipt = passkeyReceipt(i, "approve", "m:ceo", cred);
    const log = new ReceiptLog(join(mkdtempSync(join(tmpdir(), "cs-pk-log-")), "r.jsonl"));
    await log.append(receipt);
    expect((await log.verifyAll({ webauthn: policy })).ok).toBe(true);
    // Without the policy, a passkey receipt cannot be verified → flagged, not silently valid.
    expect((await log.verifyAll()).faults.some((f) => f.reason === "invalid-signature")).toBe(true);
  });

  it("HEADLINE holds: the authority key cannot forge a passkey slot", async () => {
    const cred = p256Credential();
    const i = intentWith([keyedApprover("m:ceo", cred.credential)], 1);
    // Authority tries an ordinary ed25519 receipt for the passkey slot.
    const forged = res("approve", [signDecision(i, "approve", "m:ceo", authority.secretKey, "approver")]);
    await expect(awaitWithDefault(i, Promise.resolve(forged), authority.secretKey, policy)).rejects.toThrow();
  });
});
