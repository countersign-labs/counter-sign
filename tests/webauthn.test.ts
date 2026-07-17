// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// WebAuthn (passkey) assertion verification. Assertions are constructed here
// exactly as a browser + authenticator would (independent of the verifier's
// code), so agreement proves the verifier follows the WebAuthn spec.

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateKeypair, signBytes, toB64url, utf8, fromB64url } from "../src/core/keys.js";
import { isValidCredentialDescriptor, isWebAuthnCredential, verifyWebAuthnAssertion, type WebAuthnAssertion } from "../src/core/webauthn.js";

const rpId = "approve.countersignlabs.com";
const origin = `https://${rpId}`;
const challenge = toB64url(createHash("sha256").update("a-receipt-digest").digest()); // stand-in receipt digest

function authenticatorData(flags = 0x05 /* UP|UV */, rp = rpId): Buffer {
  const rpIdHash = createHash("sha256").update(utf8(rp)).digest();
  const signCount = Buffer.from([0, 0, 0, 7]);
  return Buffer.concat([rpIdHash, Buffer.from([flags]), signCount]);
}

function clientDataJSON(over: Record<string, unknown> = {}): Buffer {
  return Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, ...over }), "utf8");
}

/** Build a signed assertion for an Ed25519 passkey. */
function ed25519Assertion(over: { flags?: number; client?: Record<string, unknown>; rp?: string } = {}) {
  const kp = generateKeypair();
  const authData = authenticatorData(over.flags, over.rp);
  const clientData = clientDataJSON(over.client);
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = signBytes(kp.secretKey, signedData);
  const assertion: WebAuthnAssertion = { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) };
  return { credential: `webauthn-ed25519:${kp.publicKey}`, assertion, signature, kp };
}

/** Build a signed assertion for a P-256 passkey (ES256, DER ECDSA). */
function p256Assertion(over: { flags?: number; client?: Record<string, unknown>; rp?: string } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = publicKey.export({ type: "spki", format: "der" });
  const point = der.subarray(der.length - 65); // 0x04 || x || y
  const authData = authenticatorData(over.flags, over.rp);
  const clientData = clientDataJSON(over.client);
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = toB64url(cryptoSign("sha256", signedData, privateKey)); // DER ECDSA
  const assertion: WebAuthnAssertion = { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) };
  return { credential: `webauthn-p256:${toB64url(point)}`, assertion, signature };
}

const opts = (credential: string, over: Record<string, unknown> = {}) => ({
  credential,
  expectedChallenge: challenge,
  rpId,
  allowedOrigins: [origin],
  ...over,
});

describe("verifyWebAuthnAssertion — positive", () => {
  it("accepts a valid Ed25519 assertion", () => {
    const a = ed25519Assertion();
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(true);
  });

  it("accepts a valid P-256 assertion", () => {
    const a = p256Assertion();
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(true);
  });

  it("enforces User Verification when required", () => {
    const uv = p256Assertion({ flags: 0x05 }); // UP|UV
    expect(verifyWebAuthnAssertion(uv.assertion, uv.signature, opts(uv.credential, { requireUserVerification: true }))).toBe(true);
    const upOnly = p256Assertion({ flags: 0x01 }); // UP only
    expect(verifyWebAuthnAssertion(upOnly.assertion, upOnly.signature, opts(upOnly.credential, { requireUserVerification: true }))).toBe(false);
  });
});

describe("verifyWebAuthnAssertion — negative (each check fails closed)", () => {
  it("rejects a mismatched challenge (replay to a different decision)", () => {
    const a = p256Assertion();
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential, { expectedChallenge: toB64url(createHash("sha256").update("other").digest()) }))).toBe(false);
  });

  it("rejects a disallowed origin (phishing)", () => {
    const a = ed25519Assertion({ client: { origin: "https://evil.example.com" } });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
  });

  it("rejects a wrong RP-ID hash", () => {
    const a = p256Assertion({ rp: "evil.example.com" });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
  });

  it("rejects a missing User Present flag", () => {
    const a = p256Assertion({ flags: 0x00 });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
  });

  it("rejects a non-'webauthn.get' clientData type", () => {
    const a = ed25519Assertion({ client: { type: "webauthn.create" } });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
  });

  it("rejects an assertion made in a cross-origin frame", () => {
    const a = p256Assertion({ client: { crossOrigin: true } });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
  });

  it("rejects a tampered signature", () => {
    const a = p256Assertion();
    const bad = toB64url(Buffer.concat([fromB64url(a.signature).subarray(0, -1), Buffer.from([0xff])]));
    expect(verifyWebAuthnAssertion(a.assertion, bad, opts(a.credential))).toBe(false);
  });

  it("rejects a signature verified against the WRONG credential key", () => {
    const a = p256Assertion();
    const other = p256Assertion();
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(other.credential))).toBe(false);
  });

  it("rejects an ed25519 assertion presented under a p256 descriptor (and vice-versa)", () => {
    const ed = ed25519Assertion();
    expect(verifyWebAuthnAssertion(ed.assertion, ed.signature, opts(`webauthn-p256:${toB64url(Buffer.alloc(65, 4))}`))).toBe(false);
  });

  it("rejects malformed inputs without throwing", () => {
    expect(verifyWebAuthnAssertion({ authenticator_data: "!!", client_data_json: "!!" }, "!!", opts("webauthn-ed25519:AAAA"))).toBe(false);
    expect(verifyWebAuthnAssertion(null as never, "", opts("x"))).toBe(false);
  });

  it("rejects Backup State set without Backup Eligibility (impossible flag combo, WebAuthn §verify)", () => {
    // UP|BS but NOT BE (0x01|0x10 = 0x11): a non-backup-eligible credential cannot be
    // backed up; the assertion is malformed and must fail even though it is well-signed.
    const a = p256Assertion({ flags: 0x11 });
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential))).toBe(false);
    // UP|BE|BS (0x19) is the legitimate backed-up combo and still verifies.
    const ok = p256Assertion({ flags: 0x19 });
    expect(verifyWebAuthnAssertion(ok.assertion, ok.signature, opts(ok.credential))).toBe(true);
  });

  it("fails closed when allowedOrigins is a bare string (no substring matching)", () => {
    // A JS caller (no compiler) passing a string instead of an array would otherwise get
    // String.prototype.includes — SUBSTRING matching: `policyString.includes(origin)` is
    // true whenever the assertion origin is a substring OF the policy string. So an
    // attacker at a shorter look-alike domain ("…countersignlabs.co", a prefix of the
    // real "…countersignlabs.com") would be accepted by the buggy code. The Array.isArray
    // guard rejects any string policy outright, closing exactly that direction.
    const a = ed25519Assertion({ client: { origin: "https://approve.countersignlabs.co" } });
    expect("https://approve.countersignlabs.com".includes("https://approve.countersignlabs.co")).toBe(true); // the bug the guard closes
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(a.credential, { allowedOrigins: origin as never }))).toBe(false);
    // And a genuine origin with a string policy still fails closed (never substring-accepted).
    const b = ed25519Assertion();
    expect(verifyWebAuthnAssertion(b.assertion, b.signature, opts(b.credential, { allowedOrigins: origin as never }))).toBe(false);
  });
});

describe("isValidCredentialDescriptor — structural well-formedness", () => {
  it("accepts a real on-curve P-256 credential and a well-formed ed25519 descriptor", () => {
    expect(isValidCredentialDescriptor(p256Assertion().credential)).toBe(true);
    expect(isValidCredentialDescriptor(`webauthn-ed25519:${generateKeypair().publicKey}`)).toBe(true);
  });

  it("accepts a well-formed-length OFF-CURVE P-256 point structurally (curve check is at verify time)", () => {
    // This predicate is STRUCTURAL (used by intent construction + audit replay), so it must
    // NOT reject an off-curve point — doing so would retroactively invalidate historical
    // records. An off-curve point is harmless: it can never produce a passing assertion.
    const offCurve = `webauthn-p256:${toB64url(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0)]))}`;
    expect(isValidCredentialDescriptor(offCurve)).toBe(true);
  });

  it("an OFF-CURVE P-256 credential can never verify an assertion (rejected at the crypto layer, fail-closed)", () => {
    // The security property: even though the descriptor is structurally valid, no assertion
    // signed for it verifies, because createPublicKey rejects the point. A dead key cannot forge.
    const offCurve = `webauthn-p256:${toB64url(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0)]))}`;
    const a = p256Assertion(); // a real assertion, presented under the off-curve descriptor
    expect(verifyWebAuthnAssertion(a.assertion, a.signature, opts(offCurve))).toBe(false);
  });
});

describe("isWebAuthnCredential", () => {
  it("distinguishes passkey descriptors from plain-ed25519 keyed keys", () => {
    expect(isWebAuthnCredential("webauthn-ed25519:AAAA")).toBe(true);
    expect(isWebAuthnCredential("webauthn-p256:AAAA")).toBe(true);
    expect(isWebAuthnCredential(generateKeypair().publicKey)).toBe(false); // raw ed25519 keyed key
    expect(isWebAuthnCredential(123 as never)).toBe(false);
  });
});
