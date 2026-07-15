// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.
//
// WebAuthn (passkey) assertion verification for KEYED approvers who sign with a
// hardware authenticator instead of a raw ed25519 key. The approver's bound
// credential is a self-describing descriptor:
//   webauthn-ed25519:<base64url 32-byte raw key>     (COSE alg -8)
//   webauthn-p256:<base64url 65-byte uncompressed EC point 0x04||x||y>  (COSE alg -7)
// A raw 43-char base64url key (no prefix) is a plain-ed25519 keyed approver (Phase 1).

import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";
import { fromB64url, utf8, verifyRaw } from "./keys.js";

/** SPKI DER prefix for an uncompressed P-256 (prime256v1) public key. */
const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

const ED25519_PREFIX = "webauthn-ed25519:";
const P256_PREFIX = "webauthn-p256:";

/** The authenticator-produced part of a passkey receipt (navigator.credentials.get). */
export interface WebAuthnAssertion {
  /** base64url authenticatorData */
  authenticator_data: string;
  /** base64url clientDataJSON (contains type, challenge, origin) */
  client_data_json: string;
}

export interface WebAuthnVerifyOptions {
  /** the bound credential descriptor (webauthn-ed25519:… | webauthn-p256:…) */
  credential: string;
  /** base64url the clientData challenge MUST equal (our receipt digest) */
  expectedChallenge: string;
  /** the Relying Party ID (registrable domain) the assertion must be scoped to */
  rpId: string;
  /** exact web origins allowed to have produced the assertion */
  allowedOrigins: readonly string[];
  /** require the User Verified flag (User Present is ALWAYS required) */
  requireUserVerification?: boolean;
}

/** True iff `s` is a passkey credential descriptor (vs. a plain-ed25519 keyed key). */
export function isWebAuthnCredential(s: unknown): s is string {
  return typeof s === "string" && (s.startsWith(ED25519_PREFIX) || s.startsWith(P256_PREFIX));
}

function eqB64url(a: string, b: string): boolean {
  const ab = utf8(a);
  const bb = utf8(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/**
 * Verify a WebAuthn assertion and that it is bound to THIS decision. Checks, in
 * order: the clientData is a `webauthn.get` whose challenge equals
 * `expectedChallenge` and whose origin is allowed; the authenticatorData RP-ID
 * hash matches `rpId` and the User Present (and, if required, User Verified) flag
 * is set; and the assertion signature over `authenticatorData || SHA256(clientDataJSON)`
 * verifies under the bound credential key (Ed25519 raw, or P-256 ECDSA/DER).
 * Never throws — returns false on any malformed input or failed check.
 */
export function verifyWebAuthnAssertion(
  assertion: WebAuthnAssertion,
  signatureB64url: string,
  opts: WebAuthnVerifyOptions,
): boolean {
  try {
    if (
      !assertion ||
      typeof assertion.authenticator_data !== "string" ||
      typeof assertion.client_data_json !== "string" ||
      typeof signatureB64url !== "string"
    )
      return false;

    const authData = fromB64url(assertion.authenticator_data);
    const clientDataBytes = fromB64url(assertion.client_data_json);
    const signature = fromB64url(signatureB64url);

    // --- clientDataJSON ---
    let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
    try {
      clientData = JSON.parse(clientDataBytes.toString("utf8"));
    } catch {
      return false;
    }
    if (clientData.type !== "webauthn.get") return false;
    if (typeof clientData.challenge !== "string" || !eqB64url(clientData.challenge, opts.expectedChallenge)) return false;
    if (typeof clientData.origin !== "string" || !opts.allowedOrigins.includes(clientData.origin)) return false;

    // --- authenticatorData: 32-byte rpIdHash | 1-byte flags | 4-byte signCount | … ---
    if (authData.length < 37) return false;
    const rpIdHash = authData.subarray(0, 32);
    const expectedRpIdHash = createHash("sha256").update(utf8(opts.rpId)).digest();
    if (rpIdHash.length !== expectedRpIdHash.length || !timingSafeEqual(rpIdHash, expectedRpIdHash)) return false;
    const flags = authData[32];
    if ((flags & 0x01) === 0) return false; // User Present (UP) — mandatory
    if (opts.requireUserVerification && (flags & 0x04) === 0) return false; // User Verified (UV)

    // --- signature over authenticatorData || SHA256(clientDataJSON) ---
    const clientDataHash = createHash("sha256").update(clientDataBytes).digest();
    const signedData = Buffer.concat([authData, clientDataHash]);

    const cred = opts.credential;
    if (cred.startsWith(ED25519_PREFIX)) {
      const raw = fromB64url(cred.slice(ED25519_PREFIX.length));
      if (raw.length !== 32) return false;
      return verifyRaw(raw, signedData, signature);
    }
    if (cred.startsWith(P256_PREFIX)) {
      const point = fromB64url(cred.slice(P256_PREFIX.length));
      if (point.length !== 65 || point[0] !== 0x04) return false;
      const key = createPublicKey({ key: Buffer.concat([P256_SPKI_PREFIX, point]), format: "der", type: "spki" });
      // WebAuthn ES256: ASN.1 DER ECDSA over SHA-256(signedData).
      return cryptoVerify("sha256", signedData, key, signature);
    }
    return false;
  } catch {
    return false;
  }
}
