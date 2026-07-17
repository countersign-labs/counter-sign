// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// Shared fixture machinery for the vector tooling (gen-vectors.ts and
// mint-p256-vector.ts import from here — gen-vectors.ts itself cannot be imported,
// its top level writes the vector file). One definition of the fixture constants
// and the passkey assertion-assembly recipe, so the two scripts cannot drift
// apart. NOTE: FIXED_DECIDED is used by EVERY vector receipt (vouched, keyed,
// chain), not just the passkey ones — this module is generic vector plumbing.

import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { challengeFor, unsignedReceipt } from "../src/core/countersignature.js";
import { fromB64url, signBytes, toB64url, utf8 } from "../src/core/keys.js";
import type { Countersignature } from "../src/core/types.js";

/** RP policy the webauthn vectors are minted under. */
export const RP_ID = "approve.example.com";
export const WEBAUTHN_ORIGIN = "https://approve.example.com";
/** The fixed decision timestamp EVERY vector receipt carries (not just passkey ones). */
export const FIXED_DECIDED = "2026-01-01T00:01:00.000Z";
/** The frozen P-256 vector's intent (gen-vectors' p256Intent). */
export const P256_INTENT_ID = "55555555-5555-4555-8555-555555555555";

/** An ed25519 authenticator-signing closure over a fixed seed (deterministic, RFC 8032). */
export const signWithEd25519 = (secretSeed: string) => (data: Buffer) => fromB64url(signBytes(secretSeed, data));

/** A fresh P-256 credential + signing closure (randomized ECDSA — for the frozen mint only). */
export function p256Credential(): { credential: string; sign: (data: Buffer) => Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = publicKey.export({ type: "spki", format: "der" });
  const point = der.subarray(der.length - 65); // 0x04 || x || y
  return { credential: `webauthn-p256:${toB64url(point)}`, sign: (data) => cryptoSign("sha256", data, privateKey) };
}

/** Mint a passkey receipt exactly as the browser signing page would — via the SAME
 *  unsignedReceipt/challengeFor recipe the SigningServer signs and the verifier checks.
 *  The timestamp is explicit so this helper carries no hidden fixture state. */
export function mintPasskeyReceipt(
  intentId: string,
  decision: "approve" | "reject",
  actor: string,
  credential: string,
  timestamp: string,
  sign: (data: Buffer) => Buffer,
  over: { flags?: number; origin?: string; crossOrigin?: boolean } = {},
): Countersignature {
  const unsigned = unsignedReceipt(intentId, decision, actor, credential, timestamp);
  const challenge = challengeFor(unsigned);
  const rpIdHash = createHash("sha256").update(utf8(RP_ID)).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([over.flags ?? 0x05]), Buffer.from([0, 0, 0, 1])]);
  const cd: Record<string, unknown> = { type: "webauthn.get", challenge, origin: over.origin ?? WEBAUTHN_ORIGIN };
  if (over.crossOrigin !== undefined) cd.crossOrigin = over.crossOrigin;
  const clientData = Buffer.from(JSON.stringify(cd), "utf8");
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  return {
    ...unsigned,
    signature: toB64url(sign(signedData)),
    webauthn: { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData) },
  };
}
