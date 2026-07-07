// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

/**
 * ed25519 keys are exchanged as base64url-encoded raw 32-byte values
 * (no padding). node:crypto only speaks DER, so we wrap/unwrap the raw
 * keys with the fixed ed25519 DER prefixes from RFC 8410.
 */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Keypair {
  /** base64url raw 32-byte ed25519 public key */
  publicKey: string;
  /** base64url raw 32-byte ed25519 seed — keep private */
  secretKey: string;
}

export function toB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromB64url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

export function utf8(s: string): Buffer {
  return Buffer.from(s, "utf8");
}

export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" });
  const sec = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    publicKey: toB64url(pub.subarray(SPKI_PREFIX.length)),
    secretKey: toB64url(sec.subarray(PKCS8_PREFIX.length)),
  };
}

function privateKeyObject(secretKey: string) {
  const seed = fromB64url(secretKey);
  if (seed.length !== 32) throw new RangeError("secretKey must be a base64url 32-byte ed25519 seed");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyObject(publicKey: string) {
  const raw = fromB64url(publicKey);
  if (raw.length !== 32) throw new RangeError("publicKey must be a base64url 32-byte ed25519 key");
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function publicKeyFromSecret(secretKey: string): string {
  const pem = privateKeyObject(secretKey).export({ type: "pkcs8", format: "pem" }) as string;
  const pub = createPublicKey(pem);
  return toB64url(pub.export({ type: "spki", format: "der" }).subarray(SPKI_PREFIX.length));
}

/** Sign raw bytes; returns base64url signature. */
export function signBytes(secretKey: string, data: Uint8Array): string {
  return toB64url(cryptoSign(null, data, privateKeyObject(secretKey)));
}

/**
 * Domain-separated signing. Every Countersign signature commits to a context
 * label so a signature minted for one envelope type can never be replayed as
 * another (intent vs. countersignature vs. email link). The signed bytes are
 * `context` + "\n" + `canonical`.
 */
export function signContext(secretKey: string, context: string, canonical: string): string {
  return signBytes(secretKey, utf8(`${context}\n${canonical}`));
}

/** Verify a domain-separated signature. Never throws on bad input. */
export function verifyContext(publicKey: string, context: string, canonical: string, signature: string): boolean {
  return verifyBytes(publicKey, utf8(`${context}\n${canonical}`), signature);
}

/** Verify a base64url signature over raw bytes. Never throws on bad input. */
export function verifyBytes(publicKey: string, data: Uint8Array, signature: string): boolean {
  try {
    return cryptoVerify(null, data, publicKeyObject(publicKey), fromB64url(signature));
  } catch {
    return false;
  }
}

/** Verify with raw byte inputs (used for Discord's hex-encoded headers). */
export function verifyRaw(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    return cryptoVerify(
      null,
      data,
      createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]),
        format: "der",
        type: "spki",
      }),
      signature,
    );
  } catch {
    return false;
  }
}
