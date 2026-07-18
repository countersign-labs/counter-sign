// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Browser-safe signing of a policy-log entry. The admin's ed25519 key never leaves
// the client: the browser builds the unsigned entry, canonicalizes it EXACTLY as the
// library does, signs `${POLICY_CONTEXT}\n${canonical}` with ed25519, and submits the
// signed entry. The server validates it via the library's PolicyLog.verifyChain and
// persists — it never sees the secret. Signatures are byte-identical to the library's
// PolicyLog.append (proven by policy-entry.test.ts against the real library).

import * as ed from "@noble/ed25519";

/** = src/core/types.ts POLICY handling; keep in lockstep with the library. */
export const POLICY_CONTEXT = "countersign-policy-v0.2";

export type Decision = "approve" | "reject";
export type PolicyChange =
  | { kind: "admin-add"; org: string; public_key: string; name?: string }
  | { kind: "admin-revoke"; org: string; public_key: string }
  | { kind: "role-set"; role: { id: string; org: string; name: string; description?: string; members: string[] } }
  | { kind: "role-delete"; org: string; id: string }
  | { kind: "rule-set"; rule: { id: string; org: string; name: string; roles: string[]; quorum: number; default: Decision; timeout_seconds: number; risk_tier?: string; action?: string } }
  | { kind: "rule-delete"; org: string; id: string };

export interface SignedPolicyEntry {
  countersign: "0.2";
  seq: number;
  change: PolicyChange;
  issued_at: string;
  prev: string | null;
  signer_public_key: string;
  signature: string;
}

const MAX_DEPTH = 64;

/** EXACT copy of src/core/canonical.ts — both sides must produce byte-identical output. */
export function canonicalize(value: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) throw new RangeError("cannot canonicalize: value nested too deeply");
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("cannot canonicalize non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v, depth + 1)).join(",")}]`;
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(record[k], depth + 1)}`).join(",")}}`;
    }
    default:
      throw new TypeError(`cannot canonicalize value of type ${typeof value}`);
  }
}

export function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Derive the base64url public key from a base64url ed25519 seed (matches the library). */
export async function publicKeyOf(adminSeedB64url: string): Promise<string> {
  return toB64url(await ed.getPublicKeyAsync(fromB64url(adminSeedB64url)));
}

/** Generate a fresh ed25519 keypair in the browser (library-compatible base64url format).
 *  `secret` is the private seed (keep it safe); `publicKey` is what gets enrolled/added. */
export async function browserKeypair(): Promise<{ secret: string; publicKey: string }> {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const pub = await ed.getPublicKeyAsync(seed);
  return { secret: toB64url(seed), publicKey: toB64url(pub) };
}

/**
 * Build and sign a policy-log entry client-side. `head` is the current log head
 * (`{ length, hash }` from PolicyLog.head()); `issuedAt` defaults to now (pass a fixed
 * value only for deterministic tests). The produced entry is byte-identical to what
 * PolicyLog.append(change, adminSecret) would produce.
 */
export async function signPolicyEntry(
  change: PolicyChange,
  head: { length: number; hash: string },
  adminSeedB64url: string,
  issuedAt: string = new Date().toISOString(),
): Promise<SignedPolicyEntry> {
  const seed = fromB64url(adminSeedB64url);
  const signer_public_key = toB64url(await ed.getPublicKeyAsync(seed));
  const seq = head.length;
  const prev = seq === 0 ? null : head.hash;
  const unsigned = { countersign: "0.2" as const, seq, change, issued_at: issuedAt, prev, signer_public_key };
  const message = new TextEncoder().encode(`${POLICY_CONTEXT}\n${canonicalize(unsigned)}`);
  const signature = toB64url(await ed.signAsync(message, seed));
  return { ...unsigned, signature };
}
