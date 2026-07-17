// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Server-side write path: accept a CLIENT-SIGNED policy entry, validate it by appending
// to the current log and running the library's verifyChain (which re-checks the
// signature, chain links, single-org, admin authority, and every rule/role invariant),
// and persist only if it verifies. The server holds no signing key — it validates and
// stores. Extracted from the Next server action so the logic is unit-testable.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PolicyLog } from "@countersignlabs/counter-sign";

function policyPath(dataDir: string): string {
  return join(dataDir, "policy.jsonl");
}

function readOrEmpty(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/** The current policy-log head the client needs to build the next entry (seq + prev). */
export function policyHead(dataDir: string): { length: number; hash: string } {
  const log = PolicyLog.fromJSONL(readOrEmpty(policyPath(dataDir)));
  return log.head();
}

/**
 * Validate a client-signed entry against the current log and, if it verifies, persist
 * the extended log. Fails closed: any bad signature, broken chain, wrong org, unauthorized
 * signer, or invariant violation is rejected without touching disk.
 */
export function applySignedEntry(dataDir: string, entry: unknown): { ok: true } | { ok: false; error: string } {
  const log = PolicyLog.fromJSONL(readOrEmpty(policyPath(dataDir)));
  if (!entry || typeof entry !== "object") return { ok: false, error: "no entry" };
  let candidate: PolicyLog;
  try {
    candidate = new PolicyLog([...log.entries, entry as never]);
  } catch (e) {
    return { ok: false, error: `malformed entry: ${String(e)}` };
  }
  if (!candidate.verifyChain()) {
    return { ok: false, error: "entry failed verification — bad signature, broken chain, wrong org, unauthorized signer, or an invalid rule/role" };
  }
  writeFileSync(policyPath(dataDir), candidate.toJSONL());
  return { ok: true };
}
