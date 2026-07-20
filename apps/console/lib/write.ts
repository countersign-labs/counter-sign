// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Server-side write path: accept a CLIENT-SIGNED policy entry, validate it by appending
// to the current log and running the library's verifyChain (which re-checks the
// signature, chain links, single-org, admin authority, and every rule/role invariant),
// and persist only if it verifies. The server holds no signing key — it validates and
// stores. Extracted from the Next server action so the logic is unit-testable.

import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { PolicyLog } from "@countersignlabs/counter-sign";
import { errMsg, isRenderSafeAdmin, isRenderSafeRole, isRenderSafeRule } from "./schema";

let tmpSeq = 0;

function policyPath(dataDir: string): string {
  return join(dataDir, "policy.jsonl");
}

/** Read the policy log. Returns "" ONLY for an absent file (ENOENT); any OTHER read error
 *  (EACCES/EIO/EISDIR/…) propagates. Treating an existing-but-unreadable log as empty would
 *  let a client-submitted genesis admin-add pass verifyChain and OVERWRITE a live policy —
 *  destroying every admin/role/rule and installing the submitter as sole root admin. */
function readPolicy(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw new Error(`cannot read ${path}: ${(e as Error).message ?? String(e)}`);
  }
}

/** True iff `s` is the CANONICAL base64url encoding of a raw 32-byte ed25519 public key —
 *  the same rule as the library's isCanonicalPublicKey (src/core/keys.ts). base64url is not
 *  injective, so requiring canonicality (decode → 32 bytes → re-encode equals the input) gives
 *  each key exactly one string form; without it a garbage or aliased key slips past both the
 *  signer authentication and the exact-string duplicate/revocation checks. */
function isCanonicalPublicKey(s: unknown): boolean {
  if (typeof s !== "string" || s.length === 0) return false;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(s, "base64url");
  } catch {
    return false;
  }
  return bytes.length === 32 && bytes.toString("base64url") === s;
}

/** The current policy-log head the client needs to build the next entry (seq + prev).
 *  Throws a clean message if the log is unreadable or corrupt (the client surfaces it). */
export function policyHead(dataDir: string): { length: number; hash: string } {
  try {
    return PolicyLog.fromJSONL(readPolicy(policyPath(dataDir))).head();
  } catch (e) {
    console.error("[countersign] read policy head failed:", errMsg(e));
    throw new Error("the policy log is currently unavailable");
  }
}

/**
 * Validate a client-signed entry against the current log and, if it verifies, persist
 * the extended log. Fails closed: a bad signature, broken chain, wrong org, unauthorized
 * signer, invariant violation, OR an unreadable/corrupt on-disk log is rejected WITHOUT
 * overwriting anything.
 */
export function applySignedEntry(dataDir: string, entry: unknown): { ok: true } | { ok: false; error: string } {
  if (!entry || typeof entry !== "object") return { ok: false, error: "no entry" };

  // Read the current log INSIDE the guard: a corrupt/unreadable log must return a structured
  // failure, never throw a raw error out of the server action, and never be treated as empty.
  let log: PolicyLog;
  try {
    log = PolicyLog.fromJSONL(readPolicy(policyPath(dataDir)));
  } catch (e) {
    console.error("[countersign] read policy log failed:", errMsg(e));
    return { ok: false, error: "the policy log is currently unavailable" };
  }

  let candidate: PolicyLog;
  try {
    candidate = new PolicyLog([...log.entries, entry as never]);
  } catch (e) {
    return { ok: false, error: `malformed entry: ${String(e)}` };
  }
  if (!candidate.verifyChain()) {
    return { ok: false, error: "entry failed verification — bad signature, broken chain, wrong org, unauthorized signer, or an invalid rule/role" };
  }

  // Fold to the resulting state — the semantic gate. verifyChain checks signatures + chain links
  // + REQUIRED rule/role invariants, but NOT: an unknown change kind, the envelope version, an
  // optional string field's type, referential integrity, or that a usable admin remains. A
  // correctly-signed entry can pass verifyChain yet poison the log or brick the org, so validate
  // the full transition here — nothing semantically invalid ever reaches disk.
  let post: ReturnType<PolicyLog["state"]>;
  try {
    post = candidate.state(); // throws on an unknown change kind → rejected below
  } catch (e) {
    return { ok: false, error: `entry is not a valid policy change: ${errMsg(e)}` };
  }

  const newEntry = candidate.entries[candidate.entries.length - 1];
  // Envelope: only the current wire version is accepted (the signature covers the field, not its value).
  if (newEntry.countersign !== "0.2") {
    return { ok: false, error: `unsupported policy entry version: ${String(newEntry.countersign)}` };
  }
  const change = newEntry.change;

  // The `org` field is never type-checked: verifyChain's single-org rule compares changeOrg(genesis)
  // to itself, so a genesis whose org is an object passes and then renders as "[object Object]" in
  // every page header AND locks the org (the single-org check compares two distinct parsed objects,
  // failing every later change). Require a string org on every change.
  const orgValue = change.kind === "role-set" ? change.role.org : change.kind === "rule-set" ? change.rule.org : change.org;
  if (typeof orgValue !== "string") {
    return { ok: false, error: "org must be a string" };
  }

  // Validate the record THIS change introduces with the SAME render-safe guards store.ts applies on
  // read, so the console never PERSISTS a record its own read side would fault on (write/read parity —
  // verifyChain does not type-check optional strings like a rule's `action`). Scope to the NEW record:
  // re-validating the entire post-state would let a single pre-existing, out-of-band-malformed record
  // (e.g. a genesis admin created via the library CLI with a non-string name) block every future
  // legitimate console change, with no way to add or fix anything through the UI.
  const newRecordMalformed =
    (change.kind === "admin-add" && !isRenderSafeAdmin({ public_key: change.public_key, name: change.name })) ||
    (change.kind === "role-set" && !isRenderSafeRole(change.role)) ||
    (change.kind === "rule-set" && !isRenderSafeRule(change.rule));
  if (newRecordMalformed) {
    return { ok: false, error: "the change would create a record with a malformed field (e.g. a non-string name/description/action)" };
  }

  // A new admin-add must carry a CANONICAL ed25519 public key: verifyChain authenticates the
  // SIGNER but never validates the ADDED key — a garbage/non-canonical key enrolls an admin that
  // can never sign, and revoking the real admins would then lock the org out entirely.
  if (change.kind === "admin-add" && !isCanonicalPublicKey(change.public_key)) {
    return { ok: false, error: "the admin public key is not a canonical base64url ed25519 key" };
  }

  // Referential integrity, checked over the RESULTING state so BOTH directions are covered:
  // a rule-set that names a missing role AND a role-delete that orphans a rule which still
  // references it. verifyChain does not enforce this (append() does), so resolveRule would
  // otherwise fail at runtime with "unknown role" for the orphaned rule.
  const roleKeys = new Set([...post.roles.values()].map((r) => JSON.stringify([r.org, r.id])));
  for (const rule of post.rules.values()) {
    for (const roleId of rule.roles) {
      if (!roleKeys.has(JSON.stringify([rule.org, roleId]))) {
        return { ok: false, error: `this change would leave rule "${rule.name}" referencing a role that does not exist: ${roleId}` };
      }
    }
  }

  // A delete must target something that exists (append() rejects a no-op delete of a missing id).
  if (change.kind === "role-delete" || change.kind === "rule-delete") {
    let pre: ReturnType<PolicyLog["state"]> | null = null;
    try {
      pre = log.state();
    } catch {
      pre = null;
    }
    const exists =
      pre !== null &&
      (change.kind === "role-delete"
        ? [...pre.roles.values()].some((r) => r.id === change.id && r.org === change.org)
        : [...pre.rules.values()].some((r) => r.id === change.id && r.org === change.org));
    if (!exists) {
      return { ok: false, error: `${change.kind} of a ${change.kind === "role-delete" ? "role" : "rule"} that does not exist: ${change.id}` };
    }
  }

  // An admin-revoke must never leave the org without a CANONICAL admin key. The console derives the
  // signer key in canonical base64url, so a non-canonical alias — even one a custom client could sign
  // with — can NEVER sign through THIS console; a revoke down to only aliased/garbage admins would
  // lock the org out of the console for good. Scoped to admin-revoke (the only change that removes an
  // admin) so ordinary role/rule edits are never blocked; a new admin-add already requires canonical.
  if (change.kind === "admin-revoke" && ![...post.admins.values()].some((a) => isCanonicalPublicKey(a.public_key))) {
    return { ok: false, error: "this revoke would leave the org with no usable (canonical-key) admin" };
  }

  // Optimistic concurrency guard: re-read immediately before persisting and confirm the on-disk
  // head is IDENTICAL (length AND hash) to what we appended onto — a length-only check would miss
  // a same-length replacement with a different tip. This closes the common two-writer clobber
  // (both read head N, both overwrite, silently dropping one change). It is not a hard interprocess
  // lock; the console is single/dual-admin by design, and the atomic rename below prevents any
  // torn write regardless. A multi-writer deployment would additionally need a file lock.
  try {
    const now = PolicyLog.fromJSONL(readPolicy(policyPath(dataDir))).head();
    const before = log.head();
    if (now.length !== before.length || now.hash !== before.hash) {
      return { ok: false, error: "the policy log changed while you were signing — reload and try again" };
    }
  } catch (e) {
    console.error("[countersign] pre-write re-check failed:", errMsg(e));
    return { ok: false, error: "the policy log is currently unavailable — please try again" };
  }

  // Atomic persist: write a temp file, then rename over the target. A crash/kill/power-loss
  // mid-write cannot leave a truncated (and then unparseable) policy.jsonl — the old file
  // stays intact until the rename swaps in the complete new one.
  const target = policyPath(dataDir);
  const tmp = `${target}.tmp-${process.pid}-${tmpSeq++}`;
  try {
    writeFileSync(tmp, candidate.toJSONL());
    renameSync(tmp, target);
  } catch (e) {
    console.error("[countersign] persist failed:", errMsg(e));
    return { ok: false, error: "failed to save the change — please try again" };
  }
  return { ok: true };
}
