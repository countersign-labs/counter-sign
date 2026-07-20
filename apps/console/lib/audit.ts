// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Async audit loader for the Audit page: the receipt log (decisions + per-receipt signature
// verification + chain status) and the policy change log (who changed which rule/role/admin).
// Receipt SIGNATURES are verified (verifyAll), so a forged/tampered receipt is flagged rather
// than rendered as authentic. See loadAuditData for the honest limits of this surface.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PolicyLog, ReceiptLog, type PolicyChange, type WebAuthnPolicy } from "@countersignlabs/counter-sign";
import { errMsg, isFiniteNum, isStr } from "./schema";

/** Coerce any value to a render-safe string, so a malformed (object) field can never reach JSX. */
function asStr(x: unknown): string {
  return typeof x === "string" ? x : "";
}

/** Per-receipt signature verdict from verifyAll (integrity: the receipt's embedded key signed it).
 *  - "valid": the ed25519 signature (or, with an RP policy, the WebAuthn assertion) verifies.
 *  - "invalid": the signature does NOT verify — a tampered or forged receipt (tamper evidence).
 *  - "unverifiable": a passkey receipt with no RP policy configured — cannot be checked here.
 *  - "malformed": the signature verifies but a displayed field is not a string — an authentic but
 *    structurally broken record. Distinct from "invalid" so it is not read as a tamper alarm. */
export type SignatureStatus = "valid" | "invalid" | "unverifiable" | "malformed";

export interface AuditDecision {
  intent_id: string;
  decision: string;
  actor: string;
  policy: string; // "approver" | "default"
  timestamp: string;
  signature: SignatureStatus;
}
export interface AuditChange {
  seq: number;
  kind: string;
  target: string;
  signer: string;
  issued_at: string;
}
export interface AuditReceipts {
  total: number;
  /** signatures that cryptographically verified */
  valid: number;
  /** signatures that did NOT verify — tampered/forged receipts */
  invalid: number;
  /** passkey receipts that cannot be verified without an RP policy (COUNTERSIGN_RP_ID/…) */
  unverifiable: number;
  /** authentically signed but structurally broken (a displayed field is not a string) */
  malformed: number;
  /** the keyless hash-chain structure over the receipts (completeness, not authenticity) */
  chainIntact: boolean;
  chainReason?: string;
  /** false when receipts.jsonl exists but is corrupt/unreadable (decisions then empty) */
  readable: boolean;
  error?: string;
}
export interface AuditData {
  decisions: AuditDecision[];
  receipts: AuditReceipts;
  changes: AuditChange[];
  /** false when policy.jsonl exists but is corrupt/unreadable (changes then empty) */
  policyReadable: boolean;
}

/** Read a file, tolerating only absence (ENOENT). Other read errors propagate to the caller,
 *  which converts them into a reported fault rather than a silently-empty (trusted) render. */
function readLog(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw new Error(`cannot read ${path}: ${(e as Error).message ?? String(e)}`);
  }
}

/** Optional WebAuthn RP policy from env, so passkey receipts can be cryptographically verified
 *  on the audit surface. Unset ⇒ passkey receipts report as "unverifiable" (honest), not tampered. */
function rpPolicyFromEnv(): WebAuthnPolicy | undefined {
  const rpId = process.env.COUNTERSIGN_RP_ID?.trim();
  const origins = (process.env.COUNTERSIGN_RP_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean);
  if (!rpId || origins.length === 0) return undefined;
  // Mirror the signing runtime's UV requirement — otherwise the console could label a UP-only
  // assertion "valid" that a UV-requiring production policy would reject.
  const requireUserVerification = /^(1|true|yes)$/i.test(process.env.COUNTERSIGN_RP_REQUIRE_UV?.trim() ?? "");
  return { rpId, allowedOrigins: origins, requireUserVerification };
}

/** A short human description of what a policy change targets. Render-safe: any field that is not a
 *  string is shown as "(malformed)" rather than interpolated (which would leak "[object Object]"). */
function changeTarget(change: PolicyChange): string {
  const s = (x: unknown): string => (typeof x === "string" ? x : "(malformed)");
  switch (change.kind) {
    case "admin-add":
      return `${typeof change.name === "string" && change.name ? change.name + " · " : ""}${s(change.public_key).slice(0, 10)}…`;
    case "admin-revoke":
      return `${s(change.public_key).slice(0, 10)}…`;
    case "role-set":
      return `role ${s(change.role?.name)}`;
    case "role-delete":
      return `role ${s(change.id)}`;
    case "rule-set":
      return `rule ${s(change.rule?.name)}`;
    case "rule-delete":
      return `rule ${s(change.id)}`;
  }
}

export async function loadAuditData(dataDir: string): Promise<AuditData> {
  const decisions: AuditDecision[] = [];
  let receipts: AuditReceipts = { total: 0, valid: 0, invalid: 0, unverifiable: 0, malformed: 0, chainIntact: true, readable: true };

  // Read the receipt log bytes ONCE and verify + project from that single immutable snapshot.
  // Calling verifyAll() then read() on the live file would be two separate reads: a concurrent
  // append/replace between them could let an unverified (or replaced) receipt inherit a stale
  // "valid" verdict. A private temp copy gives both calls identical bytes. "" only for ENOENT.
  // (verifyAll + read each re-parse the temp — a deliberate trade of one extra parse for snapshot
  // consistency; this is a per-request admin audit view, not a hot path, and the library exposes no
  // single call returning both the report and the receipts.)
  let raw: string | null = null;
  try {
    raw = readFileSync(join(dataDir, "receipts.jsonl"), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      receipts = { total: 0, valid: 0, invalid: 0, unverifiable: 0, malformed: 0, chainIntact: false, readable: false, error: errMsg(e) };
    }
    raw = null;
  }
  if (raw !== null && raw.trim().length > 0) {
    let snapDir: string | undefined;
    try {
      // Snapshot the bytes to a private temp file so verifyAll() and read() see identical data —
      // mkdtempSync/writeFileSync are INSIDE the guard so a temp-dir failure faults (readable:false)
      // rather than throwing an uncaught 500 out of the loader.
      snapDir = mkdtempSync(join(tmpdir(), "cs-audit-snap-"));
      const snapPath = join(snapDir, "receipts.jsonl");
      writeFileSync(snapPath, raw);
      const rl = new ReceiptLog(snapPath);
      const webauthn = rpPolicyFromEnv();
      // verifyAll checks EACH receipt's signature (integrity) plus the chain structure — so a
      // forged/tampered receipt whose signature does not verify is flagged, not shown as genuine.
      // (Authority-binding — that each signer was authorized for its Intent — additionally needs
      // the Intents + runtime authority key, which the console does not hold; noted in the UI.)
      const report = await rl.verifyAll(webauthn ? { webauthn } : {});
      const list = await rl.read();
      const reasonByIndex = new Map<number, string>();
      for (const f of report.faults) reasonByIndex.set(f.index, f.reason);
      list.forEach((r, i) => {
        const reason = reasonByIndex.get(i);
        // A receipt is only signature-checked by verifyAll; its DISPLAYED fields (actor, decision,
        // policy, timestamp, intent_id) are not guaranteed to be strings. A signed record with an
        // object there would throw at {d.actor} on the page — never cast it through.
        const safe = isStr(r.intent_id) && isStr(r.decision) && isStr(r.actor) && isStr(r.policy) && isStr(r.timestamp);
        if (safe) {
          const signature: SignatureStatus = reason === undefined ? "valid" : reason === "missing-webauthn-policy" ? "unverifiable" : "invalid";
          decisions.push({ intent_id: r.intent_id, decision: r.decision, actor: r.actor, policy: r.policy, timestamp: r.timestamp, signature });
        } else {
          // The signature may verify perfectly (the signer signed a non-string field) — that is a
          // MALFORMED record, not a tampered one. Flag it as such, never a false "invalid" alarm.
          const signature: SignatureStatus = reason === undefined || reason === "missing-webauthn-policy" ? "malformed" : "invalid";
          decisions.push({ intent_id: asStr(r.intent_id), decision: "(malformed)", actor: "(malformed record)", policy: asStr(r.policy), timestamp: asStr(r.timestamp), signature });
        }
      });
      let valid = 0;
      let invalid = 0;
      let unverifiable = 0;
      let malformed = 0;
      for (const d of decisions) {
        if (d.signature === "valid") valid++;
        else if (d.signature === "invalid") invalid++;
        else if (d.signature === "unverifiable") unverifiable++;
        else malformed++;
      }
      receipts = { total: list.length, valid, invalid, unverifiable, malformed, chainIntact: report.chain.intact, chainReason: report.chain.reason, readable: true };
    } catch (e) {
      // A single corrupt receipt line (or a temp-dir failure) must NOT 500 the whole audit page —
      // report it and still render the (independent) policy change log below.
      decisions.length = 0;
      receipts = { total: 0, valid: 0, invalid: 0, unverifiable: 0, malformed: 0, chainIntact: false, readable: false, error: errMsg(e) };
    } finally {
      if (snapDir) rmSync(snapDir, { recursive: true, force: true });
    }
  }

  // Policy change log — independent of the receipt log; guard its parse the same way, and make
  // every displayed field render-safe. A signed entry can carry an object where a string is
  // expected (e.g. signer_public_key), which would throw at fingerprint()/JSX on the page.
  let changes: AuditChange[] = [];
  let policyReadable = true;
  try {
    const log = PolicyLog.fromJSONL(readLog(join(dataDir, "policy.jsonl")));
    changes = log.entries.map((e) => {
      let target: string;
      try {
        const t = changeTarget(e.change);
        target = isStr(t) ? t : "(malformed)";
      } catch {
        target = "(malformed)"; // an object field inside the change → don't crash, flag it
      }
      return {
        seq: isFiniteNum(e.seq) ? e.seq : -1,
        kind: asStr((e.change as { kind?: unknown } | null)?.kind),
        target,
        signer: isStr(e.signer_public_key) ? e.signer_public_key : "(malformed)",
        issued_at: asStr(e.issued_at),
      };
    });
  } catch {
    policyReadable = false;
  }

  return { decisions, receipts, changes, policyReadable };
}
