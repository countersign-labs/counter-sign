// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.
//
// Generate counter-sign CONFORMANCE TEST VECTORS — a language-neutral, deterministic
// fixture set that any independent implementation can check itself against. Run:
//
//   npm run gen:vectors     # (re)writes vectors/countersign-vectors.json
//
// The vectors are produced FROM the reference implementation, then frozen and committed;
// tests/conformance.test.ts re-verifies the reference impl against the committed file, so a
// change to canonicalization or signing that would break cross-implementation interop shows
// up as a failing test + a reviewable diff rather than a silent wire-format drift.
//
// Everything here is deterministic: ed25519 is deterministic (RFC 8032), the canonical JSON is
// a total function of its input, and every id/timestamp below is fixed. The keys are derived
// from low-entropy, clearly-labelled TEST seeds — NEVER use them for anything real.

import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "../src/core/canonical.js";
import { publicKeyFromSecret, signContext, toB64url, utf8 } from "../src/core/keys.js";
import { createIntent } from "../src/core/intent.js";
import { signDecision } from "../src/core/countersignature.js";
import { deadline } from "../src/core/defaults.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { INTENT_CONTEXT, COUNTERSIGNATURE_CONTEXT, LINK_CONTEXT, type Intent, type Resolution } from "../src/core/types.js";

/** A fixed, low-entropy TEST seed: 32 bytes all set to `b`, base64url-encoded. NOT for production. */
const seed = (b: number): string => toB64url(Buffer.alloc(32, b));

const K = {
  agent: seed(0x01),
  authority: seed(0x02),
  org: seed(0x03),
  ceo: seed(0x11),
  cto: seed(0x12),
  rogue: seed(0xff),
};
const pub = (s: string) => publicKeyFromSecret(s);

const FIXED_CREATED = "2026-01-01T00:00:00.000Z";
const FIXED_DECIDED = "2026-01-01T00:01:00.000Z";

/** Build a signed Intent deterministically: normalize/validate via createIntent, then pin the
 *  otherwise-random intent_id + created_at and re-sign, so the fixture is byte-stable. */
function fixedIntent(intentId: string, fields: Parameters<typeof createIntent>[0]): Intent {
  const raw = createIntent(fields, { id: "agent:vectors", keypair: { publicKey: pub(K.agent), secretKey: K.agent } });
  const { signature: _drop, ...rest } = raw;
  const unsigned = { ...rest, intent_id: intentId, created_at: FIXED_CREATED };
  return { ...unsigned, signature: signContext(K.agent, INTENT_CONTEXT, canonicalize(unsigned)) };
}

// ── Intents ────────────────────────────────────────────────────────────────────────────────
const vouchedIntent = fixedIntent("11111111-1111-4111-8111-111111111111", {
  action: "billing.refund", summary: "Refund $42.00 to customer 8675309", risk_tier: "high",
  approvers: [{ actor: "tg:alice", mode: "vouched" }], quorum: 1, timeout: 300, default: "reject",
});
const keyedIntent = fixedIntent("22222222-2222-4222-8222-222222222222", {
  action: "prod.deploy", summary: "Deploy 2.4.0 to production", risk_tier: "critical",
  approvers: [
    { actor: "m:ceo", mode: "keyed", public_key: pub(K.ceo) },
    { actor: "m:cto", mode: "keyed", public_key: pub(K.cto) },
  ], quorum: 2, timeout: 300, default: "reject",
});

// ── Countersignatures (receipts) ───────────────────────────────────────────────────────────
const vouchedApprove = signDecision(vouchedIntent, "approve", "tg:alice", K.authority, "approver", FIXED_DECIDED);
const ceoApprove = signDecision(keyedIntent, "approve", "m:ceo", K.ceo, "approver", FIXED_DECIDED);
const ctoApprove = signDecision(keyedIntent, "approve", "m:cto", K.cto, "approver", FIXED_DECIDED);
const deadlineIso = new Date(deadline(keyedIntent)).toISOString();
const timeoutDefault = signDecision(keyedIntent, "reject", "default:timeout", K.authority, "default", deadlineIso);
// A receipt for m:cto's slot, but signed by the ROGUE key (a forgery an auditor must reject).
const forgedCto = signDecision(keyedIntent, "approve", "m:cto", K.rogue, "approver", FIXED_DECIDED);

// ── Chain (ReceiptLog) head over the two keyed approvals, in order ─────────────────────────
const tmp = join(mkdtempSync(join(tmpdir(), "cs-vectors-")), "receipts.jsonl");
const log = new ReceiptLog(tmp);
await log.append(ceoApprove);
await log.append(ctoApprove);
const head = await log.head();
const CHAIN_GENESIS = toB64url(createHash("sha256").update(utf8("countersign-receipt-chain-v0.1")).digest());

// A tampered Intent (summary changed after signing) — must FAIL verifyIntent.
const tamperedIntent: Intent = { ...vouchedIntent, summary: vouchedIntent.summary + " (edited)" };

/** The canonical JSON of an Intent's signed body (everything except the signature). */
function unsignedCanonical(i: Intent): string {
  const { signature: _s, ...unsigned } = i;
  return canonicalize(unsigned);
}

const vectors = {
  format: "counter-sign conformance test vectors",
  version: "0.2",
  generated_by: "scripts/gen-vectors.ts (deterministic; re-run npm run gen:vectors to reproduce byte-for-byte)",
  warning: "TEST KEYS — low-entropy, public, DO NOT USE for anything real.",
  spec: "spec/countersign-spec.md",
  algorithm: {
    signature: "ed25519 (RFC 8032, deterministic)",
    key_encoding: "base64url of the raw 32-byte value (seed for secret, public key for public)",
    canonical_json: "object keys sorted lexicographically at every depth by UTF-16 code unit; no insignificant whitespace; UTF-8 bytes; `undefined` members omitted; non-finite numbers rejected",
    signed_bytes: "utf8(`${context}\\n${canonical}`) — the domain-separation context, a single 0x0A, then the canonical JSON of the unsigned object",
    contexts: { intent: INTENT_CONTEXT, countersignature: COUNTERSIGNATURE_CONTEXT, link: LINK_CONTEXT },
    receipt_chain: {
      genesis_prev: CHAIN_GENESIS,
      genesis_preimage: "utf8(\"countersign-receipt-chain-v0.1\")",
      entry: "{ seq, prev, receipt } — seq is 0-based; prev is the previous entry's hash (genesis for seq 0)",
      entry_hash: "base64url( sha256( utf8( canonical_json(entry) ) ) )",
      head_hash: "the last entry's hash, or genesis_prev for an empty log",
    },
  },
  keys: Object.entries(K).map(([name, secret]) => ({ name, secret, public: pub(secret) })),
  canonical: [
    { name: "empty-object", value: {}, canonical: canonicalize({}) },
    { name: "key-ordering", value: { c: 3, a: 1, b: 2 }, canonical: canonicalize({ c: 3, a: 1, b: 2 }) },
    { name: "nested-and-arrays", value: { z: [3, 2, 1], a: { y: true, x: null } }, canonical: canonicalize({ z: [3, 2, 1], a: { y: true, x: null } }) },
    { name: "undefined-omitted", value: { a: 1, b: undefined as unknown as number, c: 3 }, canonical: canonicalize({ a: 1, b: undefined as unknown as number, c: 3 }) },
    { name: "unicode-string", value: { s: "café — 日本語 — \"quotes\" & <tags>" }, canonical: canonicalize({ s: "café — 日本語 — \"quotes\" & <tags>" }) },
    { name: "integers-and-negative", value: { n: 0, neg: -1000000, big: 9007199254740991 }, canonical: canonicalize({ n: 0, neg: -1000000, big: 9007199254740991 }) },
  ],
  signing: [
    // Low-level signContext known-answers: message bytes and the exact signature. A second
    // implementation can check the pre-hash message before it even wires up ed25519.
    (() => { const c = canonicalize({ hello: "world", n: 42 }); return { name: "signContext-sample", secret_key: K.authority, public_key: pub(K.authority), context: COUNTERSIGNATURE_CONTEXT, canonical: c, message_base64url: toB64url(utf8(`${COUNTERSIGNATURE_CONTEXT}\n${c}`)), signature: signContext(K.authority, COUNTERSIGNATURE_CONTEXT, c) }; })(),
  ],
  intents: [
    { name: "vouched-quorum-1", agent_public_key: pub(K.agent), context: INTENT_CONTEXT, canonical_unsigned: unsignedCanonical(vouchedIntent), valid: true, intent: vouchedIntent },
    { name: "keyed-quorum-2", agent_public_key: pub(K.agent), context: INTENT_CONTEXT, canonical_unsigned: unsignedCanonical(keyedIntent), valid: true, intent: keyedIntent },
    { name: "tampered-summary", agent_public_key: pub(K.agent), context: INTENT_CONTEXT, canonical_unsigned: unsignedCanonical(tamperedIntent), valid: false, note: "summary edited after signing; canonical_unsigned no longer matches the signed bytes", intent: tamperedIntent },
  ],
  countersignatures: [
    { name: "vouched-approve", signer_public_key: pub(K.authority), context: COUNTERSIGNATURE_CONTEXT, valid: true, receipt: vouchedApprove },
    { name: "keyed-approve-ceo", signer_public_key: pub(K.ceo), context: COUNTERSIGNATURE_CONTEXT, valid: true, receipt: ceoApprove },
    { name: "keyed-approve-cto", signer_public_key: pub(K.cto), context: COUNTERSIGNATURE_CONTEXT, valid: true, receipt: ctoApprove },
    { name: "timeout-default-reject", signer_public_key: pub(K.authority), context: COUNTERSIGNATURE_CONTEXT, valid: true, receipt: timeoutDefault },
    { name: "forged-wrong-key", signer_public_key: pub(K.cto), context: COUNTERSIGNATURE_CONTEXT, valid: false, note: "receipt claims m:cto but is signed by the rogue key; must NOT verify against m:cto's public key", receipt: forgedCto },
  ],
  resolutions: [
    { name: "keyed-2of2-approve", expect: "valid", expected_authority_public_key: pub(K.authority), intent: keyedIntent, resolution: { decision: "approve", policy: "approver", countersignatures: [ceoApprove, ctoApprove] } as Resolution },
    { name: "vouched-approve", expect: "valid", expected_authority_public_key: pub(K.authority), intent: vouchedIntent, resolution: { decision: "approve", policy: "approver", countersignatures: [vouchedApprove] } as Resolution },
    { name: "timeout-default", expect: "valid", expected_authority_public_key: pub(K.authority), intent: keyedIntent, resolution: { decision: "reject", policy: "default", countersignatures: [timeoutDefault] } as Resolution },
    { name: "under-quorum", expect: "invalid", note: "only 1 of 2 required keyed approvals", expected_authority_public_key: pub(K.authority), intent: keyedIntent, resolution: { decision: "approve", policy: "approver", countersignatures: [ceoApprove] } as Resolution },
    { name: "forged-quorum", expect: "invalid", note: "m:cto's slot signed by the rogue key", expected_authority_public_key: pub(K.authority), intent: keyedIntent, resolution: { decision: "approve", policy: "approver", countersignatures: [ceoApprove, forgedCto] } as Resolution },
    { name: "wrong-authority-key", expect: "invalid", note: "vouched receipt verified against the wrong authority key", expected_authority_public_key: pub(K.rogue), intent: vouchedIntent, resolution: { decision: "approve", policy: "approver", countersignatures: [vouchedApprove] } as Resolution },
  ],
  chain: {
    note: "append these receipts in order to a fresh hash-chained ReceiptLog; head() must equal expected_head",
    receipts: [ceoApprove, ctoApprove],
    expected_head: head,
  },
};

const out = join(process.cwd(), "vectors", "countersign-vectors.json");
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
process.stdout.write(`wrote ${out}\n  ${vectors.keys.length} keys · ${vectors.canonical.length} canonical · ${vectors.intents.length} intents · ${vectors.countersignatures.length} receipts · ${vectors.resolutions.length} resolutions · chain head ${head.hash.slice(0, 12)}…\n`);
