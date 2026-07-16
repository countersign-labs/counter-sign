// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { normalizeActor, signDecision } from "../src/core/countersignature.js";
import { deadline } from "../src/core/defaults.js";
import { CountersignError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { fromB64url, generateKeypair, publicKeyFromSecret, type Keypair } from "../src/core/keys.js";
import type { Decision, Intent, Resolution } from "../src/core/types.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { wrapAction } from "../src/shim.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const authorityPub = publicKeyFromSecret(authority);

const approverKeys = new Map<string, Keypair>();
function keyOf(actor: string): Keypair {
  let kp = approverKeys.get(actor);
  if (!kp) { kp = generateKeypair(); approverKeys.set(actor, kp); }
  return kp;
}

function intent(quorum = 1): Intent {
  const approvers =
    quorum > 1
      ? [
          { actor: "local:a", mode: "keyed" as const, public_key: keyOf("local:a").publicKey },
          { actor: "local:b", mode: "keyed" as const, public_key: keyOf("local:b").publicKey },
        ]
      : ["local:a", "local:b"];
  return createIntent(
    { action: "demo.op", summary: "Do the thing", risk_tier: "high", approvers, quorum, timeout: 300, default: "reject" },
    agent,
  );
}

/** A resolution built from real signed receipts, as an adapter would produce. A
 *  keyed approver's receipt is signed by their own key; a vouched one by the authority. */
function approval(i: Intent, actors: string[]): Resolution {
  return {
    decision: "approve",
    policy: "approver",
    countersignatures: actors.map((a) => {
      const ap = i.approvers.find((x) => normalizeActor(x.actor) === normalizeActor(a));
      const secret = ap?.mode === "keyed" ? keyOf(a).secretKey : authority;
      return signDecision(i, "approve", a, secret, "approver");
    }),
  };
}

let dir: string;
let log: ReceiptLog;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-receiptlog-"));
  log = new ReceiptLog(join(dir, "nested", "receipts.jsonl")); // nested → dir is created lazily
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("append / read round-trip", () => {
  it("reads back a written receipt intact", async () => {
    const cs = signDecision(intent(), "approve", "local:a", authority);
    await log.append(cs);
    expect(await log.read()).toEqual([cs]);
  });

  it("returns [] for a log that does not exist yet", async () => {
    expect(await log.read()).toEqual([]);
  });

  it("record() writes every receipt of a resolution, in order", async () => {
    const i = intent(2);
    await log.record(approval(i, ["local:a", "local:b"]));
    const stored = await log.read();
    expect(stored.map((c) => c.actor)).toEqual(["local:a", "local:b"]);
  });

  it("stores exactly one JSON line per receipt, newline-terminated", async () => {
    await log.record(approval(intent(2), ["local:a", "local:b"]));
    const raw = await readFile(log.filePath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    const lines = raw.split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
    for (const line of lines) expect(() => JSON.parse(line)).not.toThrow();
  });

  it("appends across multiple records rather than overwriting", async () => {
    const i = intent();
    await log.record(approval(i, ["local:a"]));
    await log.record({ decision: "reject", policy: "approver", countersignatures: [signDecision(i, "reject", "local:b", authority)] });
    const stored = await log.read();
    expect(stored).toHaveLength(2);
    expect(stored.map((c) => c.decision)).toEqual(["approve", "reject"]);
  });
});

describe("history()", () => {
  it("groups receipts by intent_id preserving write order", async () => {
    const i1 = intent(2);
    const i2 = intent();
    await log.record(approval(i1, ["local:a", "local:b"]));
    await log.record(approval(i2, ["local:a"]));
    const h = await log.history();
    expect([...h.keys()].sort()).toEqual([i1.intent_id, i2.intent_id].sort());
    expect(h.get(i1.intent_id)!.map((c) => c.actor)).toEqual(["local:a", "local:b"]);
    expect(h.get(i2.intent_id)).toHaveLength(1);
  });
});

describe("verifyAll()", () => {
  it("binds a keyed receipt to its Intent approver — a trusted approver cannot forge another's", async () => {
    const i = intent(2); // keyed local:a / local:b, distinct keys
    // local:a signs a receipt claiming to be local:b, using HER own key.
    const forged = signDecision(i, "approve", "local:b", keyOf("local:a").secretKey, "approver");
    await log.append(forged);
    const report = await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] });
    expect(report.ok).toBe(false);
    expect(report.faults.some((f) => f.reason === "untrusted-key")).toBe(true);
  });

  it("reports every receipt valid when untampered", async () => {
    await log.record(approval(intent(2), ["local:a", "local:b"]));
    const r = await log.verifyAll();
    expect(r).toMatchObject({ total: 2, valid: 2, ok: true });
    expect(r.faults).toEqual([]);
  });

  it("flags a tampered receipt as invalid-signature", async () => {
    const i = intent();
    const cs = signDecision(i, "approve", "local:a", authority);
    // Persist a forged line: flip the decision but keep the old signature.
    await log.append({ ...cs, decision: "reject" as Decision });
    const r = await log.verifyAll();
    expect(r.ok).toBe(false);
    expect(r.faults[0]).toMatchObject({ index: 0, reason: "invalid-signature", intent_id: i.intent_id });
  });

  it("with trustedKeys, flags a receipt signed by an untrusted authority", async () => {
    const i = intent();
    const rogue = generateKeypair().secretKey;
    await log.append(signDecision(i, "approve", "local:a", authority)); // trusted
    await log.append(signDecision(i, "approve", "local:b", rogue)); // untrusted but self-consistent
    const r = await log.verifyAll({ trustedKeys: authorityPub });
    expect(r.valid).toBe(1);
    expect(r.faults).toEqual([{ index: 1, intent_id: i.intent_id, actor: "local:b", reason: "untrusted-key" }]);
  });

  it("with intents, flags a receipt whose intent is unknown", async () => {
    const known = intent();
    const stray = intent();
    await log.append(signDecision(known, "approve", "local:a", authority));
    await log.append(signDecision(stray, "approve", "local:a", authority));
    // authorityKey lets the known vouched receipt verify cleanly, isolating the
    // unknown-intent check to the stray receipt.
    const r = await log.verifyAll({ intents: [known], authorityKey: authorityPub });
    expect(r.faults).toEqual([{ index: 1, intent_id: stray.intent_id, actor: "local:a", reason: "unknown-intent" }]);
  });

  it("accepts a vouched receipt signed by a ROTATED-OUT authority key (authorityKey as an array)", async () => {
    const oldAuth = generateKeypair();
    const i = intent(); // vouched local:a / local:b
    await log.append(signDecision(i, "approve", "local:a", oldAuth.secretKey)); // signed by the OLD authority
    // Auditing across a rotation: accept a receipt signed by ANY listed authority key.
    const r = await log.verifyAll({ intents: [i], authorityKey: [authorityPub, oldAuth.publicKey] });
    expect(r.ok).toBe(true);
    // …but a key NOT in the set is still rejected.
    const r2 = await log.verifyAll({ intents: [i], authorityKey: [authorityPub] });
    expect(r2.ok).toBe(false);
  });

  it("throws if authorityKey is passed without intents (no silent no-op)", async () => {
    await expect(log.verifyAll({ authorityKey: authorityPub })).rejects.toThrow(/without `intents`|no effect/);
  });

  it("throws on an EMPTY authorityKey array (would vacuously disable the SoD checks)", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await expect(log.verifyAll({ intents: [i], authorityKey: [] })).rejects.toThrow(/empty array|at least one/);
  });

  it("classifies a passkey receipt with a MISSING webauthn block as invalid-signature (not missing-policy)", async () => {
    const i = intent();
    // A valid passkey DESCRIPTOR but no assertion block (structural corruption) — detectable
    // without the RP policy, so it must not read as a mere config omission.
    const bad = { ...signDecision(i, "approve", "local:a", authority), public_key: `webauthn-ed25519:${authorityPub}` };
    await log.append(bad);
    const r = await log.verifyAll({ intents: [i] }); // no webauthn policy
    expect(r.faults.some((f) => f.reason === "invalid-signature")).toBe(true);
    expect(r.faults.some((f) => f.reason === "missing-webauthn-policy")).toBe(false);
  });

  it("faults a vouched/Default receipt as missing-authority-key when authorityKey is omitted", async () => {
    // An authority-signed receipt cannot be verified without the authority key, so the
    // audit reports it honestly (not silently valid, not a tamper alarm).
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority)); // honest vouched approval
    const r = await log.verifyAll({ intents: [i] }); // no authorityKey
    expect(r.ok).toBe(false);
    expect(r.faults).toEqual([{ index: 0, intent_id: i.intent_id, actor: "local:a", reason: "missing-authority-key" }]);
    // …and it clears once the authority key is supplied.
    expect((await log.verifyAll({ intents: [i], authorityKey: authorityPub })).ok).toBe(true);
  });

  it("does NOT trust an Intent authored BY the audit authority key (agent == authority)", async () => {
    // The authority-key holder authors an Intent (agent == authority), binds an approver
    // key IT controls, and signs the receipt. verifyResolution rejects this (SoD); the
    // audit must too — the Intent is untrusted, so its receipt faults as unverified-intent.
    const attacker = generateKeypair();
    const evil = createIntent(
      { action: "a", summary: "s", risk_tier: "critical", approvers: [{ actor: "local:a", mode: "keyed", public_key: attacker.publicKey }], quorum: 1, timeout: 300, default: "reject" },
      { id: "agent:evil", keypair: { publicKey: authorityPub, secretKey: authority } },
    );
    await log.append(signDecision(evil, "approve", "local:a", attacker.secretKey, "approver"));
    const r = await log.verifyAll({ intents: [evil], authorityKey: authorityPub });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.reason === "unverified-intent")).toBe(true);
  });

  it("classifies a MALFORMED passkey descriptor as invalid-signature, not missing-webauthn-policy", async () => {
    const i = intent();
    // A receipt whose public_key carries a WebAuthn prefix but corrupt (too-short) key bytes.
    const bad = { ...signDecision(i, "approve", "local:a", authority), public_key: "webauthn-ed25519:AAAA" };
    await log.append(bad);
    const r = await log.verifyAll({ intents: [i] }); // no webauthn policy
    expect(r.faults.some((f) => f.reason === "invalid-signature")).toBe(true);
    expect(r.faults.some((f) => f.reason === "missing-webauthn-policy")).toBe(false);
  });

  it("faults a FORGED vouched receipt when audited with authorityKey", async () => {
    // A vouched receipt is authority-signed; verifyResolution binds it to the authority
    // key, so the audit must reject one signed by a rogue key when authorityKey is given.
    const i = intent(); // quorum-1 vouched local:a / local:b
    const rogue = generateKeypair().secretKey;
    await log.append(signDecision(i, "approve", "local:a", rogue)); // forged, attacker key
    const r = await log.verifyAll({ intents: [i], authorityKey: authorityPub });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.actor === "local:a" && f.reason === "untrusted-key")).toBe(true);
  });

  it("rejects a non-canonical authorityKey (alias would dodge the SoD compare)", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const bytes = fromB64url(authorityPub);
    let alias = "";
    for (const c of alphabet) { const cand = authorityPub.slice(0, -1) + c; if (cand !== authorityPub && fromB64url(cand).length === 32 && fromB64url(cand).equals(bytes)) { alias = cand; break; } }
    expect(alias).not.toBe("");
    await expect(log.verifyAll({ intents: [i], authorityKey: alias })).rejects.toThrow(/canonical/);
  });

  it("faults a keyed slot bound to a trusted authority key (audit matches verifyResolution)", async () => {
    // An Intent that binds a keyed approver to the AUTHORITY key, with a receipt signed
    // by that authority key: verifyResolution rejects it (a keyed slot must be the
    // approver's OWN key), so the audit must not report it valid either.
    const i = createIntent(
      { action: "demo.op", summary: "x", risk_tier: "high", approvers: [{ actor: "local:a", mode: "keyed", public_key: authorityPub }], quorum: 1, timeout: 300, default: "reject" },
      agent,
    );
    await log.append(signDecision(i, "approve", "local:a", authority, "approver"));
    // With the dedicated authorityKey supplied, the forged keyed slot is caught…
    const r = await log.verifyAll({ intents: [i], authorityKey: authorityPub });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.actor === "local:a" && f.reason === "untrusted-key")).toBe(true);
  });

  it("accepts a well-formed timeout Default but faults a wrong-decision or backdated one", async () => {
    const i = intent(2); // quorum 2 → expected Default is reject
    const atDeadline = new Date(deadline(i) + 1).toISOString();
    // Well-formed: reject, stamped at/after the deadline, authority-signed.
    await log.append(signDecision(i, "reject", "default:timeout", authority, "default", atDeadline));
    expect((await log.verifyAll({ intents: [i], authorityKey: authorityPub })).ok).toBe(true);

    // Wrong decision (approve on a quorum>1 Intent) → faults.
    const log2 = new ReceiptLog(join(dir, "d2.jsonl"));
    await log2.append(signDecision(i, "approve", "default:timeout", authority, "default", atDeadline));
    expect((await log2.verifyAll({ intents: [i], authorityKey: authorityPub })).ok).toBe(false);

    // Backdated before the deadline → faults.
    const log3 = new ReceiptLog(join(dir, "d3.jsonl"));
    await log3.append(signDecision(i, "reject", "default:timeout", authority, "default", new Date(deadline(i) - 60_000).toISOString()));
    expect((await log3.verifyAll({ intents: [i], authorityKey: authorityPub })).ok).toBe(false);
  });

  it("applies trustedKeys as an ADDITIONAL allowlist to keyed receipts (with intents + authorityKey)", async () => {
    const i = intent(2); // keyed local:a / local:b
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    // local:a's key is NOT in trustedKeys → the receipt faults though it's validly bound; the auditor's
    // trust policy is honored, not dropped once the Intent authenticates. authorityKey is the required
    // keyed-slot SoD anchor; trustedKeys is the ADDITIONAL filter layered on top.
    const r = await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: [keyOf("local:b").publicKey] });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.actor === "local:a" && f.reason === "untrusted-key")).toBe(true);
    // …and when local:a's key IS in the allowlist, it passes.
    expect((await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] })).ok).toBe(true);
  });

  it("does NOT mis-flag an honest keyed receipt when its own key is in trustedKeys", async () => {
    // Regression: the keyed-slot==authority check must use the dedicated authorityKey,
    // NOT the trustedKeys allowlist — which legitimately holds the approvers' own keys.
    const i = intent(2); // keyed local:a / local:b, distinct keys
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    const r = await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] });
    expect(r.faults).toEqual([]); // Alice's own key in trustedKeys must not fault her receipt
    expect(r.ok).toBe(true);
  });

  it("does NOT trust a TAMPERED Intent's approver binding (fake receipt via a swapped key)", async () => {
    const i = intent(2); // keyed local:a / local:b with distinct keys
    const evil = generateKeypair();
    // The attacker's receipt for local:a, signed by a key THEY control.
    await log.append(signDecision(i, "approve", "local:a", evil.secretKey, "approver"));
    // …then edits the archived Intent to bind local:a -> evil's key. This
    // invalidates the Intent's agent signature; a naive verifier would still read
    // the swapped binding as the trust anchor and report the fake receipt valid.
    const tampered: Intent = {
      ...i,
      approvers: i.approvers.map((a) =>
        normalizeActor(a.actor) === normalizeActor("local:a") ? { ...a, public_key: evil.publicKey } : a,
      ),
    };
    const r = await log.verifyAll({ intents: [tampered] });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.actor === "local:a" && f.reason === "unverified-intent")).toBe(true);
  });

  it("faults a keyed-approver receipt carrying a non-approver policy (audit matches verifyResolution)", async () => {
    const i = intent(2); // keyed local:a / local:b
    // Signed by local:a's OWN key but labeled policy "default" — verifyResolution rejects
    // exactly this, so the audit must fault it too, not read it as valid.
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "default"));
    const r = await log.verifyAll({ intents: [i] });
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.actor === "local:a" && f.reason === "untrusted-key")).toBe(true);
  });

  it("with trustedAgentKeys, ignores an Intent signed by an unpinned agent", async () => {
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    // The Intent verifies under its own agent key, but we pin a DIFFERENT agent.
    const r = await log.verifyAll({ intents: [i], trustedAgentKeys: [generateKeypair().publicKey] });
    expect(r.faults.some((f) => f.reason === "unverified-intent")).toBe(true);
    // Pinning the correct agent key trusts the binding again. authorityKey is the keyed-slot SoD
    // anchor (trustedAgentKeys pins the agent but cannot check keyed-slot ≠ authority on its own).
    const ok = await log.verifyAll({ intents: [i], trustedAgentKeys: [agent.keypair.publicKey], authorityKey: authorityPub });
    expect(ok.ok).toBe(true);
  });

  it("throws on an EMPTY trustedAgentKeys array (would drop every Intent and false-fault an honest log)", async () => {
    // Symmetric to the authorityKey empty-array guard: `[].includes(agent)` is always false, so an
    // empty pin silently drops every supplied Intent and faults an untampered log as unverified-intent.
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    await expect(log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedAgentKeys: [] })).rejects.toThrow(/trustedAgentKeys must not be an empty array|at least one agent/);
  });

  it("faults a keyed receipt audited with trustedAgentKeys ONLY — the keyed-slot SoD check needs authorityKey (or trustedKeys)", async () => {
    // trustedAgentKeys pins the AGENT, but the keyed-slot ≠ authority separation-of-duty check needs
    // the authority key (or a trustedKeys allowlist that excludes it). With neither, verifyAll cannot
    // check keyed SoD and must fault missing-authority-key — matching verifyResolution, not silently
    // report ok on a log whose keyed slot might be bound to the runtime authority key.
    const i = intent(2); // keyed local:a / local:b, honest agent
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    const only = await log.verifyAll({ intents: [i], trustedAgentKeys: [agent.keypair.publicKey] });
    expect(only.ok).toBe(false);
    expect(only.faults.some((f) => f.reason === "missing-authority-key")).toBe(true);
    // Adding the authority key (the keyed-slot SoD anchor) alongside the agent pin clears it.
    expect((await log.verifyAll({ intents: [i], trustedAgentKeys: [agent.keypair.publicKey], authorityKey: authorityPub })).ok).toBe(true);
    // …but trustedKeys alone is NOT the keyed anchor — it's an approver allowlist that may itself
    // contain the authority key, so it can't check keyed-slot ≠ authority. authorityKey is required;
    // trustedKeys/trustedAgentKeys only compose ON TOP of it (shown here with all three).
    expect((await log.verifyAll({ intents: [i], trustedAgentKeys: [agent.keypair.publicKey], trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] })).ok).toBe(false);
    expect((await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedAgentKeys: [agent.keypair.publicKey], trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] })).ok).toBe(true);
  });

  it("faults a keyed receipt in BARE mode (no authorityKey / no trustedKeys) — the authority-key holder cannot forge a keyed quorum", async () => {
    // The authority-key holder authors an Intent (agent == authority), binds a keyed approver to
    // a key IT controls, and self-signs that approver's receipt. In BARE mode there is NO anchor:
    // no authorityKey for the separation-of-duty check (agent≠authority, approver-key≠authority),
    // and no trustedKeys allowlist to constrain the approver key. The receipt then only verifies
    // against an attacker-chosen binding, so it must fault as missing-authority-key (honest, like
    // vouched/Default), NOT silently pass ok=true — the exact SoD bypass keyed quorums exist to block.
    const attacker = generateKeypair();
    const evil = createIntent(
      { action: "a", summary: "s", risk_tier: "critical", approvers: [{ actor: "local:a", mode: "keyed", public_key: attacker.publicKey }], quorum: 1, timeout: 300, default: "reject" },
      { id: "agent:evil", keypair: { publicKey: authorityPub, secretKey: authority } },
    );
    await log.append(signDecision(evil, "approve", "local:a", attacker.secretKey, "approver"));
    const bare = await log.verifyAll({ intents: [evil] }); // no authorityKey, no trustedKeys
    expect(bare.ok).toBe(false);
    expect(bare.faults.some((f) => f.reason === "missing-authority-key")).toBe(true);
    // A trustedKeys allowlist that omits the attacker's key is a valid anchor and also catches it.
    expect((await log.verifyAll({ intents: [evil], trustedKeys: [keyOf("local:b").publicKey] })).ok).toBe(false);
  });

  it("does NOT fault an authority-signed vouched OR timeout-Default receipt when trustedKeys holds only approver keys (round-7 regression)", async () => {
    // The additional trustedKeys gate must apply ONLY to keyed (approver-signed) receipts.
    // authorityKey is the distinct anchor for authority-signed vouched approvals and the timeout
    // Default; a trustedKeys allowlist that legitimately holds only approver keys must not fault them.
    const iv = intent(); // vouched local:a / local:b
    await log.append(signDecision(iv, "approve", "local:a", authority)); // honest vouched approval
    const rv = await log.verifyAll({ intents: [iv], authorityKey: authorityPub, trustedKeys: [keyOf("local:a").publicKey] });
    expect(rv.faults).toEqual([]);
    expect(rv.ok).toBe(true);

    // Same for a well-formed timeout Default (authority-signed, actor default:timeout).
    const ik = intent(2); // quorum 2 → expected Default is reject
    const atDeadline = new Date(deadline(ik) + 1).toISOString();
    const log2 = new ReceiptLog(join(dir, "reg3-default.jsonl"));
    await log2.append(signDecision(ik, "reject", "default:timeout", authority, "default", atDeadline));
    expect((await log2.verifyAll({ intents: [ik], authorityKey: authorityPub, trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] })).ok).toBe(true);
  });

  it("faults a keyed slot bound to the authority key even when trustedKeys contains it, no authorityKey (audit matches verifyResolution)", async () => {
    // An auditor who (mis)uses trustedKeys as the authority allowlist and omits authorityKey. A keyed
    // slot bound to — and signed by — the authority key is a SoD violation verifyResolution always
    // rejects. Without authorityKey, verifyAll cannot check keyed-slot ≠ authority, so it must fault
    // missing-authority-key — NOT pass just because the authority key happens to sit in trustedKeys.
    const i = createIntent(
      { action: "demo.op", summary: "x", risk_tier: "high", approvers: [{ actor: "local:a", mode: "keyed", public_key: authorityPub }], quorum: 1, timeout: 300, default: "reject" },
      agent,
    );
    await log.append(signDecision(i, "approve", "local:a", authority, "approver"));
    const r = await log.verifyAll({ intents: [i], trustedKeys: [authorityPub] }); // authority key IN trustedKeys, NO authorityKey
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.reason === "missing-authority-key")).toBe(true);
    // With authorityKey supplied, the same slot is caught specifically as the keyed-slot==authority violation.
    const r2 = await log.verifyAll({ intents: [i], authorityKey: authorityPub });
    expect(r2.ok).toBe(false);
    expect(r2.faults.some((f) => f.actor === "local:a" && f.reason === "untrusted-key")).toBe(true);
  });

  it("throws when trustedAgentKeys is supplied WITHOUT intents (silent no-op guard, symmetric to authorityKey)", async () => {
    // trustedAgentKeys is consulted only inside the per-Intent block, so passing it alone would be a
    // silent no-op yielding an integrity-only pass — like the authorityKey-without-intents case, throw.
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    await expect(log.verifyAll({ trustedAgentKeys: [agent.keypair.publicKey] })).rejects.toThrow(/trustedAgentKeys has no effect without|without `intents`/);
  });

  it("treats a keyed approver's raw key and its webauthn-ed25519 descriptor as ONE identity in the trustedKeys gate", async () => {
    // The keyed-slot==authority check normalizes via credentialKeyMaterial (raw K ≡ webauthn-ed25519:K),
    // so the ADDITIONAL trustedKeys allowlist must too — else an auditor who holds the key in the other
    // equivalent encoding false-faults an honest log. Here a raw-ed25519 keyed approver's key is given
    // to trustedKeys in DESCRIPTOR form; it must still pass, not fault untrusted-key.
    const i = intent(2); // raw-ed25519 keyed local:a / local:b
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    const descriptorForm = [`webauthn-ed25519:${keyOf("local:a").publicKey}`, `webauthn-ed25519:${keyOf("local:b").publicKey}`];
    const r = await log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: descriptorForm });
    expect(r.faults).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it("throws on an EMPTY trustedKeys array (would silently fault every keyed receipt)", async () => {
    // Symmetric to the authorityKey / trustedAgentKeys empty-array guards: verifyCountersignature([])
    // is always false, so an empty allowlist faults every receipt as untrusted-key on an honest log.
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    await expect(log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: [] })).rejects.toThrow(/trustedKeys must not be empty|at least one/);
  });

  it("throws on an empty-STRING trustedKeys (it must not slip past the empty guard)", async () => {
    // trustedKeys: "" normalizes to [""], which matches no real key — same all-untrusted false alarm
    // as trustedKeys: []. The guard must catch a no-usable-key allowlist whatever its shape.
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    await expect(log.verifyAll({ intents: [i], authorityKey: authorityPub, trustedKeys: "" })).rejects.toThrow(/trustedKeys must not be empty|at least one/);
  });

  it("no-intents trustedKeys fallback matches by credentialKeyMaterial (raw ≡ descriptor), same as the keyed gate", async () => {
    // The keyed gate treats raw K and webauthn-ed25519:K as ONE identity (one key, one holder).
    // The no-intents fallback must use the SAME semantics — else the identical allowlist flips the
    // audit verdict depending on whether `intents` was supplied, and the equivalent-form key
    // false-faults an honest log.
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority)); // public_key = raw authorityPub
    const r = await log.verifyAll({ trustedKeys: [`webauthn-ed25519:${authorityPub}`] }); // descriptor form of the SAME key
    expect(r.faults).toEqual([]);
    expect(r.ok).toBe(true);
    // A genuinely different key still faults.
    expect((await log.verifyAll({ trustedKeys: [`webauthn-ed25519:${generateKeypair().publicKey}`] })).ok).toBe(false);
  });

  it("throws on an EMPTY intents array (would fault every receipt as unknown-intent)", async () => {
    // Symmetric to the other empty-array guards: intents: [] builds an empty binding map, so every
    // receipt on an honest log faults unknown-intent (ok:false) — a false tamper alarm. Reject it.
    const i = intent(2);
    await log.append(signDecision(i, "approve", "local:a", keyOf("local:a").secretKey, "approver"));
    await expect(log.verifyAll({ intents: [], authorityKey: authorityPub })).rejects.toThrow(/intents must not be an empty array|at least one Intent/);
  });
});

describe("corruption is loud", () => {
  it("read() throws with a line number on a non-JSON line", async () => {
    await log.append(signDecision(intent(), "approve", "local:a", authority));
    await writeFile(log.filePath, (await readFile(log.filePath, "utf8")) + "{ not json\n");
    await expect(log.read()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.read()).rejects.toBeInstanceOf(CountersignError);
  });
});

describe("concurrent writes do not interleave", () => {
  it("keeps every line intact under parallel records", async () => {
    const i = intent();
    // Fire 50 records concurrently; each is one receipt.
    await Promise.all(
      Array.from({ length: 50 }, (_, n) =>
        log.record({ decision: "approve", policy: "approver", countersignatures: [signDecision(i, "approve", `local:${n}`, authority)] }),
      ),
    );
    const stored = await log.read(); // read() would throw if any line were torn
    expect(stored).toHaveLength(50);
    expect(new Set(stored.map((c) => c.actor)).size).toBe(50);
    // Serialized writes must still form one unbroken chain (seq 0..49).
    expect(await log.verifyChain()).toEqual({ intact: true, length: 50 });
  });
});

describe("hash chain — completeness", () => {
  async function rawLines(): Promise<string[]> {
    return (await readFile(log.filePath, "utf8")).split("\n").filter(Boolean);
  }
  async function writeLines(lines: string[]): Promise<void> {
    await writeFile(log.filePath, lines.map((l) => l + "\n").join(""));
  }

  it("verifyChain is intact for an untampered log", async () => {
    const i = intent();
    for (const a of ["local:a", "local:b", "local:c"]) await log.append(signDecision(i, "approve", a, authority));
    expect(await log.verifyChain()).toEqual({ intact: true, length: 3 });
  });

  it("detects a deleted middle entry", async () => {
    const i = intent();
    for (const a of ["local:a", "local:b", "local:c"]) await log.append(signDecision(i, "approve", a, authority));
    const lines = await rawLines();
    await writeLines([lines[0], lines[2]]); // drop the middle one
    const c = await log.verifyChain();
    expect(c.intact).toBe(false);
    expect(c.brokenAt).toBe(1);
    expect(["bad-seq", "broken-link"]).toContain(c.reason);
  });

  it("detects reordered entries", async () => {
    const i = intent();
    for (const a of ["local:a", "local:b"]) await log.append(signDecision(i, "approve", a, authority));
    const [l0, l1] = await rawLines();
    await writeLines([l1, l0]); // swap
    expect((await log.verifyChain()).intact).toBe(false);
  });

  it("detects an edited receipt in a non-final entry via the next link", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await log.append(signDecision(i, "approve", "local:b", authority));
    const lines = await rawLines();
    const entry0 = JSON.parse(lines[0]);
    entry0.receipt.actor = "local:evil"; // tamper the first entry's receipt, keep its prev
    lines[0] = JSON.stringify(entry0);
    await writeLines(lines);
    const c = await log.verifyChain();
    expect(c).toMatchObject({ intact: false, reason: "broken-link", brokenAt: 1 });
  });

  it("detects an inserted entry", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await log.append(signDecision(i, "approve", "local:b", authority));
    const [l0, l1] = await rawLines();
    await writeLines([l0, l0, l1]); // duplicate line 0 in
    expect((await log.verifyChain()).intact).toBe(false);
  });

  it("continues the chain across a simulated process restart (new instance, same file)", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await log.append(signDecision(i, "approve", "local:b", authority));
    const reopened = new ReceiptLog(log.filePath); // fresh process → fresh instance
    await reopened.append(signDecision(i, "approve", "local:c", authority));
    expect(await reopened.verifyChain()).toEqual({ intact: true, length: 3 });
    expect((await reopened.read()).map((r) => r.actor)).toEqual(["local:a", "local:b", "local:c"]);
  });

  it("head() anchors detection of tail truncation", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await log.append(signDecision(i, "approve", "local:b", authority));
    const anchored = await log.head(); // { length: 2, hash }
    const [l0] = await rawLines();
    await writeLines([l0]); // lop off the newest entry
    // A forward chain alone still looks intact (one clean entry)...
    expect((await log.verifyChain()).intact).toBe(true);
    // ...but against the anchored head, truncation is caught.
    expect(await log.verifyChain(anchored)).toMatchObject({ intact: false, reason: "truncated" });
  });

  it("verifyAll folds completeness into ok (authentic receipts, broken chain)", async () => {
    const i = intent();
    await log.append(signDecision(i, "approve", "local:a", authority));
    await log.append(signDecision(i, "approve", "local:b", authority));
    const [l0, l1] = await rawLines();
    await writeLines([l1, l0]); // reorder: receipts stay genuine, chain breaks
    const r = await log.verifyAll();
    expect(r.faults).toEqual([]); // every receipt is a genuine signature
    expect(r.chain.intact).toBe(false); // but the sequence was tampered
    expect(r.ok).toBe(false);
  });

  it("reads a legacy unchained log but flags it in verifyChain", async () => {
    const i = intent();
    await mkdir(dirname(log.filePath), { recursive: true }); // no prior append created it
    await writeFile(log.filePath, JSON.stringify(signDecision(i, "approve", "local:a", authority)) + "\n");
    expect(await log.read()).toHaveLength(1); // bare v0.1.1 line still readable
    expect(await log.verifyChain()).toMatchObject({ intact: false, brokenAt: 0, reason: "unchained-entry" });
  });

  it("verifyAll REPORTS a malformed line as a fault instead of throwing", async () => {
    await log.append(signDecision(intent(), "approve", "local:a", authority));
    await writeFile(log.filePath, (await readFile(log.filePath, "utf8")) + '{"note":"junk-but-valid-json"}\n');
    const r = await log.verifyAll(); // must not throw
    expect(r.ok).toBe(false);
    expect(r.faults.some((f) => f.reason === "malformed")).toBe(true);
  });
});

describe("wrapAction integration", () => {
  class FakeAdapter implements Adapter {
    readonly channel = "fake";
    constructor(
      private readonly decision: Decision,
      private readonly secret: string,
    ) {}
    async deliver(): Promise<void> {}
    async awaitResolution(i: Intent): Promise<Resolution> {
      const cs = signDecision(i, this.decision, "fake:approver", this.secret);
      return { decision: this.decision, policy: "approver", countersignatures: [cs] };
    }
  }

  it("records the approval before running the guarded action", async () => {
    const order: string[] = [];
    const guarded = wrapAction(
      () => {
        order.push("action");
        return "done";
      },
      { action: "demo.op", summary: "x", risk_tier: "high", approvers: ["fake:approver"], timeout: 300, default: "reject" },
      new FakeAdapter("approve", authority),
      { authorityKey: authority, receiptLog: log, onResolution: () => order.push("recorded-hook") },
    );
    expect(await guarded()).toBe("done");
    const stored = await log.read();
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ decision: "approve", actor: "fake:approver" });
    // action ran after the resolution hook fired (log write is awaited before the action)
    expect(order).toEqual(["recorded-hook", "action"]);
  });

  it("records a veto even though the action is blocked", async () => {
    const guarded = wrapAction(
      () => "should-not-run",
      { action: "demo.op", summary: "x", risk_tier: "high", approvers: ["fake:approver"], timeout: 300, default: "reject" },
      new FakeAdapter("reject", authority),
      { authorityKey: authority, receiptLog: log },
    );
    await expect(guarded()).rejects.toThrow(/not authorized/);
    const stored = await log.read();
    expect(stored).toHaveLength(1);
    expect(stored[0].decision).toBe("reject");
  });

  it("fail-closed: if the sink throws, the guarded action never runs", async () => {
    let ran = false;
    const throwingSink = {
      record: () => {
        throw new Error("disk full");
      },
    };
    const guarded = wrapAction(
      () => {
        ran = true;
        return "done";
      },
      { action: "demo.op", summary: "x", risk_tier: "high", approvers: ["fake:approver"], timeout: 300, default: "reject" },
      new FakeAdapter("approve", authority),
      { authorityKey: authority, receiptLog: throwingSink },
    );
    await expect(guarded()).rejects.toThrow(/disk full/);
    expect(ran).toBe(false);
  });
});
