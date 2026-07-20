// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// End-to-end write round-trip in node: browser-sign an entry, apply it server-side
// (validate + persist), and confirm it lands and re-verifies from disk — and that a
// forged/unauthorized entry is rejected without touching disk.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PolicyLog, generateKeypair } from "@countersignlabs/counter-sign";
import { signPolicyEntry } from "./policy-entry";
import { applySignedEntry, policyHead } from "./write";

function emptyDir() {
  return mkdtempSync(join(tmpdir(), "cs-write-"));
}
function readPolicy(dir: string) {
  return PolicyLog.fromJSONL(readFileSync(join(dir, "policy.jsonl"), "utf8"));
}

describe("applySignedEntry", () => {
  it("accepts a browser-signed genesis then a role-set, persisting a verifiable log", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();

    const genesis = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: "root" }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, genesis)).toEqual({ ok: true });

    const role = await signPolicyEntry({ kind: "role-set", role: { id: "finance", org: "acme", name: "finance", members: ["m:cfo"] } }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, role)).toEqual({ ok: true });

    const log = readPolicy(dir);
    expect(log.verifyChain()).toBe(true);
    expect(log.getRoleById("acme", "finance")?.name).toBe("finance");
  });

  it("rejects an entry signed by a non-admin key and does not persist it", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    const stranger = generateKeypair();
    const genesis = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey);
    applySignedEntry(dir, genesis);

    // A role-set signed by a key that was never an admin.
    const forged = await signPolicyEntry({ kind: "role-set", role: { id: "x", org: "acme", name: "x", members: ["m:x"] } }, policyHead(dir), stranger.secretKey);
    const res = applySignedEntry(dir, forged);
    expect(res.ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1); // unchanged — nothing persisted
  });

  it("fails closed on a corrupt on-disk log — never overwrites it with a submitted genesis", async () => {
    const dir = emptyDir();
    // A live-but-corrupt policy.jsonl (e.g. truncated by a crash). A client submits a
    // self-signed genesis admin-add; it must be REJECTED, and the file left untouched.
    const corrupt = "not valid json\n";
    writeFileSync(join(dir, "policy.jsonl"), corrupt);
    const attacker = generateKeypair();
    const genesis = await signPolicyEntry({ kind: "admin-add", org: "evil", public_key: attacker.publicKey }, { length: 0, hash: "" }, attacker.secretKey);
    const res = applySignedEntry(dir, genesis);
    expect(res.ok).toBe(false);
    expect(readFileSync(join(dir, "policy.jsonl"), "utf8")).toBe(corrupt); // unchanged
  });

  it("policyHead throws a clean message on a corrupt log (not a raw parse error)", () => {
    const dir = emptyDir();
    writeFileSync(join(dir, "policy.jsonl"), "not valid json\n");
    expect(() => policyHead(dir)).toThrow(/unavailable/); // clean generic message (detail is logged server-side, not leaked)
  });

  it("rejects a correctly-signed entry with an unknown change kind (would poison the log)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    // An unknown kind: verifyChain accepts it, but state() cannot interpret it.
    const bogus = await signPolicyEntry({ kind: "bogus", org: "acme" } as never, policyHead(dir), admin.secretKey);
    const res = applySignedEntry(dir, bogus);
    expect(res.ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1); // not persisted
  });

  it("rejects an admin-add whose public key is not a canonical ed25519 key (lockout guard)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    const bad = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: "not-a-key" }, policyHead(dir), admin.secretKey);
    const res = applySignedEntry(dir, bad);
    expect(res.ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1); // not persisted
  });

  it("rejects a rule that references a nonexistent role (dangling reference)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    const dangling = await signPolicyEntry({ kind: "rule-set", rule: { id: "x", org: "acme", name: "x", roles: ["ghost"], quorum: 1, default: "reject", timeout_seconds: 3600 } }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, dangling).ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1);
  });

  it("rejects a role-delete that would orphan a rule still referencing it (both directions)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "role-set", role: { id: "ops", org: "acme", name: "ops", members: ["m:a"] } }, policyHead(dir), admin.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "rule-set", rule: { id: "deploy", org: "acme", name: "deploy", roles: ["ops"], quorum: 1, default: "reject", timeout_seconds: 3600 } }, policyHead(dir), admin.secretKey));
    // Deleting 'ops' would orphan rule 'deploy' (resolveRule -> "unknown role") — must be rejected.
    expect(applySignedEntry(dir, await signPolicyEntry({ kind: "role-delete", org: "acme", id: "ops" }, policyHead(dir), admin.secretKey)).ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(3); // not persisted
    // Deleting an UNreferenced role is still allowed.
    applySignedEntry(dir, await signPolicyEntry({ kind: "role-set", role: { id: "temp", org: "acme", name: "temp", members: ["m:b"] } }, policyHead(dir), admin.secretKey));
    expect(applySignedEntry(dir, await signPolicyEntry({ kind: "role-delete", org: "acme", id: "temp" }, policyHead(dir), admin.secretKey)).ok).toBe(true);
  });

  it("rejects a delete of a role/rule that does not exist", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    const del = await signPolicyEntry({ kind: "role-delete", org: "acme", id: "nope" }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, del).ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1);
  });

  it("a pre-existing (out-of-band) malformed record does NOT block a new valid change", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    // Simulate a genesis admin created out-of-band (e.g. library CLI) with a NON-STRING name: it
    // verifyChain-passes but the console would never create it. Write it straight to disk.
    const genesis = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey, name: {} } as never, { length: 0, hash: "" }, admin.secretKey);
    writeFileSync(join(dir, "policy.jsonl"), JSON.stringify(genesis) + "\n");
    // A perfectly valid new role-set must still be accepted — the write gate validates the NEW record,
    // not the whole (already-malformed) history, so the org is not permanently locked out of the console.
    const role = await signPolicyEntry({ kind: "role-set", role: { id: "finance", org: "acme", name: "finance", members: ["m:cfo"] } }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, role)).toEqual({ ok: true });
  });

  it("rejects a rule whose optional action is a non-string (write gate matches the read-side render-safe gate)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "role-set", role: { id: "finance", org: "acme", name: "finance", members: ["m:cfo"] } }, policyHead(dir), admin.secretKey));
    // verifyChain does NOT type-check `action`; without the render-safe write gate this would persist
    // and then brick the console on load. It must be rejected.
    const bad = await signPolicyEntry({ kind: "rule-set", rule: { id: "r", org: "acme", name: "r", roles: ["finance"], quorum: 1, default: "reject", timeout_seconds: 3600, action: {} } } as never, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, bad).ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(2); // not persisted
  });

  it("rejects a genesis whose org is not a string (would leak an object into the header + lock the org)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    const bad = await signPolicyEntry({ kind: "admin-add", org: {}, public_key: admin.publicKey } as never, { length: 0, hash: "" }, admin.secretKey);
    expect(applySignedEntry(dir, bad).ok).toBe(false);
  });

  it("rejects an admin name that is not a string (would crash the page)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    const other = generateKeypair();
    const bad = await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: other.publicKey, name: {} } as never, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, bad).ok).toBe(false);
    expect(readPolicy(dir).entries.length).toBe(1);
  });

  it("rejects a revoke that would leave no usable admin", async () => {
    const dir = emptyDir();
    const a1 = generateKeypair();
    const a2 = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: a1.publicKey }, policyHead(dir), a1.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: a2.publicKey }, policyHead(dir), a1.secretKey));
    // Revoking a2 leaves a1 (usable) — allowed.
    expect(applySignedEntry(dir, await signPolicyEntry({ kind: "admin-revoke", org: "acme", public_key: a2.publicKey }, policyHead(dir), a1.secretKey)).ok).toBe(true);
  });

  it("rejects an unsafe rule (quorum>1 + default approve)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "role-set", role: { id: "f", org: "acme", name: "f", members: ["m:a", "m:b"] } }, policyHead(dir), admin.secretKey));
    const bad = await signPolicyEntry({ kind: "rule-set", rule: { id: "u", org: "acme", name: "u", roles: ["f"], quorum: 2, default: "approve", timeout_seconds: 3600 } }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, bad).ok).toBe(false);
  });
});
