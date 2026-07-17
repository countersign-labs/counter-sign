// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// End-to-end write round-trip in node: browser-sign an entry, apply it server-side
// (validate + persist), and confirm it lands and re-verifies from disk — and that a
// forged/unauthorized entry is rejected without touching disk.
import { mkdtempSync, readFileSync } from "node:fs";
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

  it("rejects an unsafe rule (quorum>1 + default approve)", async () => {
    const dir = emptyDir();
    const admin = generateKeypair();
    applySignedEntry(dir, await signPolicyEntry({ kind: "admin-add", org: "acme", public_key: admin.publicKey }, policyHead(dir), admin.secretKey));
    applySignedEntry(dir, await signPolicyEntry({ kind: "role-set", role: { id: "f", org: "acme", name: "f", members: ["m:a", "m:b"] } }, policyHead(dir), admin.secretKey));
    const bad = await signPolicyEntry({ kind: "rule-set", rule: { id: "u", org: "acme", name: "u", roles: ["f"], quorum: 2, default: "approve", timeout_seconds: 3600 } }, policyHead(dir), admin.secretKey);
    expect(applySignedEntry(dir, bad).ok).toBe(false);
  });
});
