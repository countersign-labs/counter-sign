// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, appendFileSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PolicyLog } from "@countersignlabs/counter-sign";
import { loadConsoleState } from "./store";
import { signPolicyEntry } from "./policy-entry";
import { seedSampleData } from "./seed";

function seeded() {
  const dir = mkdtempSync(join(tmpdir(), "cs-console-"));
  const { orgPublicKey, adminSecret } = seedSampleData(dir);
  return { dir, orgPublicKey, adminSecret };
}

describe("loadConsoleState", () => {
  it("loads and verifies a seeded data dir", () => {
    const { dir, orgPublicKey } = seeded();
    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(true);
    expect(s.faults).toEqual([]);
    expect(s.org).toBe("acme");
    expect(s.rules.map((r) => r.name)).toContain("refund");
    expect(s.roles.map((r) => r.name)).toContain("finance-approvers");
    expect(s.admins.length).toBe(1);
    expect(s.approvers.find((a) => a.actor === "m:cfo")?.keys.length).toBe(1);
  });

  it("reports verified:false with a fault when the policy log is tampered", () => {
    const { dir, orgPublicKey } = seeded();
    // Append a junk line to policy.jsonl to break the chain (bad seq/prev/signature).
    appendFileSync(
      join(dir, "policy.jsonl"),
      JSON.stringify({
        countersign: "0.2",
        seq: 99,
        change: { kind: "role-set", role: { id: "x", org: "acme", name: "x", members: ["m:cfo"] } },
        issued_at: "2026-01-01T00:00:00.000Z",
        prev: "bad",
        signer_public_key: "z",
        signature: "z",
      }) + "\n",
    );
    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(false);
    expect(s.faults.some((f) => /policy log/.test(f))).toBe(true);
  });

  it("does NOT project derived state from an unverified log (no malformed data leaks to pages)", () => {
    const { dir, orgPublicKey } = seeded();
    // A forged role-set with members:null: parses + folds, but fails verifyChain. It must not
    // reach the roles list (the Roles page would crash on r.members.join before the banner).
    appendFileSync(
      join(dir, "policy.jsonl"),
      JSON.stringify({
        countersign: "0.2",
        seq: 99,
        change: { kind: "role-set", role: { id: "x", org: "acme", name: "x", members: null } },
        issued_at: "2026-01-01T00:00:00.000Z",
        prev: "bad",
        signer_public_key: "z",
        signature: "z",
      }) + "\n",
    );
    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(false);
    expect(s.policyVerified).toBe(false);
    expect(s.roles).toEqual([]); // nothing derived from the unverified log
    expect(s.admins).toEqual([]);
    expect(s.rules).toEqual([]);
  });

  it("faults (never renders an object) when a VERIFIED record has a malformed optional field", async () => {
    const { dir, orgPublicKey, adminSecret } = seeded();
    // A role-set whose optional `description` is an object. This passes verifyChain (the library
    // validates required fields, not optional strings) yet would throw at {r.description} on the
    // Roles page. It must instead surface as a fault with empty lists.
    const head = PolicyLog.fromJSONL(readFileSync(join(dir, "policy.jsonl"), "utf8")).head();
    const bad = await signPolicyEntry({ kind: "role-set", role: { id: "bad", org: "acme", name: "bad", members: ["m:cfo"], description: {} } } as never, head, adminSecret);
    appendFileSync(join(dir, "policy.jsonl"), JSON.stringify(bad) + "\n");

    const s = loadConsoleState(dir, orgPublicKey);
    expect(s.verified).toBe(false);
    expect(s.policyVerified).toBe(false);
    expect(s.roles).toEqual([]); // nothing malformed leaks to the page
    expect(s.rules).toEqual([]);
    expect(s.admins).toEqual([]);
  });

  it("faults when a registry is present but no org key is supplied", () => {
    const { dir } = seeded();
    const s = loadConsoleState(dir, "");
    expect(s.verified).toBe(false);
    expect(s.faults.some((f) => /ORG_PUBLIC_KEY/.test(f))).toBe(true);
  });

  it("an empty data dir loads as verified with empty lists", () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-console-empty-"));
    const s = loadConsoleState(dir, "");
    expect(s.verified).toBe(true);
    expect(s.policyVerified).toBe(true);
    expect(s.rules).toEqual([]);
    expect(s.admins).toEqual([]);
  });

  it("faults (never throws) when policy.jsonl is not valid JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-console-corrupt-"));
    writeFileSync(join(dir, "policy.jsonl"), "this is not json\n");
    const s = loadConsoleState(dir, "");
    expect(s.verified).toBe(false);
    expect(s.policyVerified).toBe(false);
    expect(s.faults.some((f) => /policy log/.test(f))).toBe(true);
    expect(s.admins).toEqual([]); // no trusted state leaks out of a corrupt log
  });

  it("faults (never throws) when policy.jsonl holds an unknown change kind", () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-console-unknownkind-"));
    // Valid JSON, parseable entry, but a change.kind foldState does not recognize.
    writeFileSync(
      join(dir, "policy.jsonl"),
      JSON.stringify({ countersign: "0.2", seq: 0, change: { kind: "not-a-real-kind", org: "acme" }, issued_at: "2026-01-01T00:00:00.000Z", prev: null, signer_public_key: "z", signature: "z" }) + "\n",
    );
    const s = loadConsoleState(dir, "");
    expect(s.verified).toBe(false);
    expect(s.policyVerified).toBe(false);
  });

  it("a registry-only fault leaves policyVerified true", () => {
    const { dir } = seeded();
    // Supply no org key: registry present but unverifiable → registry fault only.
    const s = loadConsoleState(dir, "");
    expect(s.verified).toBe(false);
    expect(s.policyVerified).toBe(true); // the policy log itself is fine
    expect(s.faults.some((f) => /ORG_PUBLIC_KEY/.test(f))).toBe(true);
  });
});
