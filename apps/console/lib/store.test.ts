// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConsoleState } from "./store";
import { seedSampleData } from "./seed";

function seeded() {
  const dir = mkdtempSync(join(tmpdir(), "cs-console-"));
  const { orgPublicKey } = seedSampleData(dir);
  return { dir, orgPublicKey };
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
    expect(s.rules).toEqual([]);
    expect(s.admins).toEqual([]);
  });
});
