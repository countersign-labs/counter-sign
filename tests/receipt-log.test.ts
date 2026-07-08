// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { CountersignError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Decision, Intent, Resolution } from "../src/core/types.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { wrapAction } from "../src/shim.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const authorityPub = publicKeyFromSecret(authority);

function intent(quorum = 1): Intent {
  return createIntent(
    { action: "demo.op", summary: "Do the thing", risk_tier: "high", approvers: ["local:a", "local:b"], quorum, timeout: 300, default: "reject" },
    agent,
  );
}

/** A resolution built from real signed receipts, as an adapter would produce. */
function approval(i: Intent, actors: string[], secret = authority): Resolution {
  return { decision: "approve", policy: "approver", countersignatures: actors.map((a) => signDecision(i, "approve", a, secret)) };
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
    const r = await log.verifyAll({ intents: [known] });
    expect(r.faults).toEqual([{ index: 1, intent_id: stray.intent_id, actor: "local:a", reason: "unknown-intent" }]);
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
