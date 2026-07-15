// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { normalizeActor, signDecision } from "../src/core/countersignature.js";
import { CountersignError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret, type Keypair } from "../src/core/keys.js";
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
    const report = await log.verifyAll({ intents: [i], trustedKeys: [keyOf("local:a").publicKey, keyOf("local:b").publicKey] });
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
