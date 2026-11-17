// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { appendFile, mkdtemp, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { CountersignError } from "../src/core/errors.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Decision, Intent, Resolution } from "../src/core/types.js";
import { FileIntentStore, ReceiptLog } from "../src/receipt-log.js";
import { wrapAction } from "../src/shim.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const authorityPub = publicKeyFromSecret(authority);

const fields = { action: "demo.op", summary: "Do the thing", risk_tier: "high" as const, approvers: ["fake:approver"], timeout: 300, default: "reject" as const };

function intent(): Intent {
  return createIntent(fields, agent);
}
function approve(i: Intent): Resolution {
  return { decision: "approve", policy: "approver", countersignatures: [signDecision(i, "approve", "fake:approver", authority)] };
}

class FakeAdapter implements Adapter {
  readonly channel = "fake";
  constructor(private readonly decision: Decision) {}
  async deliver(): Promise<void> {}
  async awaitResolution(i: Intent): Promise<Resolution> {
    return { decision: this.decision, policy: "approver", countersignatures: [signDecision(i, this.decision, "fake:approver", authority)] };
  }
}

/** The prototype every fs/promises FileHandle shares — spied on to observe flushes. */
async function fileHandleProto(path: string): Promise<{ datasync: () => Promise<void> }> {
  const fh = await open(path, "w");
  const proto = Object.getPrototypeOf(fh);
  await fh.close();
  return proto;
}

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-durable-log-"));
  path = join(dir, "receipts.jsonl");
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

describe("A1 durability: appends are flushed before record() resolves", () => {
  it("calls datasync on the log before record() resolves", async () => {
    const order: string[] = [];
    const proto = await fileHandleProto(join(dir, "probe"));
    const real = proto.datasync;
    vi.spyOn(proto, "datasync").mockImplementation(function (this: unknown) {
      order.push("datasync");
      return real.call(this);
    });
    const log = new ReceiptLog(path);
    await log.record(approve(intent()));
    order.push("resolved");
    expect(order).toContain("datasync");
    expect(order.at(-1)).toBe("resolved");
  });

  it("a failed flush rejects record() — an approval that may not be on disk is not reported as stored", async () => {
    const proto = await fileHandleProto(join(dir, "probe"));
    vi.spyOn(proto, "datasync").mockRejectedValue(Object.assign(new Error("EIO: flush failed"), { code: "EIO" }));
    const log = new ReceiptLog(path);
    await expect(log.record(approve(intent()))).rejects.toThrow(/EIO/);
  });

  it("wrapAction: the receipt is flushed to disk before the guarded action runs", async () => {
    const order: string[] = [];
    const proto = await fileHandleProto(join(dir, "probe"));
    const real = proto.datasync;
    vi.spyOn(proto, "datasync").mockImplementation(function (this: unknown) {
      order.push("datasync");
      return real.call(this);
    });
    const log = new ReceiptLog(path);
    const guarded = wrapAction(
      async () => {
        // the receipt is already on disk when the action starts
        const onDisk = await readFile(path, "utf8");
        order.push(onDisk.includes('"decision":"approve"') ? "action-saw-receipt" : "action-without-receipt");
        return "done";
      },
      fields,
      new FakeAdapter("approve"),
      { agent, authorityKey: authority, receiptLog: log },
    );
    expect(await guarded()).toBe("done");
    expect(order.indexOf("datasync")).toBeGreaterThanOrEqual(0);
    expect(order.at(-1)).toBe("action-saw-receipt");
    expect(order.indexOf("datasync")).toBeLessThan(order.indexOf("action-saw-receipt"));
  });

  it("fsync: false opts out of the flush (for tests and throwaway logs)", async () => {
    const proto = await fileHandleProto(join(dir, "probe"));
    const spy = vi.spyOn(proto, "datasync");
    const log = new ReceiptLog(path, { fsync: false });
    await log.record(approve(intent()));
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("A1 durability: a torn last line (crash mid-write) does not stop the log, with repairTornTail opted in", () => {
  /** One good entry, then the first bytes of a second, with no newline — what a crash mid-append leaves. */
  async function tornLog(): Promise<{ first: Intent; second: Intent; torn: string }> {
    const first = intent();
    const second = intent();
    await new ReceiptLog(path).record(approve(first));
    const full = (await readFile(path, "utf8")).trim();
    // A plausible torn tail: the start of a real next entry.
    const torn = `{"prev":"${"x".repeat(43)}","receipt":{"actor":"fake:approver","decision":"approve","intent_id":"${second.intent_id}","po`;
    await appendFile(path, torn);
    expect(full.length).toBeGreaterThan(0);
    return { first, second, torn };
  }

  it("the writer quarantines the torn tail before its next append; history() and record() keep working; verifyAll reports it", async () => {
    const { first, second, torn } = await tornLog();
    const log = new ReceiptLog(path, { repairTornTail: true });
    const h = await log.history(); // threw "corrupt at line 2" before the fix
    expect([...h.keys()]).toEqual([first.intent_id]);
    await expect(stat(log.quarantinePath)).rejects.toMatchObject({ code: "ENOENT" }); // a read never repairs (F1)
    await log.repair(); // the writer, explicitly

    // the bytes were moved aside into a clearly named quarantine file
    const q = await readFile(log.quarantinePath, "utf8");
    expect(log.quarantinePath).toBe(`${path}.quarantine.jsonl`);
    const rec = JSON.parse(q.trim().split("\n")[0]);
    expect(Buffer.from(rec.bytes_b64, "base64").toString("utf8")).toBe(torn);
    expect(rec).toMatchObject({ line: 1, intent_id: second.intent_id });
    // and the log itself now ends on a whole line
    expect((await readFile(path, "utf8")).endsWith("\n")).toBe(true);

    // appends continue, on an intact chain
    await log.record(approve(second));
    expect((await log.read()).map((c) => c.intent_id)).toEqual([first.intent_id, second.intent_id]);
    expect(await log.verifyChain()).toEqual({ intact: true, length: 2 });

    const report = await log.verifyAll();
    expect(report.chain.intact).toBe(true);
    expect(report.faults).toEqual([]);
    expect(report.tornTails).toEqual([{ index: 1, intent_id: second.intent_id, offset: expect.any(Number), length: torn.length, quarantined: true }]);
    expect(report.ok).toBe(false);
    expect(report.valid).toBe(2);
  });

  it("the same after a restart: a fresh instance still reports the quarantined tail and keeps appending", async () => {
    const { second } = await tornLog();
    await new ReceiptLog(path, { repairTornTail: true }).repair(); // first process: its writer repaired
    const restarted = new ReceiptLog(path, { repairTornTail: true });
    await restarted.record(approve(intent()));
    const report = await restarted.verifyAll();
    expect(report.faults).toEqual([]);
    expect(report.tornTails?.map((t) => [t.intent_id, t.quarantined])).toEqual([[second.intent_id, true]]);
    expect(report.chain).toEqual({ intact: true, length: 2 });
  });

  it("a torn tail found by the first record() (no read first) is repaired before the append", async () => {
    await tornLog();
    const log = new ReceiptLog(path, { repairTornTail: true });
    await log.record(approve(intent()));
    expect(await log.verifyChain()).toEqual({ intact: true, length: 2 });
  });

  it("repair() can be called explicitly; it reports what it moved and is a no-op on a clean log", async () => {
    const { second } = await tornLog();
    const log = new ReceiptLog(path);
    const r = await log.repair();
    expect(r).toMatchObject({ line: 1, intent_id: second.intent_id });
    expect(await log.repair()).toBeNull();
  });

  it("a whole last entry missing only its newline is kept (newline restored), not quarantined", async () => {
    const i = intent();
    await new ReceiptLog(path).record(approve(i));
    await writeFile(path, (await readFile(path, "utf8")).replace(/\n$/, ""));
    const log = new ReceiptLog(path, { repairTornTail: true });
    await log.record(approve(intent()));
    expect(await log.verifyChain()).toEqual({ intact: true, length: 2 });
    await expect(stat(log.quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await log.verifyAll()).toMatchObject({ faults: [], tornTails: [], ok: true });
  });

  it("a corrupt line in the MIDDLE is still a hard fault — nothing is moved aside", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    const good = (await readFile(path, "utf8")).split("\n")[0];
    await appendFile(path, "{ not json\n" + good + "\n");
    const log = new ReceiptLog(path);
    await expect(log.read()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.read()).rejects.toBeInstanceOf(CountersignError);
    await expect(log.record(approve(intent()))).rejects.toThrow(/corrupt at line 2/);
    await expect(stat(log.quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("repairTornTail: false keeps the old loud behaviour", async () => {
    await tornLog();
    const log = new ReceiptLog(path, { repairTornTail: false });
    await expect(log.read()).rejects.toThrow(/corrupt at line 2/);
  });
});

describe("A2: keeping each Intent beside its receipts", () => {
  it("verifyAll audits vouched receipts from the sidecar, without being handed the Intents", async () => {
    const log = new ReceiptLog(path, { intents: true });
    const guarded = wrapAction(async () => "done", fields, new FakeAdapter("approve"), { agent, authorityKey: authority, receiptLog: log });
    await guarded();
    await expect(guarded.call(null)).resolves.toBe("done");

    const report = await new ReceiptLog(path, { intents: true }).verifyAll({ authorityKey: authorityPub, trustedAgentKeys: [agent.keypair.publicKey] });
    expect(report).toMatchObject({ total: 2, valid: 2, ok: true, faults: [] });
  });

  it("without the sidecar the same audit is impossible, exactly as before", async () => {
    const log = new ReceiptLog(path);
    await wrapAction(async () => "done", fields, new FakeAdapter("approve"), { agent, authorityKey: authority, receiptLog: log })();
    await expect(log.verifyAll({ authorityKey: authorityPub })).rejects.toThrow(/without `intents`/);
    expect((await log.verifyAll()).ok).toBe(true);
    await expect(stat(`${path}.intents.jsonl`)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("the receipts file format is unchanged: lines are still {seq, prev, receipt}", async () => {
    const log = new ReceiptLog(path, { intents: true });
    const i = intent();
    await log.record(approve(i), i);
    const lines = (await readFile(path, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(lines).toHaveLength(1);
    expect(Object.keys(lines[0]).sort()).toEqual(["prev", "receipt", "seq"]);
    const stored = (await readFile(`${path}.intents.jsonl`, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(stored).toEqual([i]);
  });

  it("the Intent is stored before its receipts and only once", async () => {
    const log = new ReceiptLog(path, { intents: true });
    const i = intent();
    await log.rememberIntent(i);
    await log.record(approve(i), i);
    expect(await log.intentStore!.all()).toEqual([i]);
  });

  it("a tampered stored Intent faults its receipts as unverified-intent", async () => {
    const log = new ReceiptLog(path, { intents: true });
    const i = intent();
    await log.record(approve(i), i);
    const side = `${path}.intents.jsonl`;
    await writeFile(side, (await readFile(side, "utf8")).replace("Do the thing", "Do another thing"));
    const report = await new ReceiptLog(path, { intents: true }).verifyAll({ authorityKey: authorityPub });
    expect(report.faults.map((f) => f.reason)).toEqual(["unverified-intent"]);
  });

  it("FileIntentStore refuses to rebind an intent_id to different content", async () => {
    const store = new FileIntentStore(join(dir, "intents.jsonl"));
    const i = intent();
    await store.put(i);
    await store.put(i); // idempotent
    await expect(store.put({ ...i, summary: "something else" })).rejects.toThrow(/already stored with different content/);
    expect(await store.all()).toEqual([i]);
    expect(await new FileIntentStore(join(dir, "intents.jsonl")).get(i.intent_id)).toEqual(i);
  });

  it("caller-supplied intents still take precedence over the sidecar", async () => {
    const log = new ReceiptLog(path, { intents: true });
    const i = intent();
    const other = intent();
    await log.record(approve(i), i);
    const report = await log.verifyAll({ intents: [other], authorityKey: authorityPub });
    expect(report.faults.map((f) => f.reason)).toEqual(["unknown-intent"]);
  });
});

describe("N6: a default log whose last whole entry lost its newline (0.2.0 glued the next receipt onto it)", () => {
  it("the next append writes the missing newline first, so the log reads as two entries", async () => {
    const log = new ReceiptLog(path);
    const a = intent();
    const b = intent();
    await log.record(approve(a));
    const text = await readFile(path, "utf8");
    await writeFile(path, text.slice(0, -1)); // the whole entry, no newline
    await log.record(approve(b));
    const after = await readFile(path, "utf8");
    expect(after.startsWith(text)).toBe(true);
    expect(after.endsWith("\n")).toBe(true);
    expect(after.split("\n").filter(Boolean)).toHaveLength(2);
    const fresh = new ReceiptLog(path);
    expect((await fresh.read()).map((r) => r.intent_id)).toEqual([a.intent_id, b.intent_id]);
    expect(await fresh.verifyChain()).toEqual({ intact: true, length: 2 });
  });

  it("the same for a fresh instance (the head is recovered from the newline-less file)", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    await writeFile(path, (await readFile(path, "utf8")).slice(0, -1));
    await new ReceiptLog(path).record(approve(intent()));
    expect(await new ReceiptLog(path).verifyChain()).toEqual({ intact: true, length: 2 });
  });

  it("reading never adds the newline: a reader leaves the file byte for byte", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    const cut = (await readFile(path, "utf8")).slice(0, -1);
    await writeFile(path, cut);
    const reader = new ReceiptLog(path);
    await reader.read();
    await reader.history();
    await reader.head();
    await reader.verifyChain();
    await reader.verifyAll();
    expect(await readFile(path, "utf8")).toBe(cut);
  });

  it("a last segment that does not parse is left exactly as before: the append throws and nothing is written", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    const torn = (await readFile(path, "utf8")) + '{"seq":1,"prev":"x","rec';
    await writeFile(path, torn);
    await expect(new ReceiptLog(path).record(approve(intent()))).rejects.toThrow(/corrupt at line 2/);
    expect(await readFile(path, "utf8")).toBe(torn);
  });
});

describe("NF1: the lost newline is restored only after the head is read and only after this log's own last entry", () => {
  it("a failing append (a corrupt line earlier in the file) leaves the file byte for byte, newline-less tail and all", async () => {
    const log = new ReceiptLog(path);
    await log.record(approve(intent()));
    await log.record(approve(intent()));
    const [l1, l2] = (await readFile(path, "utf8")).split("\n");
    const damaged = `${l1}\ngarbage\n${l2}`; // a whole chain entry at the end, no newline
    await writeFile(path, damaged);
    await expect(new ReceiptLog(path).record(approve(intent()))).rejects.toThrow(/corrupt at line 2/);
    expect(await readFile(path, "utf8")).toBe(damaged);
  });

  it("a whole JSON object that is not a chain entry of this log gets no newline (the append behaves as in 0.2.0)", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    const before = (await readFile(path, "utf8")) + '{"x":1}';
    await writeFile(path, before);
    await new ReceiptLog(path).record(approve(intent()));
    const after = await readFile(path, "utf8");
    expect(after.startsWith(before)).toBe(true);
    expect(after.slice(before.length, before.length + 1)).toBe("{"); // nothing inserted
  });

  it("a chain entry whose seq is not this log's head gets no newline either", async () => {
    const log = new ReceiptLog(path);
    await log.record(approve(intent()));
    await log.record(approve(intent()));
    const [l1, l2] = (await readFile(path, "utf8")).split("\n");
    const wrong = `${l1}\n${l1}\n${l2}`; // l2 claims seq 1 but sits at index 2, no newline
    await writeFile(path, wrong);
    await new ReceiptLog(path).record(approve(intent()));
    const after = await readFile(path, "utf8");
    expect(after.startsWith(wrong)).toBe(true);
    expect(after.slice(wrong.length, wrong.length + 1)).toBe("{");
  });
});
