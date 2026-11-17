// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PendingDecisions, type Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { verifyResolution } from "../src/core/defaults.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Decision, Intent, Resolution } from "../src/core/types.js";
import { ReceiptLog, type ReceiptSink } from "../src/receipt-log.js";
import { DurableDecisions, FilePendingStore, type PendingStore } from "../src/resumable.js";
import { wrapAction } from "../src/shim.js";
import { DeliveryPartialError } from "../src/adapters/whatsapp.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const authorityPub = publicKeyFromSecret(authority);
const fields = { action: "post.linkedin", summary: "Post the weekly piece", risk_tier: "high" as const, approvers: ["manual:hari"], timeout: 60, default: "reject" as const };

/** A chat-like adapter: in-memory PendingDecisions (as every shipped adapter has), a button press via press(). */
class ManualAdapter implements Adapter {
  readonly channel = "manual";
  readonly authorityPublicKey = authorityPub;
  readonly pending = new PendingDecisions();
  readonly delivered: Intent[] = [];
  failDelivery = false;
  /** answer every Intent as soon as it is awaited (a person pressing the button) */
  autoAnswer?: Decision;
  async deliver(i: Intent): Promise<void> {
    if (this.failDelivery) throw new Error("chat unreachable");
    this.delivered.push(i);
  }
  awaitResolution(i: Intent): Promise<Resolution> {
    const p = this.pending.wait(i);
    const d = this.autoAnswer;
    if (d) queueMicrotask(() => this.press(i.intent_id, d));
    return p;
  }
  press(intentId: string, d: Decision, actor = "manual:hari") {
    return this.pending.settle(intentId, d, actor, authority);
  }
}

let dir: string;
let storePath: string;
let logPath: string;
const open: FilePendingStore[] = [];

/** One "process": its own store handle, adapter, log and DurableDecisions. */
async function boot(receiptLog?: ReceiptSink, store?: PendingStore) {
  const s = store ?? (await FilePendingStore.open(storePath));
  if (s instanceof FilePendingStore) open.push(s);
  const adapter = new ManualAdapter();
  const log = receiptLog ?? new ReceiptLog(logPath, { intents: true });
  const dd = new DurableDecisions({ adapter, store: s, receiptLog: log, authorityKey: authority });
  return { store: s, adapter, log, dd };
}
/** Simulate the process dying: drop the lock without deciding or cleaning up anything else. */
async function crash(store: PendingStore): Promise<void> {
  await (store as FilePendingStore).close();
}
async function logLines(): Promise<number> {
  try {
    return (await readFile(logPath, "utf8")).split("\n").filter(Boolean).length;
  } catch {
    return 0;
  }
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-durable-"));
  storePath = join(dir, "pending.jsonl");
  logPath = join(dir, "receipts.jsonl");
});
afterEach(async () => {
  vi.useRealTimers();
  for (const s of open.splice(0)) await s.close().catch(() => {});
  await rm(dir, { recursive: true, force: true });
});

describe("restart between issue and decision", () => {
  it("re-arms the Intent; the answer after the restart decides it exactly once", async () => {
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.dd.issue(i);
    expect(a.adapter.delivered).toHaveLength(1);
    await crash(a.store); // nobody answered before the process died

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([i.intent_id]);
    expect(report.lapsed).toEqual([]);
    expect(report.completed).toEqual([]);
    expect(b.adapter.delivered).toHaveLength(0); // already delivered before the crash; the old buttons work again
    expect(b.adapter.press(i.intent_id, "approve")?.status).toBe("resolved");
    const res = await report.rearmed[0].resolution;
    expect(res.decision).toBe("approve");
    verifyResolution(i, res, authorityPub);
    expect(b.adapter.press(i.intent_id, "reject")).toBeNull(); // a second answer cannot decide it again
    expect(await logLines()).toBe(1);
    expect(await b.store.get(i.intent_id)).toMatchObject({ status: "final", logged: true });
    await crash(b.store);

    // a third start finds nothing to do
    const c = await boot();
    const again = await c.dd.restore();
    expect(again).toMatchObject({ rearmed: [], lapsed: [], completed: [], redelivered: [] });
    expect(await logLines()).toBe(1);
    expect(await c.dd.decide(i)).toEqual(res); // asking again returns the one decision
  });

  it("an Intent stored but never delivered (crash before the chat message) is delivered at restart", async () => {
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.store.issue(i); // crash right after storing, before deliver()
    await crash(a.store);

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.redelivered.map((x) => x.intent_id)).toEqual([i.intent_id]);
    expect(b.adapter.delivered.map((x) => x.intent_id)).toEqual([i.intent_id]);
    expect(await b.store.get(i.intent_id)).toMatchObject({ delivered: true, status: "pending" });
    b.adapter.press(i.intent_id, "reject");
    expect((await report.rearmed[0].resolution).decision).toBe("reject");
  });

  it("a failed delivery is recorded as abandoned and never re-armed (no silent 72-hour Default)", async () => {
    const a = await boot();
    a.adapter.failDelivery = true;
    const i = createIntent(fields, agent);
    await expect(a.dd.issue(i)).rejects.toThrow(/chat unreachable/);
    expect(await a.store.get(i.intent_id)).toMatchObject({ status: "abandoned" });
    await crash(a.store);

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.abandoned.map((x) => x.intent_id)).toEqual([i.intent_id]);
    expect(report.rearmed).toEqual([]);
    expect(b.adapter.delivered).toHaveLength(0);
  });
});

describe("restart after the decision but before the log write", () => {
  it("finishes the stored decision at restart: logged once, never re-asked", async () => {
    const powerCut: ReceiptSink = { record: () => Promise.reject(new Error("power cut")) };
    const a = await boot(powerCut);
    const i = createIntent(fields, agent);
    await a.dd.issue(i);
    const deciding = a.dd.decide(i);
    a.adapter.press(i.intent_id, "approve");
    await expect(deciding).rejects.toThrow(/power cut/);
    expect(await a.store.get(i.intent_id)).toMatchObject({ status: "final", logged: false });
    await crash(a.store);

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.rearmed).toEqual([]);
    expect(report.completed.map((c) => [c.intent.intent_id, c.resolution.decision])).toEqual([[i.intent_id, "approve"]]);
    expect(b.adapter.delivered).toHaveLength(0);
    expect(b.adapter.press(i.intent_id, "reject")).toBeNull();
    expect(await logLines()).toBe(1);
    expect((await (b.log as ReceiptLog).verifyAll({ authorityKey: authorityPub })).ok).toBe(true);

    await crash(b.store);
    const c = await boot();
    expect((await c.dd.restore()).completed).toEqual([]);
    expect(await logLines()).toBe(1);
  });

  it("a crash after the log write but before the store noted it does not log twice", async () => {
    const real = await FilePendingStore.open(storePath);
    open.push(real);
    let failOnce = true;
    const flaky: PendingStore = {
      issue: (i) => real.issue(i),
      markDelivered: (id) => real.markDelivered(id),
      finalize: (i, r) => real.finalize(i, r),
      abandon: (id, why) => real.abandon(id, why),
      get: (id) => real.get(id),
      list: () => real.list(),
      markLogged: async (id: string) => {
        if (failOnce) {
          failOnce = false;
          throw new Error("power cut");
        }
        return real.markLogged(id);
      },
    };
    const a = await boot(undefined, flaky);
    const i = createIntent(fields, agent);
    await a.dd.issue(i);
    const deciding = a.dd.decide(i);
    a.adapter.press(i.intent_id, "approve");
    await expect(deciding).rejects.toThrow(/power cut/);
    expect(await logLines()).toBe(1);
    await crash(real);

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.completed.map((c) => c.intent.intent_id)).toEqual([i.intent_id]);
    expect(await logLines()).toBe(1);
    expect(await b.store.get(i.intent_id)).toMatchObject({ logged: true });
  });

  it("never decides an Intent the receipt log already holds a final receipt for, even if the store says pending", async () => {
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.dd.issue(i);
    // An older code path wrote the decision straight to the log.
    await (a.log as ReceiptLog).record({ decision: "reject", policy: "approver", countersignatures: [signDecision(i, "reject", "manual:hari", authority)] }, i);
    await crash(a.store);

    const b = await boot();
    const report = await b.dd.restore();
    expect(report.rearmed).toEqual([]);
    expect(report.completed.map((c) => c.resolution.decision)).toEqual(["reject"]);
    expect(await b.store.get(i.intent_id)).toMatchObject({ status: "final", logged: true });
    expect(await logLines()).toBe(1);
  });
});

describe("deadlines across a restart", () => {
  it("an Intent whose deadline passed while the process was down lapses to its signed Default", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.dd.issue(i);
    await crash(a.store);

    vi.setSystemTime(Date.now() + 120_000); // down for two minutes; the window was one
    const b = await boot();
    const report = await b.dd.restore();
    expect(report.rearmed).toEqual([]);
    expect(report.lapsed).toHaveLength(1);
    const res = report.lapsed[0].resolution;
    expect(res).toMatchObject({ decision: "reject", policy: "default" });
    verifyResolution(i, res, authorityPub);
    expect(b.adapter.press(i.intent_id, "approve")).toBeNull();
    expect(await logLines()).toBe(1);
    expect((await (b.log as ReceiptLog).verifyAll({ authorityKey: authorityPub })).ok).toBe(true);
  });

  it("a re-armed Intent keeps only its REMAINING time, not a fresh window", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const a = await boot();
    const i = createIntent(fields, agent); // 60 s window
    await a.dd.issue(i);
    await crash(a.store);

    vi.setSystemTime(Date.now() + 30_000); // down for 30 s
    const b = await boot();
    const report = await b.dd.restore();
    let settled: Resolution | undefined;
    void report.rearmed[0].resolution.then((r) => (settled = r));
    await vi.advanceTimersByTimeAsync(29_000);
    expect(settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1_500);
    const res = await report.rearmed[0].resolution;
    expect(res).toMatchObject({ decision: "reject", policy: "default" });
    expect(await logLines()).toBe(1);
  });
});

describe("one writer per store", () => {
  it("a second process cannot open the same store while the first holds it", async () => {
    const a = await FilePendingStore.open(storePath);
    open.push(a);
    await expect(FilePendingStore.open(storePath)).rejects.toThrow(/held by pid/);
    await a.close();
    const b = await FilePendingStore.open(storePath);
    open.push(b);
    expect(b).toBeInstanceOf(FilePendingStore);
  });

  it("takes over a stale lock left by a process that is gone", async () => {
    const gone = spawnSync(process.execPath, ["-e", ""]).pid;
    await writeFile(`${storePath}.lock`, JSON.stringify({ pid: gone, hostname: (await import("node:os")).hostname(), token: "old" }));
    const s = await FilePendingStore.open(storePath);
    open.push(s);
    expect(s).toBeInstanceOf(FilePendingStore);
  });

  it("finalize is first-wins: a second, different decision for the same Intent is not stored", async () => {
    const s = await FilePendingStore.open(storePath);
    open.push(s);
    const i = createIntent(fields, agent);
    await s.issue(i);
    const yes: Resolution = { decision: "approve", policy: "approver", countersignatures: [signDecision(i, "approve", "manual:hari", authority)] };
    const no: Resolution = { decision: "reject", policy: "approver", countersignatures: [signDecision(i, "reject", "manual:hari", authority)] };
    expect(await s.finalize(i, yes)).toEqual(yes);
    expect(await s.finalize(i, no)).toEqual(yes);
    await s.close();
    const s2 = await FilePendingStore.open(storePath);
    open.push(s2);
    expect((await s2.get(i.intent_id))?.resolution).toEqual(yes);
  });
});

describe("PendingDecisions with a PendingStore", () => {
  it("refuses to wait before restore(), so a decided Intent cannot be re-registered blind", async () => {
    const s = await FilePendingStore.open(storePath);
    open.push(s);
    const pd = new PendingDecisions({ store: s });
    await expect(pd.wait(createIntent(fields, agent))).rejects.toThrow(/restore\(\)/);
  });

  it("finality survives a restart: re-waiting a decided Intent returns its decision and a new answer is ignored", async () => {
    const s = await FilePendingStore.open(storePath);
    open.push(s);
    const pd = new PendingDecisions({ store: s });
    await pd.restore();
    const i = createIntent(fields, agent);
    const waiting = pd.wait(i);
    expect(pd.settle(i.intent_id, "approve", "manual:hari", authority)?.status).toBe("resolved");
    const res = await waiting;
    expect(await s.get(i.intent_id)).toMatchObject({ status: "final" });
    await s.close();

    const s2 = await FilePendingStore.open(storePath);
    open.push(s2);
    const pd2 = new PendingDecisions({ store: s2 });
    const unfinished = await pd2.restore();
    expect(unfinished).toEqual([]);
    expect(await pd2.wait(i)).toEqual(res);
    expect(pd2.settle(i.intent_id, "reject", "manual:hari", authority)).toBeNull();
  });

  it("restore() hands back the Intents still waiting, for the adapter owner to re-arm", async () => {
    const s = await FilePendingStore.open(storePath);
    open.push(s);
    const i = createIntent(fields, agent);
    await s.issue(i);
    const pd = new PendingDecisions({ store: s });
    expect((await pd.restore()).map((r) => r.intent.intent_id)).toEqual([i.intent_id]);
  });
});

describe("wrapAction durable mode (opt-in)", () => {
  it("stores the Intent before delivery, finalizes and logs before the action; a later restore has nothing to do", async () => {
    const store = await FilePendingStore.open(storePath);
    open.push(store);
    const adapter = new ManualAdapter();
    adapter.autoAnswer = "approve";
    const log = new ReceiptLog(logPath, { intents: true });
    const seen: string[] = [];
    const guarded = wrapAction(
      async () => {
        const rec = await store.list();
        seen.push(`${rec[0].status}/${rec[0].logged}/${await logLines()}`);
        return "posted";
      },
      fields,
      adapter,
      { agent, authorityKey: authority, receiptLog: log, pendingStore: store },
    );
    expect(await guarded()).toBe("posted");
    expect(seen).toEqual(["final/true/1"]);
    const report = await new DurableDecisions({ adapter: new ManualAdapter(), store, receiptLog: log, authorityKey: authority }).restore();
    expect(report).toMatchObject({ rearmed: [], lapsed: [], completed: [] });
  });
});

describe("F8: a delivery that reached some approvers but not all (DeliveryPartialError)", () => {
  const two = { ...fields, approvers: ["manual:hari", "manual:ann"] };
  function partly(adapter: ManualAdapter) {
    adapter.deliver = async (x: Intent) => {
      adapter.delivered.push(x);
      throw new DeliveryPartialError(x.intent_id, ["manual:hari"], ["manual:ann"], new Error("rate limited"));
    };
  }

  it("keeps the Intent pending and delivered; the reached approver's press decides it; the unreached are on the result and the record", async () => {
    const a = await boot();
    partly(a.adapter);
    const i = createIntent(two, agent);
    const rec = await a.dd.issue(i);
    expect(rec).toMatchObject({ status: "pending", delivered: true, unreached: ["manual:ann"] });
    expect(await a.store.get(i.intent_id)).toMatchObject({ status: "pending", delivered: true, unreached: ["manual:ann"] });
    a.adapter.press(i.intent_id, "approve", "manual:hari");
    const res = await a.dd.decide(i);
    expect(res.decision).toBe("approve");
    expect(res.countersignatures.map((c) => c.actor)).toEqual(["manual:hari"]);
    expect(await logLines()).toBe(1);
  });

  it("the unreached list survives a restart, and the default restore does not deliver again to those reached", async () => {
    const a = await boot();
    partly(a.adapter);
    const i = createIntent(two, agent);
    await a.dd.issue(i);
    await crash(a.store);
    const b = await boot();
    expect(await b.store.get(i.intent_id)).toMatchObject({ status: "pending", delivered: true, unreached: ["manual:ann"] });
    const report = await b.dd.restore();
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([i.intent_id]);
    expect(report.redelivered).toEqual([]);
    expect(b.adapter.delivered).toHaveLength(0);
  });

  it("a later full delivery (restore with redeliver: \"all\") clears the unreached list", async () => {
    const a = await boot();
    partly(a.adapter);
    const i = createIntent(two, agent);
    await a.dd.issue(i);
    await crash(a.store);
    const b = await boot();
    const report = await b.dd.restore({ redeliver: "all" });
    expect(report.redelivered.map((x) => x.intent_id)).toEqual([i.intent_id]);
    const rec = await b.store.get(i.intent_id);
    expect(rec).toMatchObject({ status: "pending", delivered: true });
    expect(rec?.unreached).toBeUndefined();
  });

  it("a delivery that reached nobody is still abandoned and rethrown, as before", async () => {
    const a = await boot();
    a.adapter.failDelivery = true;
    const i = createIntent(two, agent);
    await expect(a.dd.issue(i)).rejects.toThrow(/chat unreachable/);
    expect(await a.store.get(i.intent_id)).toMatchObject({ status: "abandoned" });
  });
});

describe("NF4: a failed re-delivery of an Intent that already reached people", () => {
  it("keeps it pending (their buttons still count) and reports the failure in redeliveryFailed", async () => {
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.dd.issue(i); // delivered: manual:hari holds a live button
    await crash(a.store);
    const b = await boot();
    b.adapter.failDelivery = true;
    const report = await b.dd.restore({ redeliver: "all" });
    expect(report.abandoned).toEqual([]);
    expect(report.redelivered).toEqual([]);
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([i.intent_id]);
    expect(report.redeliveryFailed.map((f) => f.intent.intent_id)).toEqual([i.intent_id]);
    expect(report.redeliveryFailed[0].error.message).toMatch(/chat unreachable/);
    expect(await b.store.get(i.intent_id)).toMatchObject({ status: "pending", delivered: true });
    b.adapter.press(i.intent_id, "approve");
    const res = await report.rearmed[0].resolution;
    expect(res.decision).toBe("approve");
    expect(await logLines()).toBe(1);
  });

  it("an Intent that never reached anyone is still abandoned when its re-delivery fails", async () => {
    const a = await boot();
    const i = createIntent(fields, agent);
    await a.store.issue(i); // stored, crash before delivery
    await crash(a.store);
    const b = await boot();
    b.adapter.failDelivery = true;
    const report = await b.dd.restore();
    expect(report.abandoned.map((x) => x.intent_id)).toEqual([i.intent_id]);
    expect(report.rearmed).toEqual([]);
    expect(report.redeliveryFailed).toEqual([]);
    expect(await b.store.get(i.intent_id)).toMatchObject({ status: "abandoned" });
  });
});

describe("NF3: wrapAction with a pendingStore hands the issued record to onDelivered", () => {
  const two = { ...fields, approvers: ["manual:hari", "manual:ann"] };

  it("on a partial delivery the caller learns who was not reached; the reached approver's press runs the action", async () => {
    const { store, adapter, log } = await boot();
    adapter.deliver = async (x: Intent) => {
      adapter.delivered.push(x);
      throw new DeliveryPartialError(x.intent_id, ["manual:hari"], ["manual:ann"], new Error("rate limited"));
    };
    adapter.autoAnswer = "approve";
    const seen: unknown[] = [];
    const guarded = wrapAction(async () => "posted", two, adapter, {
      agent,
      authorityKey: authority,
      receiptLog: log,
      pendingStore: store,
      onDelivered: (rec) => seen.push({ status: rec.status, delivered: rec.delivered, unreached: rec.unreached }),
    });
    expect(await guarded()).toBe("posted");
    expect(seen).toEqual([{ status: "pending", delivered: true, unreached: ["manual:ann"] }]);
  });

  it("on a full delivery it is called once with no unreached list", async () => {
    const { store, adapter, log } = await boot();
    adapter.autoAnswer = "approve";
    const seen: Array<readonly string[] | undefined> = [];
    const guarded = wrapAction(async () => "posted", fields, adapter, {
      agent,
      authorityKey: authority,
      receiptLog: log,
      pendingStore: store,
      onDelivered: (rec) => seen.push(rec.unreached),
    });
    expect(await guarded()).toBe("posted");
    expect(seen).toEqual([undefined]);
  });
});
