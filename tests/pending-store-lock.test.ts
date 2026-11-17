// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

// FilePendingStore's lock and DurableDecisions.restore(). Review findings F4 (a
// stale lock whose pid is ours, or any live pid, was never taken over), F5
// (taking over a stale lock was check-then-act: two processes could both hold
// it) and F9 (restore() used the stored deadline, and one bad record aborted it).

import { mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PendingDecisions, type Adapter } from "../src/adapter.js";
import { signDecision } from "../src/core/countersignature.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair, publicKeyFromSecret } from "../src/core/keys.js";
import type { Decision, Intent, Resolution } from "../src/core/types.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { DurableDecisions, FilePendingStore, type LockStep } from "../src/resumable.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const authorityPub = publicKeyFromSecret(authority);
const fields = { action: "post.linkedin", summary: "Post the weekly piece", risk_tier: "high" as const, approvers: ["manual:hari"], timeout: 60, default: "reject" as const };

class ManualAdapter implements Adapter {
  readonly channel = "manual";
  readonly authorityPublicKey = authorityPub;
  readonly pending = new PendingDecisions();
  async deliver(): Promise<void> {}
  awaitResolution(i: Intent): Promise<Resolution> {
    return this.pending.wait(i);
  }
  press(intentId: string, d: Decision) {
    return this.pending.settle(intentId, d, "manual:hari", authority);
  }
}

let dir: string;
let storePath: string;
let lockPath: string;
const opened: FilePendingStore[] = [];
async function track(p: Promise<FilePendingStore>): Promise<FilePendingStore> {
  const s = await p;
  opened.push(s);
  return s;
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-lock-"));
  storePath = join(dir, "pending.jsonl");
  lockPath = `${storePath}.lock`;
});
afterEach(async () => {
  for (const s of opened.splice(0)) await s.close().catch(() => {});
  await rm(dir, { recursive: true, force: true });
});

async function staleLock(body: Record<string, unknown>, ageMs = 0): Promise<string> {
  const text = JSON.stringify(body);
  await writeFile(lockPath, text);
  if (ageMs) {
    const t = new Date(Date.now() - ageMs);
    await utimes(lockPath, t, t);
  }
  return text;
}

/** When this process started, as resumable.ts computes it (epoch ms). */
const processStarted = (): number => Math.floor(Date.now() - process.uptime() * 1000);
/** An age (ms) that puts a lock's last heartbeat a minute before this process started: a crashed earlier run. */
const beforeThisProcess = (): number => Date.now() - processStarted() + 60_000;

describe("F4: a stale lock is taken over even when its pid is alive", () => {
  it("a lock left by an earlier run with THIS process's pid (a container restart as pid 1) is taken over", async () => {
    await staleLock({ pid: process.pid, hostname: hostname(), token: "old-run", started: 1, at: "2026-01-01T00:00:00Z" }, beforeThisProcess());
    const s = await track(FilePendingStore.open(storePath));
    expect(JSON.parse(await readFile(lockPath, "utf8"))).toMatchObject({ pid: process.pid, hostname: hostname() });
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).not.toBe("old-run");
    expect(s).toBeInstanceOf(FilePendingStore);
  });

  it("a lock naming another LIVE pid on this host whose heartbeat is older than the lease is taken over", async () => {
    await staleLock({ pid: process.ppid, hostname: hostname(), token: "old-run", started: 1 }, 60_000);
    const s = await track(FilePendingStore.open(storePath, { lockLeaseMs: 5_000 }));
    expect(s).toBeInstanceOf(FilePendingStore);
  });

  it("a lock naming another live pid with a fresh heartbeat is still refused", async () => {
    await staleLock({ pid: process.ppid, hostname: hostname(), token: "someone-else", started: 1 });
    await expect(FilePendingStore.open(storePath, { lockLeaseMs: 5_000 })).rejects.toThrow(/held by pid/);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).toBe("someone-else");
  });

  it("a lock from another host is never taken over, however old", async () => {
    await staleLock({ pid: 4242, hostname: "some-other-host", token: "elsewhere", started: 1 }, 3_600_000);
    await expect(FilePendingStore.open(storePath, { lockLeaseMs: 5_000 })).rejects.toThrow(/held by pid 4242 on some-other-host/);
  });

  it("the holder keeps its lock fresh with a heartbeat, and records pid, token and start time", async () => {
    const s = await track(FilePendingStore.open(storePath, { lockLeaseMs: 300 }));
    const body = JSON.parse(await readFile(lockPath, "utf8"));
    expect(body).toMatchObject({ pid: process.pid, hostname: hostname(), token: expect.any(String), started: expect.any(Number) });
    const old = new Date(Date.now() - 60_000);
    await utimes(lockPath, old, old);
    await new Promise((r) => setTimeout(r, 250)); // a few heartbeats
    const { mtimeMs } = await (await import("node:fs/promises")).stat(lockPath);
    expect(Date.now() - mtimeMs).toBeLessThan(300);
    // and a second handle in this process is refused: that token is held here
    await expect(FilePendingStore.open(storePath, { lockLeaseMs: 300 })).rejects.toThrow(/held by pid/);
    await s.close();
  });

  it("a store whose lock was taken from it stops writing (fail closed)", async () => {
    const s = await track(FilePendingStore.open(storePath));
    await writeFile(lockPath, JSON.stringify({ pid: process.ppid, hostname: hostname(), token: "thief", started: 1 }));
    await expect(s.issue(createIntent(fields, agent))).rejects.toThrow(/lost its lock/);
  });
});

describe("F5: taking over a stale lock is atomic: two openers, exactly one wins", () => {
  /** Two stores race on one stale lock: `a` is parked at `at` while `b` runs start to finish, then `a` resumes. */
  async function race(at: LockStep): Promise<PromiseSettledResult<FilePendingStore>[]> {
    await staleLock({ pid: process.pid, hostname: hostname(), token: "crashed-run", started: 1 }, beforeThisProcess());
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let reached!: () => void;
    const atStep = new Promise<void>((r) => (reached = r));
    const a = FilePendingStore.open(storePath, {
      lockSteps: async (step: LockStep) => {
        if (step === at) {
          reached();
          await gate;
        }
      },
    });
    await Promise.race([atStep, new Promise((r) => setTimeout(r, 500))]);
    const b = FilePendingStore.open(storePath);
    await b.then(
      () => undefined,
      () => undefined,
    );
    release();
    const results = await Promise.allSettled([a, b]);
    for (const r of results) if (r.status === "fulfilled") opened.push(r.value);
    return results;
  }

  for (const at of ["judged-stale", "renamed"] as const) {
    it(`one opener paused after "${at}" while the other takes the lock: exactly one holds it`, async () => {
      const results = await race(at);
      const winners = results.filter((r) => r.status === "fulfilled") as PromiseFulfilledResult<FilePendingStore>[];
      const losers = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
      expect(winners).toHaveLength(1);
      expect(String(losers[0].reason)).toMatch(/held by pid|could not take the lock/);
      // the lock on disk is the winner's, and nothing was left lying around
      const onDisk = JSON.parse(await readFile(lockPath, "utf8"));
      expect(onDisk.token).toBe((winners[0].value as unknown as { lockToken: string }).lockToken);
      expect((await readdir(dir)).filter((f) => f.includes(".lock."))).toEqual([]);
      // the winner can write; the loser never got a handle to write with
      await winners[0].value.issue(createIntent(fields, agent));
    });
  }
});

describe("F9: restore() uses the Intent's own deadline, and one bad record does not stop the others", () => {
  it("a record whose stored deadline disagrees with the Intent's is re-armed by the Intent's deadline (no 'cannot fire early')", async () => {
    const i = createIntent(fields, agent);
    const s1 = await FilePendingStore.open(storePath);
    await s1.issue(i);
    await s1.close();
    // An older or edited file: the stored deadline says the window closed long ago.
    const text = await readFile(storePath, "utf8");
    await writeFile(storePath, text.replace(/"deadline":\d+/, '"deadline":1'));

    const store = await track(FilePendingStore.open(storePath));
    const adapter = new ManualAdapter();
    const dd = new DurableDecisions({ adapter, store, receiptLog: new ReceiptLog(join(dir, "r.jsonl")), authorityKey: authority });
    const report = await dd.restore();
    expect(report.lapsed).toEqual([]);
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([i.intent_id]);
    expect(report.failed).toEqual([]);
    adapter.press(i.intent_id, "approve");
    expect((await report.rearmed[0].resolution).decision).toBe("approve");
  });

  it("a record that cannot be restored is reported in `failed`; the records after it are still restored", async () => {
    const bad = createIntent(fields, agent);
    const good = createIntent(fields, agent);
    const s1 = await FilePendingStore.open(storePath);
    await s1.issue(bad);
    await s1.finalize(bad, { decision: "approve", policy: "approver", countersignatures: [signDecision(bad, "approve", "manual:hari", authority)] });
    await s1.issue(good);
    await s1.close();
    // Someone edited the stored decision: its signature no longer verifies.
    const lines = (await readFile(storePath, "utf8")).split("\n");
    const at = lines.findIndex((l) => l.includes('"ev":"final"'));
    const ev = JSON.parse(lines[at]);
    const sig: string = ev.resolution.countersignatures[0].signature;
    ev.resolution.countersignatures[0].signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    lines[at] = JSON.stringify(ev);
    await writeFile(storePath, lines.join("\n"));

    const store = await track(FilePendingStore.open(storePath));
    const adapter = new ManualAdapter();
    const dd = new DurableDecisions({ adapter, store, receiptLog: new ReceiptLog(join(dir, "r.jsonl")), authorityKey: authority });
    const report = await dd.restore();
    expect(report.failed.map((f) => f.intent.intent_id)).toEqual([bad.intent_id]);
    expect(report.failed[0].error).toBeInstanceOf(Error);
    expect(report.completed).toEqual([]);
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([good.intent_id]);
  });
});

describe("adapter plumbing: an adapter can be given its PendingDecisions from outside", () => {
  it("pendingDecisionsFor: the given one, one over a given store, or (default) a new in-memory one", async () => {
    const { pendingDecisionsFor } = await import("../src/adapter.js");
    const mine = new PendingDecisions();
    expect(pendingDecisionsFor({ pending: mine })).toBe(mine);
    const fresh = pendingDecisionsFor();
    expect(fresh).toBeInstanceOf(PendingDecisions);
    expect(fresh).not.toBe(pendingDecisionsFor({}));
    // the default is in memory: waits work at once, no restore() needed
    const i = createIntent(fields, agent);
    const w = fresh.wait(i);
    fresh.settle(i.intent_id, "approve", "manual:hari", authority);
    expect((await w).decision).toBe("approve");

    const store = await track(FilePendingStore.open(storePath));
    const durable = pendingDecisionsFor({ pendingStore: store });
    await expect(durable.wait(createIntent(fields, agent))).rejects.toThrow(/restore\(\)/);
    await durable.restore();
    const j = createIntent(fields, agent);
    const wj = durable.wait(j);
    durable.settle(j.intent_id, "reject", "manual:hari", authority);
    await wj;
    expect(await store.get(j.intent_id)).toMatchObject({ status: "final" });
    expect(() => pendingDecisionsFor({ pending: mine, pendingStore: store })).toThrow(/not both/);
  });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("N1: a LIVE lock naming this process's pid (a twin container sharing hostname and pid 1) is never taken", () => {
  it("crash-restart as the same pid: a lock last heartbeated before this process started is taken over at once", async () => {
    await staleLock({ pid: process.pid, hostname: hostname(), token: "crashed", started: 1 }, beforeThisProcess());
    const t0 = Date.now();
    await track(FilePendingStore.open(storePath));
    expect(Date.now() - t0).toBeLessThan(1_000);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).not.toBe("crashed");
  });

  it("a live twin: same pid and host, heartbeat after this process started, is refused and its lock left in place", async () => {
    await staleLock({ pid: process.pid, hostname: hostname(), token: "twin", started: processStarted() });
    await expect(FilePendingStore.open(storePath)).rejects.toThrow(/held by pid/);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).toBe("twin");
  });

  it("a twin whose last heartbeat came just before this process started is refused once it heartbeats again", async () => {
    const age = Date.now() - processStarted() + 50; // last heartbeat 50 ms before this process started
    const lockLeaseMs = Math.ceil((age + 400) * 1.5); // two heartbeat intervals = age + 400 ms
    await staleLock({ pid: process.pid, hostname: hostname(), token: "twin", started: 1 }, age);
    const opening = FilePendingStore.open(storePath, { lockLeaseMs });
    await sleep(100);
    const now = new Date();
    await utimes(lockPath, now, now); // the twin's heartbeat
    await expect(opening).rejects.toThrow(/held by pid/);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).toBe("twin");
  });

  it("... and taken once two heartbeat intervals pass with no heartbeat (that earlier run is gone)", async () => {
    const age = Date.now() - processStarted() + 50;
    const lockLeaseMs = Math.ceil((age + 300) * 1.5);
    await staleLock({ pid: process.pid, hostname: hostname(), token: "crashed", started: 1 }, age);
    await track(FilePendingStore.open(storePath, { lockLeaseMs }));
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).not.toBe("crashed");
  });

  it("a takeover between the lock check and the append: the call rejects and the event is not applied", async () => {
    const s = await track(FilePendingStore.open(storePath));
    const inner = s as unknown as { checkLock: (touch?: boolean) => Promise<boolean> };
    const real = inner.checkLock.bind(s);
    let stolen = false;
    inner.checkLock = async (touch?: boolean) => {
      const ok = await real(touch);
      if (ok && !stolen) {
        // another process takes the lock right after this handle's check, before its append
        stolen = true;
        await writeFile(lockPath, JSON.stringify({ pid: process.ppid, hostname: hostname(), token: "thief", started: 1 }));
      }
      return ok;
    };
    const i = createIntent(fields, agent);
    await expect(s.issue(i)).rejects.toThrow(/lost its lock/);
    await expect(s.get(i.intent_id)).rejects.toThrow(/lost its lock/);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).toBe("thief");
  });

  it("the holder notices an append it did not make (a late write from a handle that lost the lock) and stops writing", async () => {
    const s = await track(FilePendingStore.open(storePath));
    const a = createIntent(fields, agent);
    await s.issue(a);
    const late = JSON.stringify({ ev: "abandoned", intent_id: a.intent_id, reason: "late write" }) + "\n";
    await writeFile(storePath, (await readFile(storePath, "utf8")) + late);
    const before = await readFile(storePath, "utf8");
    await expect(s.issue(createIntent(fields, agent))).rejects.toThrow(/another writer/);
    expect(await readFile(storePath, "utf8")).toBe(before);
    await expect(s.markDelivered(a.intent_id)).rejects.toThrow(/no longer writes/);
  });
});

describe("N4: two openers that both lose a takeover round retry instead of both failing", () => {
  it("an opener whose fresh lock was moved aside by a slower taker backs off and gets it once it is put back", async () => {
    await staleLock({ pid: process.pid, hostname: hostname(), token: "crashed-run", started: 1 }, beforeThisProcess());
    const gate = () => {
      let open!: () => void;
      const p = new Promise<void>((r) => (open = r));
      return { p, open };
    };
    const aJudged = gate(), aGo1 = gate(), aRenamed = gate(), aGo2 = gate();
    const bCreated = gate(), bGo1 = gate(), bBackoff = gate(), bGo2 = gate();
    let aStepJudged = 0;
    const a = FilePendingStore.open(storePath, {
      lockSteps: async (step: LockStep) => {
        if (step === "judged-stale" && aStepJudged++ === 0) {
          aJudged.open();
          await aGo1.p;
        } else if (step === "renamed") {
          aRenamed.open();
          await aGo2.p;
        }
      },
    });
    await aJudged.p; // a judged the crashed lock stale and is about to move it aside
    let bCreatedOnce = false;
    const b = FilePendingStore.open(storePath, {
      lockSteps: async (step: LockStep) => {
        if (step === "created" && !bCreatedOnce) {
          bCreatedOnce = true;
          bCreated.open();
          await bGo1.p;
        } else if (step === "backoff") {
          bBackoff.open();
          await bGo2.p;
        }
      },
    });
    await bCreated.p; // b took over and created its lock, not yet re-read
    aGo1.open();
    await aRenamed.p; // a moved b's fresh lock aside
    bGo1.open();
    const bSettled = b.then(() => "ok", (e) => `rejected: ${String(e)}`);
    expect(await Promise.race([bBackoff.p.then(() => "backoff"), bSettled])).toBe("backoff");
    aGo2.open(); // a puts b's lock back, then finds it held by b
    const aResult = await a.then(() => "ok", (e) => String(e));
    expect(aResult).toMatch(/held by pid/);
    bGo2.open();
    const store = await b;
    opened.push(store);
    expect(JSON.parse(await readFile(lockPath, "utf8")).token).toBe((store as unknown as { lockToken: string }).lockToken);
    expect((await readdir(dir)).filter((f) => f.includes(".lock."))).toEqual([]);
    await store.issue(createIntent(fields, agent));
  });
});

describe("N2: restore() never re-arms or re-delivers an Intent that no longer verifies", () => {
  class CountingAdapter extends ManualAdapter {
    readonly delivered: string[] = [];
    override async deliver(i?: Intent): Promise<void> {
      if (i) this.delivered.push(i.intent_id);
    }
  }

  it("a pending record whose stored Intent was edited goes to `failed`; nobody is shown the edited text", async () => {
    const forged = createIntent(fields, agent);
    const good = createIntent({ ...fields, summary: "Post the other piece" }, agent);
    const s1 = await FilePendingStore.open(storePath);
    await s1.issue(forged);
    await s1.issue(good);
    await s1.close();
    const text = await readFile(storePath, "utf8");
    const lines = text.split("\n");
    const at = lines.findIndex((l) => l.includes(forged.intent_id));
    lines[at] = lines[at].replace("Post the weekly piece", "Wire $1M to account 42");
    await writeFile(storePath, lines.join("\n"));

    const store = await track(FilePendingStore.open(storePath));
    const adapter = new CountingAdapter();
    const dd = new DurableDecisions({ adapter, store, receiptLog: new ReceiptLog(join(dir, "r.jsonl")), authorityKey: authority });
    const report = await dd.restore({ redeliver: "all" });
    expect(report.failed.map((f) => f.intent.intent_id)).toEqual([forged.intent_id]);
    expect(String(report.failed[0].error)).toMatch(/agent signature/);
    expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([good.intent_id]);
    expect(report.redelivered.map((i) => i.intent_id)).toEqual([good.intent_id]);
    expect(adapter.delivered).toEqual([good.intent_id]);
    expect(await store.get(forged.intent_id)).toMatchObject({ status: "pending" }); // left as it is
  });
});
