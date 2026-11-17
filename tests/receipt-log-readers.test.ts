// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

// A reader never writes, and nothing changes for a user who opts into nothing.
// Review findings F1 (an auditor instance cut off a receipt the writer had just
// been told was safe), F2 (default behaviour and the ReceiptFault union changed)
// and F6 (a tail torn after open was dropped silently).

import { appendFile, mkdtemp, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { signDecision } from "../src/core/countersignature.js";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Intent, Resolution } from "../src/core/types.js";
import { ReceiptLog, type ReceiptFault, type ReceiptLogReport } from "../src/receipt-log.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair().secretKey;
const fields = { action: "demo.op", summary: "Do the thing", risk_tier: "high" as const, approvers: ["fake:approver"], timeout: 300, default: "reject" as const };

function intent(): Intent {
  return createIntent(fields, agent);
}
function approve(i: Intent): Resolution {
  return { decision: "approve", policy: "approver", countersignatures: [signDecision(i, "approve", "fake:approver", authority)] };
}

/** The prototype every fs/promises FileHandle shares, to hold a write half-way. */
async function fileHandleProto(path: string): Promise<{ writeFile: (data: string, enc?: BufferEncoding) => Promise<void> }> {
  const fh = await open(path, "w");
  const proto = Object.getPrototypeOf(fh);
  await fh.close();
  return proto;
}

/** Everything a read-only audit must leave exactly as it found it. */
async function snapshot(p: string): Promise<{ bytes: string; mtimeMs: number; quarantine: boolean }> {
  const bytes = (await readFile(p)).toString("base64");
  const { mtimeMs } = await stat(p);
  const quarantine = await stat(`${p}.quarantine.jsonl`).then(
    () => true,
    () => false,
  );
  return { bytes, mtimeMs, quarantine };
}

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-log-readers-"));
  path = join(dir, "receipts.jsonl");
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

/** One good entry, then the first bytes of a second with no newline: what a crash mid-append leaves. */
async function tornLog(): Promise<{ first: Intent; second: Intent }> {
  const first = intent();
  const second = intent();
  await new ReceiptLog(path).record(approve(first));
  await appendFile(path, `{"prev":"${"x".repeat(43)}","receipt":{"actor":"fake:approver","decision":"approve","intent_id":"${second.intent_id}","po`);
  return { first, second };
}

describe("F1: a reader never writes", () => {
  it("an auditor verifying while the writer's append is in flight changes nothing, and the writer's receipt survives", async () => {
    const writer = new ReceiptLog(path, { repairTornTail: true });
    const first = intent();
    await writer.record(approve(first));

    // Hold the writer's next append half-way: the first 40 bytes are on disk, the rest waits.
    const proto = await fileHandleProto(join(dir, "probe"));
    const realWrite = proto.writeFile;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let halfWritten!: () => void;
    const half = new Promise<void>((r) => (halfWritten = r));
    vi.spyOn(proto, "writeFile").mockImplementation(async function (this: unknown, data: string, enc?: BufferEncoding) {
      if (typeof data === "string" && data.length > 40 && data.includes('"receipt"')) {
        await realWrite.call(this, data.slice(0, 40), enc);
        halfWritten();
        await gate;
        return realWrite.call(this, data.slice(40), enc);
      }
      return realWrite.call(this, data, enc);
    });

    const second = intent();
    const recorded = writer.record(approve(second));
    await half;

    // Two auditors look while the line is half on disk: one opted into the repair, one into nothing.
    const before = await snapshot(path);
    const auditor = new ReceiptLog(path, { repairTornTail: true });
    const report = await auditor.verifyAll();
    await auditor.read();
    await auditor.history();
    await auditor.head();
    await auditor.verifyChain();
    await expect(new ReceiptLog(path).verifyAll()).rejects.toThrow(/corrupt at line 2/); // 0.2.0, unchanged
    expect(await snapshot(path)).toEqual(before);

    // The auditor reports what it saw, as a torn tail still in the file, not quarantined.
    expect(report.ok).toBe(false);
    expect(report.total).toBe(1);
    expect(report.faults).toEqual([]);
    expect(report.tornTails).toEqual([{ index: 1, intent_id: "", offset: expect.any(Number), length: 40, quarantined: false }]);

    // The writer's write completes and record() resolves: that receipt is on disk, whole.
    release();
    await recorded;
    vi.restoreAllMocks();
    const after = new ReceiptLog(path, { repairTornTail: true });
    expect((await after.read()).map((c) => c.intent_id)).toEqual([first.intent_id, second.intent_id]);
    expect(await after.verifyAll()).toMatchObject({ total: 2, valid: 2, ok: true, faults: [], tornTails: [] });
    expect(await new ReceiptLog(path).verifyChain()).toEqual({ intact: true, length: 2 });
  });

  it("a reader with the repair opted in leaves a crash's torn tail where it is, and reports it", async () => {
    const { first, second } = await tornLog();
    const before = await snapshot(path);
    const reader = new ReceiptLog(path, { repairTornTail: true });
    expect((await reader.read()).map((c) => c.intent_id)).toEqual([first.intent_id]);
    expect([...(await reader.history()).keys()]).toEqual([first.intent_id]);
    expect((await reader.head()).length).toBe(1);
    expect(await reader.verifyChain()).toEqual({ intact: true, length: 1 });
    const report = await reader.verifyAll();
    expect(await snapshot(path)).toEqual(before);
    expect(report).toMatchObject({ total: 1, valid: 1, faults: [], ok: false });
    expect(report.tornTails).toEqual([{ index: 1, intent_id: second.intent_id, offset: expect.any(Number), length: expect.any(Number), quarantined: false }]);
  });

  it("the instance that appends repairs, on its write path; then every reader sees it as quarantined", async () => {
    const { second } = await tornLog();
    const writer = new ReceiptLog(path, { repairTornTail: true });
    await writer.read(); // a read first: still nothing moved
    await expect(stat(writer.quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
    await writer.record(approve(intent()));
    expect((await readFile(writer.quarantinePath, "utf8")).trim().split("\n")).toHaveLength(1);
    const report = await new ReceiptLog(path, { repairTornTail: true }).verifyAll();
    expect(report.chain).toEqual({ intact: true, length: 2 });
    expect(report.tornTails).toEqual([{ index: 1, intent_id: second.intent_id, offset: expect.any(Number), length: expect.any(Number), quarantined: true }]);
    expect(report.ok).toBe(false);
  });

  it("repair() still repairs when called explicitly", async () => {
    const { second } = await tornLog();
    const log = new ReceiptLog(path);
    expect(await log.repair()).toMatchObject({ line: 1, intent_id: second.intent_id });
    expect(await log.repair()).toBeNull();
    expect(await log.verifyChain()).toEqual({ intact: true, length: 1 });
  });
});

describe("F2: nothing changes for a user who opts into nothing", () => {
  it("new ReceiptLog(path) on a torn log throws as in 0.2.0 and leaves the file and the directory as they were", async () => {
    await tornLog();
    const before = await snapshot(path);
    const log = new ReceiptLog(path);
    await expect(log.read()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.history()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.head()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.verifyAll()).rejects.toThrow(/corrupt at line 2/);
    await expect(log.record(approve(intent()))).rejects.toThrow(/corrupt at line 2/);
    expect(await snapshot(path)).toEqual(before);
  });

  it("a clean log's report has exactly the 0.2.0 keys", async () => {
    await new ReceiptLog(path).record(approve(intent()));
    const report = await new ReceiptLog(path).verifyAll();
    expect(Object.keys(report).sort()).toEqual(["chain", "faults", "ok", "total", "valid"]);
  });

  it("the ReceiptFault reason union is the 0.2.0 union: an exhaustive switch still compiles and covers it", () => {
    // Type-level: if a reason is added, `never` below stops type-checking (vitest runs it through esbuild,
    // so the check is kept honest by tsc on this file in the test run below).
    const label = (r: ReceiptFault["reason"]): string => {
      switch (r) {
        case "invalid-signature":
        case "untrusted-key":
        case "unknown-intent":
        case "unverified-intent":
        case "missing-webauthn-policy":
        case "missing-authority-key":
        case "malformed":
          return r;
        default: {
          const unreachable: never = r;
          return unreachable;
        }
      }
    };
    expect(label("malformed")).toBe("malformed");
    const r: Pick<ReceiptLogReport, "tornTails"> = {};
    expect(r.tornTails).toBeUndefined();
  });
});

describe("F6: a tail torn after the instance opened is reported, not dropped", () => {
  it("verifyAll reports it (ok false) without touching the file; the next append moves it aside", async () => {
    const log = new ReceiptLog(path, { repairTornTail: true });
    await log.record(approve(intent()));
    const second = intent();
    await log.record(approve(second));
    const text = await readFile(path, "utf8");
    await writeFile(path, text.slice(0, text.length - 30)); // the last receipt cut mid-line

    const before = await snapshot(path);
    const report = await log.verifyAll();
    expect(await snapshot(path)).toEqual(before);
    expect(report).toMatchObject({ total: 1, valid: 1, ok: false, chain: { intact: true, length: 1 } });
    expect(report.tornTails).toEqual([{ index: 1, intent_id: second.intent_id, offset: expect.any(Number), length: expect.any(Number), quarantined: false }]);

    // The same writer appends next: it sees the torn end first, moves it aside, and links onto line 1.
    await log.record(approve(intent()));
    const after = await new ReceiptLog(path, { repairTornTail: true }).verifyAll();
    expect(after.chain).toEqual({ intact: true, length: 2 });
    expect(after.tornTails?.map((t) => t.quarantined)).toEqual([true]);
  });
});
