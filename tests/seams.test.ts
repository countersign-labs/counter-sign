// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Where the durability work (DurableDecisions, FilePendingStore, the Intent
// sidecar) meets the chat adapters: a real adapter, a real webhook, a restart.

import { createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";
import { createIntent } from "../src/core/intent.js";
import { generateKeypair } from "../src/core/keys.js";
import type { Intent, IntentFields } from "../src/core/types.js";
import { SlackAdapter } from "../src/adapters/slack.js";
import { WhatsAppAdapter } from "../src/adapters/whatsapp.js";
import { ReceiptLog } from "../src/receipt-log.js";
import { DurableDecisions, FilePendingStore } from "../src/resumable.js";

const authority = generateKeypair();
const agent = { id: "agent:test", keypair: generateKeypair() };
const SLACK_SECRET = "slack-signing-secret";

function makeIntent(overrides: Partial<IntentFields> = {}): Intent {
  return createIntent(
    { action: "demo.op", summary: "Do the thing", risk_tier: "medium", approvers: ["slack:U42"], timeout: 300, default: "reject", ...overrides },
    agent,
  );
}

function interceptFetch(): string[] {
  const real = globalThis.fetch;
  const urls: string[] = [];
  vi.stubGlobal("fetch", async (input: any, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("127.0.0.1")) return real(input, init);
    urls.push(url);
    return new Response(JSON.stringify({ ok: true, ts: "1.1" }), { status: 200, headers: { "content-type": "application/json" } });
  });
  return urls;
}

function listen(handler: (req: any, res: any) => void): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}

async function pressSlack(base: string, intent: Intent, user: string) {
  const payload = JSON.stringify({
    type: "block_actions",
    user: { id: user },
    response_url: "https://hooks.slack.test/respond",
    actions: [{ action_id: "countersign_approve", value: `cs:${intent.intent_id}:approve` }],
  });
  const body = `payload=${encodeURIComponent(payload)}`;
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = `v0=${createHmac("sha256", SLACK_SECRET).update(`v0:${ts}:${body}`).digest("hex")}`;
  return fetch(base, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig },
    body,
  });
}

const slack = () => new SlackAdapter({ botToken: "xoxb-test", channelId: "C123", signingSecret: SLACK_SECRET, authorityKey: authority.secretKey });

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cs-seams-"));
});
afterEach(async () => {
  vi.unstubAllGlobals();
  await rm(dir, { recursive: true, force: true });
});

describe("DurableDecisions over a real chat adapter", () => {
  it("Slack: issued before a restart, approved after it, decided once and auditable from the sidecar", async () => {
    const urls = interceptFetch();
    const storePath = join(dir, "pending.jsonl");
    const logPath = join(dir, "receipts.jsonl");
    const intent = makeIntent();

    // Process 1: issue, then "crash" before anyone presses.
    const a1 = slack();
    const store1 = await FilePendingStore.open(storePath);
    const d1 = new DurableDecisions({ adapter: a1, store: store1, receiptLog: new ReceiptLog(logPath, { intents: true }), authorityKey: authority.secretKey });
    await d1.issue(intent);
    expect(urls.filter((u) => u.endsWith("chat.postMessage"))).toHaveLength(1);
    a1.close();
    await store1.close();

    // Process 2: a fresh adapter, store and log. restore() re-arms without posting again.
    const a2 = slack();
    const { server, base } = await listen(a2.interactivityHandler());
    const store2 = await FilePendingStore.open(storePath);
    const log2 = new ReceiptLog(logPath, { intents: true });
    try {
      const d2 = new DurableDecisions({ adapter: a2, store: store2, receiptLog: log2, authorityKey: authority.secretKey });
      const report = await d2.restore();
      expect(report.rearmed.map((r) => r.intent.intent_id)).toEqual([intent.intent_id]);
      expect(report.redelivered).toEqual([]);
      expect(urls.filter((u) => u.endsWith("chat.postMessage"))).toHaveLength(1);

      expect((await pressSlack(base, intent, "U42")).status).toBe(200);
      const resolution = await report.rearmed[0].resolution;
      expect(resolution.decision).toBe("approve");
      expect(resolution.countersignatures[0].actor).toBe("slack:U42");

      // Final and logged before it was handed back; the sidecar lets the audit stand alone.
      expect((await store2.get(intent.intent_id))?.status).toBe("final");
      expect((await readFile(logPath, "utf8")).trim().split("\n")).toHaveLength(1);
      const audit = await log2.verifyAll({ authorityKey: authority.publicKey, trustedAgentKeys: [agent.keypair.publicKey] });
      expect(audit.ok).toBe(true);
      expect(audit.total).toBe(1);

      // Asking again changes nothing.
      expect(await d2.decide(intent)).toEqual(resolution);
      expect((await readFile(logPath, "utf8")).trim().split("\n")).toHaveLength(1);
    } finally {
      server.close();
      a2.close();
      await store2.close();
    }
  });

  it("WhatsApp: a request the adapter refuses to deliver is abandoned, never re-armed, and has no receipt", async () => {
    const urls = interceptFetch();
    const savedTo = process.env.WHATSAPP_TO;
    delete process.env.WHATSAPP_TO; // approvers mode (opt-in since F3)
    onTestFinished(() => {
      if (savedTo !== undefined) process.env.WHATSAPP_TO = savedTo;
    });
    const wa = new WhatsAppAdapter({ recipientMode: "approvers", accessToken: "t", phoneNumberId: "555", verifyToken: "v", appSecret: "s", authorityKey: authority.secretKey });
    const storePath = join(dir, "pending.jsonl");
    const logPath = join(dir, "receipts.jsonl");
    const store = await FilePendingStore.open(storePath);
    try {
      const d = new DurableDecisions({ adapter: wa, store, receiptLog: new ReceiptLog(logPath), authorityKey: authority.secretKey });
      // A summary with a newline is refused before anything is sent (it would be rejected or reflowed).
      const intent = makeIntent({ approvers: ["whatsapp:6591234567"], summary: "line one\nline two" });
      await expect(d.issue(intent)).rejects.toThrow(/newline|tab|spaces/i);
      expect(urls).toHaveLength(0);
      expect((await store.get(intent.intent_id))?.status).toBe("abandoned");
      const report = await d.restore();
      expect(report.abandoned.map((i) => i.intent_id)).toEqual([intent.intent_id]);
      expect(report.rearmed).toEqual([]);
      expect(urls).toHaveLength(0);
      await expect(readFile(logPath, "utf8")).rejects.toThrow(/ENOENT/);
    } finally {
      wa.close();
      await store.close();
    }
  });
});
